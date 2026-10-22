package pesymbols

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type layer struct {
	base  uint64
	data  []byte
	calls int
}

func (l *layer) Name() string { return "module" }
func (l *layer) Ranges() []memory.Range {
	return []memory.Range{{Start: l.base, Length: uint64(len(l.data))}}
}
func (l *layer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	l.calls++
	if at < l.base || at-l.base >= uint64(len(l.data)) {
		return 0, io.EOF
	}
	n := copy(p, l.data[at-l.base:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func fixture(t testing.TB) (Module, *layer) {
	t.Helper()
	raw, err := os.ReadFile("../pe/testdata/exports-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Base uint64
			Data []byte
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	l := &layer{base: f.Cases[0].Base, data: f.Cases[0].Data}
	return Module{l, l.base, uint64(len(l.data)), nil}, l
}
func pdb(t testing.TB, values map[string]uint64) PDB {
	t.Helper()
	s := map[string]any{}
	for name, at := range values {
		s[name] = map[string]any{"address": at}
	}
	raw, _ := json.Marshal(map[string]any{"metadata": map[string]any{"format": "6.2.0", "windows": map[string]any{"pdb": map[string]any{"database": "fixture.pdb", "GUID": strings.Repeat("12", 16), "age": 1}}}, "base_types": map[string]any{"pointer": map[string]any{"kind": "int", "size": 4, "endian": "little", "signed": false}}, "user_types": map[string]any{}, "enums": map[string]any{}, "symbols": s})
	dir := t.TempDir()
	path := filepath.Join(dir, "pdb.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	table, err := symbols.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := table.PDBIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return PDB{Table: table, Identity: id, SourceSHA256: strings.Repeat("ab", 32)}
}
func options() Options { return Options{Limits: pe.DefaultExportLimits(), MaxSymbols: 1000000} }
func TestPDBFirstAcrossAllInstancesAndExactFallback(t *testing.T) {
	m, l := fixture(t)
	other := *l
	other.calls = 0
	first := pdb(t, map[string]uint64{"Zulu": 0x1200, "AlphaPDB": 0x1200, "Private": 0x1300})
	second := pdb(t, map[string]uint64{"Alpha": 0x1600})
	loads := 0
	opts := options()
	opts.PDB = func(ctx context.Context, module Module) (PDB, error) {
		loads++
		if module.Layer.Name() == "second" {
			return second, nil
		}
		return first, nil
	}
	otherModule := Module{namedLayer{&other, "second"}, m.Base, m.Size, nil}
	r, err := New([]Module{m, otherModule}, opts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Resolve(context.Background(), Request{Names: []string{"Alpha", "Forward", "absent", "Alpha"}})
	if err != nil || len(result.Found) != 3 || len(result.Missing.Names) != 1 || result.Missing.Names[0] != "absent" {
		t.Fatal(result, err)
	}
	want := []Match{{"Alpha", m.Base + 0x1600, 1, "pdb", second.Table.Digest(), second.SourceSHA256}, {"Alpha", m.Base + 0x1600, 1, "pdb", second.Table.Digest(), second.SourceSHA256}, {"Forward", m.Base + 0x1700, 0, "exports", "", ""}}
	if !reflect.DeepEqual(result.Found, want) {
		t.Fatal(result.Found, want)
	}
	calls := l.calls + other.calls
	repeat, err := r.Resolve(context.Background(), Request{Addresses: []uint64{m.Base + 0x1200, m.Base + 0x1201, m.Base + 0x1700}})
	if err != nil || loads != 2 || l.calls+other.calls != calls || len(repeat.Found) != 2 || repeat.Found[0].Name != "AlphaPDB" || repeat.Found[1].Name != "Forward" || len(repeat.Missing.Addresses) != 1 {
		t.Fatal(repeat, err, loads)
	}
}

type namedLayer struct {
	memory.MemoryLayer
	name string
}

func (l namedLayer) Name() string { return l.name }

func TestPinnedGroupStopAndDuplicateRequests(t *testing.T) {
	m, _ := fixture(t)
	opts := options()
	p := pdb(t, map[string]uint64{"Private": 0x1300})
	opts.PDB = func(context.Context, Module) (PDB, error) { return p, nil }
	r, _ := New([]Module{m}, opts)
	result, err := r.Resolve(context.Background(), Request{Names: []string{"Private", "Private"}, Addresses: []uint64{m.Base + 0x1200}})
	if err != nil || !result.StoppedOnGroup || len(result.Found) != 2 || len(result.Missing.Addresses) != 1 || len(result.Attempts) != 1 {
		t.Fatal(result, err)
	}
}
func TestUnavailableAndFailedAcquisitionsAreDistinct(t *testing.T) {
	for _, unavailable := range []bool{true, false} {
		m, l := fixture(t)
		opts := options()
		failure := errors.New("PDB input failure")
		if unavailable {
			failure = ErrUnavailable
		}
		opts.PDB = func(ctx context.Context, m Module) (PDB, error) {
			_, _ = memory.Read(ctx, m.Layer, m.Base, 1)
			return PDB{}, failure
		}
		reads := 0
		opts.Observe = func(r Read) error {
			reads++
			if r.Module != 0 || r.Requested != len(r.Raw) || r.Err != nil {
				t.Fatal(r)
			}
			return nil
		}
		r, _ := New([]Module{m}, opts)
		result, err := r.Resolve(context.Background(), Request{Names: []string{"Alpha"}})
		if unavailable != (err == nil) || len(result.Found) != 1 || result.Found[0].Method != "exports" || result.Attempts[0].Unavailable != unavailable || reads != l.calls {
			t.Fatal(result, err, reads, l.calls)
		}
		calls := l.calls
		again, err := r.Resolve(context.Background(), Request{Names: []string{"Alpha"}})
		if unavailable != (err == nil) || l.calls != calls || len(again.Found) != 1 {
			t.Fatal(again, err)
		}
	}
}
func TestCancellationAndOutputFailureStopAcquisition(t *testing.T) {
	m, _ := fixture(t)
	total := 0
	opts := options()
	opts.Observe = func(Read) error { total++; return nil }
	clean, _ := New([]Module{m}, opts)
	if _, err := clean.Resolve(context.Background(), Request{Names: []string{"Alpha"}}); err != nil {
		t.Fatal(err)
	}
	for boundary := 1; boundary <= total; boundary++ {
		for _, cancelled := range []bool{false, true} {
			m, l := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			calls := 0
			stop := errors.New("observer stop")
			opts.Observe = func(Read) error {
				calls++
				if calls == boundary {
					if cancelled {
						cancel()
					} else {
						return stop
					}
				}
				return nil
			}
			r, _ := New([]Module{m}, opts)
			_, err := r.Resolve(ctx, Request{Names: []string{"Alpha"}})
			cancel()
			expected := stop
			if cancelled {
				expected = context.Canceled
			}
			if !errors.Is(err, expected) || calls != boundary || l.calls != boundary {
				t.Fatal(boundary, err, calls, l.calls)
			}
		}
	}
}
func TestSymbolAndAcquisitionBudgetsAndIdentity(t *testing.T) {
	m, _ := fixture(t)
	for _, mode := range []string{"symbols", "bytes", "identity", "nil-table", "overflow", "extent"} {
		opts := options()
		p := pdb(t, map[string]uint64{"Private": 0x1300, "Other": 0x1400})
		switch mode {
		case "symbols":
			opts.MaxSymbols = 1
		case "bytes":
			opts.Limits.MaxBytes = 64
		case "identity":
			p.Identity.Age++
		case "nil-table":
			p.Table = nil
		case "overflow":
			p = pdb(t, map[string]uint64{"Bad": ^uint64(0)})
		case "extent":
			m.Size = 0x2000
		}
		opts.PDB = func(context.Context, Module) (PDB, error) { return p, nil }
		r, err := New([]Module{m}, opts)
		if err != nil {
			t.Fatal(err)
		}
		result, err := r.Resolve(context.Background(), Request{Names: []string{"absent"}})
		if err == nil {
			t.Fatal(mode, result)
		}
		if r.acquired > opts.Limits.MaxBytes || r.indexed > opts.MaxSymbols {
			t.Fatal("budget exceeded")
		}
	}
}
func TestInvalidResolverInputs(t *testing.T) {
	m, _ := fixture(t)
	opts := options()
	for _, modules := range [][]Module{{{nil, 0, 1, nil}}, {{m.Layer, 0, 0, nil}}, {{m.Layer, ^uint64(0), 2, nil}}, make([]Module, 10001)} {
		if _, err := New(modules, opts); err == nil {
			t.Fatal("invalid module accepted")
		}
	}
	for _, bad := range []Options{{}, {Limits: pe.DefaultExportLimits(), MaxSymbols: 10000001}} {
		if _, err := New(nil, bad); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	r, _ := New([]Module{m}, opts)
	for _, req := range []Request{{}, {Names: []string{""}}, {Names: []string{strings.Repeat("a", 65537)}}} {
		if _, err := r.Resolve(context.Background(), req); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestUnmodifiedPinnedModuleResolution(t *testing.T) {
	raw, err := os.ReadFile("testdata/resolver-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Base   uint64
		Images [][]byte
		Tables []json.RawMessage
		Cases  []struct {
			Order    []int
			Request  Request
			Expected [][2]json.RawMessage
			Missing  Request
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 18 {
		t.Fatal("oracle drift")
	}
	tables := make([]PDB, len(f.Tables))
	for i, raw := range f.Tables {
		path := filepath.Join(t.TempDir(), "pdb.json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		table, err := symbols.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		id, err := table.PDBIdentity()
		if err != nil {
			t.Fatal(err)
		}
		tables[i] = PDB{Table: table, Identity: id}
	}
	for number, c := range f.Cases {
		t.Run(string(rune('A'+number)), func(t *testing.T) {
			var modules []Module
			for _, i := range c.Order {
				l := &layer{base: f.Base, data: f.Images[i]}
				modules = append(modules, Module{namedLayer{l, string(rune('0' + i))}, f.Base, uint64(len(l.data)), nil})
			}
			opts := options()
			opts.PDB = func(ctx context.Context, m Module) (PDB, error) {
				marker, err := memory.Read(ctx, m.Layer, m.Base+0x1900, 36)
				if err != nil {
					return PDB{}, err
				}
				if string(marker[:4]) != "RSDS" {
					return PDB{}, errors.New("wrong PDB marker")
				}
				return tables[int(m.Layer.Name()[0]-'0')], nil
			}
			captures := 0
			opts.Observe = func(r Read) error {
				captures++
				i := c.Order[r.Module]
				at := r.Address - f.Base
				if r.Err != nil || !reflect.DeepEqual(r.Raw, f.Images[i][at:at+uint64(len(r.Raw))]) {
					t.Fatal(r)
				}
				return nil
			}
			resolver, err := New(modules, opts)
			if err != nil {
				t.Fatal(err)
			}
			result, err := resolver.Resolve(context.Background(), c.Request)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Found) != len(c.Expected) || !slices.Equal(result.Missing.Names, c.Missing.Names) || !slices.Equal(result.Missing.Addresses, c.Missing.Addresses) {
				t.Fatal(result, c)
			}
			for i, expected := range c.Expected {
				var name string
				var address uint64
				if err = json.Unmarshal(expected[0], &name); err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(expected[1], &address); err != nil {
					t.Fatal(err)
				}
				if result.Found[i].Name != name || result.Found[i].Address != address {
					t.Fatal(i, result.Found[i], name, address)
				}
			}
			if captures == 0 {
				t.Fatal("no acquisitions")
			}
		})
	}
}

func FuzzModuleSymbolRequests(f *testing.F) {
	f.Add([]byte("Alpha"), uint64(0x401200), true)
	f.Add([]byte("absent"), uint64(0), false)
	m, _ := fixture(f)
	f.Fuzz(func(t *testing.T, name []byte, address uint64, mixed bool) {
		if len(name) == 0 || len(name) > 256 {
			return
		}
		opts := options()
		opts.Limits.MaxBytes = 65536
		opts.MaxSymbols = 32
		r, err := New([]Module{m}, opts)
		if err != nil {
			t.Fatal(err)
		}
		request := Request{Names: []string{string(name)}}
		if mixed {
			request.Addresses = []uint64{address, address}
		}
		result, _ := r.Resolve(context.Background(), request)
		if len(result.Found) > 3 || len(result.Attempts) > 2 || r.acquired > 65536 || r.indexed > 32 {
			t.Fatal("unbounded resolution")
		}
		for _, match := range result.Found {
			if match.Module != 0 || match.Method != "exports" {
				t.Fatal(match)
			}
		}
	})
}

func TestProviderCannotReadAfterObserverFailure(t *testing.T) {
	m, l := fixture(t)
	sentinel := errors.New("evidence output failed")
	opts := options()
	opts.Observe = func(Read) error { return sentinel }
	opts.PDB = func(ctx context.Context, module Module) (PDB, error) {
		for i := 0; i < 3; i++ {
			_, err := memory.Read(ctx, module.Layer, module.Base, 2)
			if !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
		}
		return PDB{}, sentinel
	}
	resolver, err := New([]Module{m}, opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background(), Request{Names: []string{"absent"}})
	if !errors.Is(err, sentinel) || l.calls != 1 {
		t.Fatal(err, l.calls)
	}
}

func TestCumulativeAcquisitionLimits(t *testing.T) {
	for _, kind := range []string{"bytes", "symbols"} {
		t.Run(kind, func(t *testing.T) {
			m, l := fixture(t)
			opts := options()
			table := pdb(t, map[string]uint64{"private": 0x1200})
			opts.MaxSymbols = 1
			opts.Limits.MaxBytes = 4
			opts.PDB = func(ctx context.Context, module Module) (PDB, error) {
				if kind == "bytes" {
					_, err := memory.Read(ctx, module.Layer, module.Base, 4)
					if err != nil {
						return PDB{}, err
					}
					return PDB{}, ErrUnavailable
				}
				return table, nil
			}
			resolver, err := New([]Module{m, m}, opts)
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.Resolve(context.Background(), Request{Names: []string{"absent"}})
			if err == nil || resolver.acquired > 4 || resolver.indexed > 1 {
				t.Fatal(err, resolver)
			}
			if kind == "bytes" && l.calls != 1 {
				t.Fatal("read past shared byte budget", l.calls)
			}
		})
	}
}

func TestExportReadsStayInsideCollectedModule(t *testing.T) {
	m, l := fixture(t)
	m.Size = 1
	resolver, err := New([]Module{m}, options())
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background(), Request{Names: []string{"Alpha"}})
	if err == nil || l.calls != 0 {
		t.Fatal(err, l.calls)
	}
}

func TestPDBNameCandidatesAreValidatedAndOwned(t *testing.T) {
	m, _ := fixture(t)
	opts := options()
	p := pdb(t, map[string]uint64{"private": 0x1300})
	opts.PDB = func(context.Context, Module) (PDB, error) { return p, nil }
	for _, names := range [][]string{{""}, {"a/b.pdb"}, make([]string, 17)} {
		m.PDBNames = names
		if _, err := New([]Module{m}, opts); err == nil {
			t.Fatal(names)
		}
	}
	m.PDBNames = []string{"unrelated.pdb"}
	r, err := New([]Module{m}, opts)
	if err != nil {
		t.Fatal(err)
	}
	m.PDBNames[0] = "fixture.pdb"
	result, err := r.Resolve(context.Background(), Request{Names: []string{"private"}})
	if err != nil || len(result.Found) != 0 || !result.Attempts[0].Unavailable {
		t.Fatal(result, err)
	}
}
