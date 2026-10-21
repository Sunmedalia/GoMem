package kallsyms_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/kallsyms"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type resolverRow struct {
	coreRow
	Module, Subsystem string
}
type resolverCase struct {
	Width            int
	Layout, Scenario string
	Sequence         uint64
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Expected         []struct {
		Query             uint64
		Result, Primitive *resolverRow
		Error             *struct{ Class, Message string }
	}
}

func resolverCases(t testing.TB) []resolverCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/resolver-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []resolverCase
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 96 {
		t.Fatal("resolver oracle provenance/count")
	}
	return v.Cases
}
func resolverLimits() kallsyms.ResolverLimits {
	return kallsyms.ResolverLimits{Core: kallsyms.Limits{Symbols: 100, Bytes: 1 << 20, TokenBytes: 256, NameBytes: 512}, NodesPerSource: 64, ModuleSymbols: 100}
}
func resolverReader(t testing.TB, c resolverCase) (*object.Reader, buffer) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := make(buffer, 0x50000)
	for _, w := range c.Writes {
		var at int
		var text string
		if err = json.Unmarshal(w[0], &at); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(w[1], &text); err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], raw)
	}
	return &object.Reader{Layer: data, Symbols: table}, data
}
func resolverMask(width int) uint64 {
	if width == 4 {
		return 0xffffffff
	}
	return 0x0000ffffffffffff
}
func resolutionRow(r kallsyms.Resolution) *resolverRow {
	if r.Symbol == nil {
		return nil
	}
	return &resolverRow{coreRow: *bpfRow(*r.Symbol), Module: r.Module, Subsystem: r.Source}
}
func TestPinnedFullResolver(t *testing.T) {
	for _, c := range resolverCases(t) {
		t.Run(fmt.Sprintf("%d/%s/%d/%s", c.Width, c.Layout, c.Sequence, c.Scenario), func(t *testing.T) {
			r, data := resolverReader(t, c)
			trace := &bpfObserved{buffer: data}
			r.Layer = trace
			s, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(c.Width), resolverLimits())
			if err != nil {
				t.Fatal(err)
			}
			for _, read := range trace.reads {
				raw, cause := memory.Read(context.Background(), data, read.at, read.want)
				if (cause == nil) != (read.err == nil) || !bytes.Equal(raw, read.data) {
					t.Fatal("bootstrap reread", cause, read.err)
				}
			}
			for i, want := range c.Expected {
				trace.reads = nil
				got, err := s.Lookup(context.Background(), want.Query)
				for _, read := range trace.reads {
					raw, cause := memory.Read(context.Background(), data, read.at, read.want)
					if (cause == nil) != (read.err == nil) || !bytes.Equal(raw, read.data) {
						t.Fatal("resolver independent reread", cause, read.err)
					}
				}
				expected := want.Result
				if want.Error != nil {
					if want.Error.Class == "AttributeError" && strings.Contains(want.Error.Message, "get_addr_region") && want.Primitive != nil {
						expected = want.Primitive
					} else {
						if err == nil || got.Symbol != nil {
							t.Fatal(i, want.Query, want.Error, got, err)
						}
						continue
					}
				} else if want.Primitive != nil {
					t.Fatal("unexpected primitive without baseline failure")
				}
				if err != nil {
					t.Fatal(i, want.Query, err)
				}
				if !reflect.DeepEqual(resolutionRow(got), expected) {
					t.Fatalf("query %d %#x: got %+v expected %+v", i, want.Query, resolutionRow(got), expected)
				}
				if got.Address != want.Query&resolverMask(c.Width) {
					t.Fatal("normalized query", got)
				}
				sources := []string{"core", "module", "bpf", "ftrace"}
				for j, name := range got.Attempted {
					if name != sources[j] {
						t.Fatal("source order", got.Attempted)
					}
				}
				if got.Symbol != nil && got.Attempted[len(got.Attempted)-1] != got.Source {
					t.Fatal("lookup continued after match", got)
				}
			}
			stats := s.Stats()
			if stats.Queries != uint64(len(c.Expected)) || stats.Resolved+stats.NoMatch+stats.Failed != stats.Queries || stats.CachedModules > 64 || stats.CachedModuleSymbols > 100 {
				t.Fatal(stats)
			}
		})
	}
}
func resolverNormal(t testing.TB, scenario string) resolverCase {
	for _, c := range resolverCases(t) {
		if c.Width == 8 && c.Layout == "modern" && c.Sequence == 0 && c.Scenario == scenario {
			return c
		}
	}
	t.Fatal("missing resolver fixture")
	return resolverCase{}
}

type resolverFaultLayer struct {
	buffer
	calls, fail, cancelAt int
	cancel                context.CancelFunc
	reads                 []bpfRead
}

func (l *resolverFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.calls++
	if l.calls == l.fail {
		return 0, memory.ErrUnmapped
	}
	n, err := l.buffer.ReadAt(ctx, p, at)
	l.reads = append(l.reads, bpfRead{at, append([]byte(nil), p[:n]...), len(p), err})
	if l.calls == l.cancelAt {
		l.cancel()
	}
	return n, err
}
func TestFullResolverEveryAcquisitionBoundary(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, key := range []uint64{0x8400, 0x8500, 0x8800, 0x8600, 0x9000} {
			c := resolverNormal(t, "module-first")
			if key == 0x8800 || key == 0x8600 || key == 0x9000 {
				c = resolverNormal(t, "no-bpf-root")
				if key == 0x8800 {
					c = resolverNormal(t, "bpf-first")
				}
			}
			r, data := resolverReader(t, c)
			probe := &resolverFaultLayer{buffer: data}
			r.Layer = probe
			s, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(8), resolverLimits())
			if err != nil {
				t.Fatal(err)
			}
			if warm {
				if _, err := s.Lookup(context.Background(), key); err != nil {
					t.Fatal(err)
				}
			}
			probe.calls = 0
			expected, err := s.Lookup(context.Background(), key)
			if err != nil {
				t.Fatal(err)
			}
			count := probe.calls
			for boundary := 1; boundary <= count; boundary++ {
				for _, cancelInside := range []bool{false, true} {
					layer := &resolverFaultLayer{buffer: data}
					r.Layer = layer
					s, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(8), resolverLimits())
					if err != nil {
						t.Fatal(err)
					}
					if warm {
						if _, err := s.Lookup(context.Background(), key); err != nil {
							t.Fatal(err)
						}
					}
					layer.calls = 0
					ctx, cancel := context.WithCancel(context.Background())
					layer.cancel = cancel
					if cancelInside {
						layer.cancelAt = boundary
					} else {
						layer.fail = boundary
					}
					got, err := s.Lookup(ctx, key)
					cancel()
					if err == nil || got.Symbol != nil {
						t.Fatal(key, boundary, cancelInside, got, err)
					}
					if cancelInside && !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
					layer.fail = 0
					layer.cancelAt = 0
					got, err = s.Lookup(context.Background(), key)
					if err != nil || !reflect.DeepEqual(resolutionRow(got), resolutionRow(expected)) {
						t.Fatal("retry", key, boundary, got, expected, err)
					}
				}
			}
		}
	}
}

func TestFullResolverModuleSnapshotReuse(t *testing.T) {
	r, data := resolverReader(t, resolverNormal(t, "module-first"))
	trace := &resolverFaultLayer{buffer: data}
	r.Layer = trace
	s, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(8), resolverLimits())
	if err != nil {
		t.Fatal(err)
	}
	cold, err := s.Lookup(context.Background(), 0x8500)
	if err != nil || cold.ModuleSearch == nil || cold.ModuleSearch.SymbolsRead != 3 {
		t.Fatal(cold, err)
	}
	trace.reads = nil
	warm, err := s.Lookup(context.Background(), 0x8501)
	if err != nil || warm.Symbol == nil || warm.ModuleSearch == nil || !warm.ModuleSearch.ListReused || warm.ModuleSearch.SymbolsRead != 0 || warm.ModuleSearch.TablesReused != 1 {
		t.Fatal(warm, err)
	}
	for _, read := range trace.reads {
		if read.at >= 0x18400 && read.at < 0x18448 || read.at == 0x17c00 || read.at == 0x18000 {
			t.Fatal("index reacquired", read)
		}
	}
	// Returned range snapshots cannot mutate the retained index.
	warm.ModuleSearch.Ranges[0].Start = ^uint64(0)
	again, err := s.Lookup(context.Background(), 0x8500)
	if err != nil || again.Symbol == nil || again.ModuleSearch.Ranges[0].Start != 0x8500 {
		t.Fatal(again, err)
	}
	if s.Stats().CachedModules != 1 || s.Stats().CachedModuleSymbols != 3 {
		t.Fatal(s.Stats())
	}
}

func TestFullResolverBootstrapFailures(t *testing.T) {
	r, data := resolverReader(t, resolverNormal(t, "normal"))
	probe := &resolverFaultLayer{buffer: data}
	r.Layer = probe
	if _, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(8), resolverLimits()); err != nil {
		t.Fatal(err)
	}
	for boundary := 1; boundary <= probe.calls; boundary++ {
		for _, cancelInside := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			layer := &resolverFaultLayer{buffer: data, cancel: cancel}
			r.Layer = layer
			if cancelInside {
				layer.cancelAt = boundary
			} else {
				layer.fail = boundary
			}
			got, err := kallsyms.OpenResolver(ctx, r, 0, resolverMask(8), resolverLimits())
			cancel()
			if err == nil || got != nil {
				t.Fatal(boundary, cancelInside, got, err)
			}
			if cancelInside && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			layer.fail = 0
			layer.cancelAt = 0
			if _, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(8), resolverLimits()); err != nil {
				t.Fatal("bootstrap retry", err)
			}
		}
	}
}

func TestFullResolverIntelPaging(t *testing.T) {
	for _, c := range resolverCases(t) {
		modes := []string{"x64"}
		if c.Width == 4 {
			modes = []string{"x86", "pae"}
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("%s/%s/%s/%d", mode, c.Layout, c.Scenario, c.Sequence), func(t *testing.T) {
				flat, data := resolverReader(t, c)
				physical := make(buffer, 0x75000)
				copy(physical, data)
				put := func(at, value uint64) { binary.LittleEndian.PutUint64(physical[at:], value) }
				switch mode {
				case "x64":
					put(0x70000, 0x71003)
					put(0x71000, 0x72003)
					put(0x72000, 0x73003)
				case "pae":
					put(0x70000, 0x72003)
					put(0x72000, 0x73003)
				case "x86":
					binary.LittleEndian.PutUint32(physical[0x70000:], 0x73003)
				}
				for i := uint64(0); i < uint64(len(data)/4096); i++ {
					if mode == "x86" {
						binary.LittleEndian.PutUint32(physical[0x73000+i*4:], uint32(i*4096|3))
					} else {
						put(0x73000+i*8, i*4096|3)
					}
				}
				translator, err := memory.NewIntelForOS(physical, 0x70000, mode, "linux", 8)
				if err != nil {
					t.Fatal(err)
				}
				trace := &bpfPagingReads{MemoryLayer: &memory.Virtual{Physical: physical, Translator: translator, ID: mode}, original: data, t: t}
				paged := &object.Reader{Layer: trace, Symbols: flat.Symbols}
				flatResolver, err := kallsyms.OpenResolver(context.Background(), flat, 0, resolverMask(c.Width), resolverLimits())
				if err != nil {
					t.Fatal(err)
				}
				pagedResolver, err := kallsyms.OpenResolver(context.Background(), paged, 0, resolverMask(c.Width), resolverLimits())
				if err != nil {
					t.Fatal(err)
				}
				for i, query := range c.Expected {
					expected, wantErr := flatResolver.Lookup(context.Background(), query.Query)
					got, err := pagedResolver.Lookup(context.Background(), query.Query)
					if !reflect.DeepEqual(got, expected) || (err == nil) != (wantErr == nil) {
						t.Fatal(i, got, expected, err, wantErr)
					}
				}
				if trace.reads == 0 {
					t.Fatal("paging not exercised")
				}
			})
		}
	}
}

func TestFullResolverModuleTreeReuse(t *testing.T) {
	r, data, cfg := moduleReader(t, moduleNormal(t, true))
	table := r.Symbols.(*symbols.ISF)
	symbol := table.Symbols["_etext"]
	symbol.Address = 0x8480
	table.Symbols["_etext"] = symbol
	trace := &resolverFaultLayer{buffer: data}
	r.Layer = trace
	s, err := kallsyms.OpenResolver(context.Background(), r, 0, cfg.AddressMask, resolverLimits())
	if err != nil {
		t.Fatal(err)
	}
	cold, err := s.Lookup(context.Background(), 0x8500)
	if err != nil || cold.Source != "module" || cold.Module != "tree_copy_0" {
		t.Fatal(cold, err)
	}
	trace.reads = nil
	warm, err := s.Lookup(context.Background(), 0x8501)
	if err != nil || warm.ModuleSearch == nil || warm.ModuleSearch.TablesReused != 1 || warm.ModuleSearch.SymbolsRead != 0 || warm.ModuleSearch.ListReused {
		t.Fatal(warm, err)
	}
	for _, read := range trace.reads {
		if read.at >= 0x18400 && read.at < 0x18448 {
			t.Fatal("tree ELF table reacquired", read)
		}
	}
}
func TestFullResolverInvalidSetup(t *testing.T) {
	var zero kallsyms.Resolver
	if zero.Stats() != (kallsyms.ResolverStats{}) {
		t.Fatal(zero.Stats())
	}
	if _, err := zero.Lookup(context.Background(), 0); err == nil {
		t.Fatal("zero resolver accepted")
	}
	if _, err := kallsyms.OpenResolver(context.Background(), nil, 0, resolverMask(8), resolverLimits()); err == nil {
		t.Fatal("nil reader accepted")
	}
	r, _ := resolverReader(t, resolverNormal(t, "normal"))
	bad := resolverLimits()
	bad.NodesPerSource = 0
	if _, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(8), bad); err == nil {
		t.Fatal("zero bound accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := kallsyms.OpenResolver(ctx, r, 0, resolverMask(8), resolverLimits()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(got, err)
	}
}
func FuzzFullResolver(f *testing.F) {
	c := resolverNormal(f, "module-first")
	f.Add(uint64(0x8500), uint8(0), []byte{0})
	f.Add(uint64(0x8800), uint8(4), []byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, key uint64, region uint8, payload []byte) {
		if len(payload) > 512 {
			t.Skip()
		}
		r, data := resolverReader(t, c)
		at := []int{0x16000, 0x16100, 0x17000, 0x18200, 0x1020, 0x19d00, 0x19f00}[int(region)%7]
		copy(data[at:], payload)
		limits := resolverLimits()
		limits.Core.Symbols = 16
		limits.NodesPerSource = 8
		limits.ModuleSymbols = 16
		s, err := kallsyms.OpenResolver(context.Background(), r, 0, resolverMask(8), limits)
		if err != nil {
			if s != nil {
				t.Fatal("failed bootstrap returned resolver")
			}
			return
		}
		first, err := s.Lookup(context.Background(), key)
		if err != nil && first.Symbol != nil {
			t.Fatal("failed symbol")
		}
		next, againErr := s.Lookup(context.Background(), key)
		if againErr != nil && next.Symbol != nil {
			t.Fatal("failed repeated symbol")
		}
		if err == nil && (againErr != nil || !reflect.DeepEqual(resolutionRow(first), resolutionRow(next))) {
			t.Fatal("unstable immutable resolution", first, next, err, againErr)
		}
		stats := s.Stats()
		if stats.CachedModules > 8 || stats.CachedModuleSymbols > 16 {
			t.Fatal("unbounded snapshot cache", stats)
		}
	})
}

func TestFullResolverRetainedIndexBounds(t *testing.T) {
	for _, maxSymbols := range []int{3, 6} {
		r, _, cfg := moduleReader(t, moduleNormal(t, true))
		table := r.Symbols.(*symbols.ISF)
		v := table.Symbols["_etext"]
		v.Address = 0x8480
		table.Symbols["_etext"] = v
		limits := resolverLimits()
		limits.ModuleSymbols = maxSymbols
		s, err := kallsyms.OpenResolver(context.Background(), r, 0, cfg.AddressMask, limits)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.Lookup(context.Background(), 0x8500); err != nil || got.Source != "module" {
			t.Fatal(got, err)
		}
		got, err := s.Lookup(context.Background(), 0x8fff)
		if maxSymbols == 3 {
			if err == nil || got.Symbol != nil || s.Stats().CachedModuleSymbols != 3 {
				t.Fatal("retained symbol bound", got, err, s.Stats())
			}
		} else {
			if err != nil || got.Symbol != nil || s.Stats().CachedModuleSymbols != 6 {
				t.Fatal(got, err, s.Stats())
			}
		}
		if got, err := s.Lookup(context.Background(), 0x8501); err != nil || got.Source != "module" {
			t.Fatal("verified index poisoned", got, err)
		}
	}
	r, data, cfg := moduleReader(t, moduleNormal(t, true))
	table := r.Symbols.(*symbols.ISF)
	// Isolate retained module capacity from unrelated optional ftrace walks.
	delete(table.Types, "ftrace_mod_map")
	delete(table.Types, "ftrace_ops")
	for name, at := range map[string]uint64{"_stext": 0x8000, "_etext": 0x8100} {
		v := table.Symbols[name]
		v.Address = at
		table.Symbols[name] = v
	}
	copy(data[0x1e000:0x1e0a0], data[0x1c000:0x1c0a0])
	binary.LittleEndian.PutUint64(data[0x21f0:], 0x1d000)
	binary.LittleEndian.PutUint64(data[0x23f0:], 0x1e000)
	limits := resolverLimits()
	limits.NodesPerSource = 2
	s, err := kallsyms.OpenResolver(context.Background(), r, 0, cfg.AddressMask, limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []uint64{0x8500, 0x8400} {
		if _, err := s.Lookup(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Lookup(context.Background(), 0x8580)
	if err == nil || got.Symbol != nil || !strings.Contains(err.Error(), "module cache object bound") || s.Stats().CachedModules != 2 {
		t.Fatal(got, err, s.Stats())
	}
}
