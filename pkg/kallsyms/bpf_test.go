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

type bpfCase struct {
	Width            int
	Nested           bool
	Sequence         uint64
	Layout, Scenario string
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Expected         []struct {
		Query     uint64
		Result    *coreRow
		Error     *struct{ Class, Message string }
		Primitive *struct {
			Object, Aux, RegionStart, RegionEnd uint64
			Name                                *string
		}
	}
}

func bpfCases(t testing.TB) []bpfCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/bpf-lookup-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []bpfCase
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 480 {
		t.Fatal("BPF oracle provenance/count")
	}
	return v.Cases
}
func bpfReader(t testing.TB, c bpfCase) (*object.Reader, buffer, kallsyms.BPFConfig) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := make(buffer, 0x50000)
	for _, w := range c.Writes {
		var at int
		var text string
		if err := json.Unmarshal(w[0], &at); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(w[1], &text); err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], raw)
	}
	layout := "legacy"
	if c.Layout == "modern" {
		layout = "modern"
	}
	mask := uint64(0xffffffff)
	if c.Width == 8 {
		mask = 0x0000ffffffffffff
	}
	cfg := kallsyms.BPFConfig{Root: 0x1000, AddressMask: mask, MaxNodes: 64, Layout: layout}
	if c.Scenario == "missing-root" {
		cfg.Root = 0
	}
	return &object.Reader{Layer: data, Symbols: table}, data, cfg
}

type bpfRead struct {
	at   uint64
	data []byte
	want int
	err  error
}
type bpfObserved struct {
	buffer
	reads  []bpfRead
	failAt *uint64
	after  func()
}

func (l *bpfObserved) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if l.failAt != nil && at == *l.failAt {
		return 0, memory.ErrUnmapped
	}
	n, err := l.buffer.ReadAt(ctx, p, at)
	l.reads = append(l.reads, bpfRead{at, append([]byte(nil), p[:n]...), len(p), err})
	if l.after != nil {
		l.after()
	}
	return n, err
}
func bpfRow(s kallsyms.Symbol) *coreRow {
	r := &coreRow{Name: s.Name, Type: s.Type, Address: s.Address, Exported: s.Exported}
	if s.SizeAvailable {
		size := s.Size
		r.Size = &size
	}
	return r
}
func TestPinnedBPFLookup(t *testing.T) {
	for _, c := range bpfCases(t) {
		t.Run(fmt.Sprintf("%d/%t/%d/%s/%s", c.Width, c.Nested, c.Sequence, c.Layout, c.Scenario), func(t *testing.T) {
			r, data, cfg := bpfReader(t, c)
			trace := &bpfObserved{buffer: data}
			r.Layer = trace
			for i, want := range c.Expected {
				trace.reads = nil
				got, err := kallsyms.LookupBPF(context.Background(), r, cfg, want.Query)
				for _, read := range trace.reads {
					raw, err := memory.Read(context.Background(), data, read.at, read.want)
					if err != nil || !bytes.Equal(raw, read.data) {
						t.Fatal("independent BPF acquisition reread", err)
					}
				}
				if want.Error != nil {
					if c.Layout == "modern" {
						if err == nil || got != nil {
							t.Fatalf("query %d: baseline %s; native %+v %v", i, want.Error.Class, got, err)
						}
						continue
					}
					if want.Error.Class != "AttributeError" || !strings.Contains(want.Error.Message, "get_addr_region") || want.Primitive == nil {
						t.Fatal("unclassified baseline failure", want.Error)
					}
				} else if want.Primitive != nil {
					t.Fatal("legacy baseline error disappeared")
				}
				if err != nil {
					t.Fatal(i, err)
				}
				expected := want.Result
				nameAvailable := true
				if p := want.Primitive; p != nil {
					name := ""
					nameAvailable = p.Name != nil
					if nameAvailable {
						name = *p.Name
					}
					exported := false
					expected = &coreRow{Name: name, Type: "t", Address: p.RegionStart & cfg.AddressMask, Exported: &exported}
					if p.RegionEnd > p.RegionStart {
						size := p.RegionEnd - p.RegionStart
						expected.Size = &size
					}
					if got == nil || got.ProgramDetails == nil || got.ProgramDetails.Object != p.Object || got.ProgramDetails.Aux != p.Aux || got.Program != p.Object || got.Aux != p.Aux || got.RegionStart != p.RegionStart || got.RegionEnd != p.RegionEnd {
						t.Fatal(i, got, p)
					}
				}
				var actual *coreRow
				if got != nil {
					actual = bpfRow(got.Symbol)
					if got.NameAvailable != nameAvailable || got.Search.Sequence != c.Sequence || got.Search.Index != c.Sequence&1 {
						t.Fatal(i, got)
					}
				}
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("query %d %#x: got %+v want %+v", i, want.Query, actual, expected)
				}

			}
		})
	}
}
func bpfFaultCase(t testing.TB, layout string) bpfCase {
	t.Helper()
	for _, c := range bpfCases(t) {
		if c.Width == 8 && c.Nested && c.Sequence == 0 && c.Layout == layout && c.Scenario == "normal" {
			return c
		}
	}
	t.Fatal("BPF fixture missing")
	return bpfCase{}
}
func TestBPFLookupFailures(t *testing.T) {
	c := bpfFaultCase(t, "modern")
	for _, fault := range []string{"cycle", "bound", "node-hole", "name-hole", "member-layout", "underflow", "cancel-read", "cancel-before", "zero-mask", "layout", "bound-zero", "bound-large"} {
		t.Run(fault, func(t *testing.T) {
			r, data, cfg := bpfReader(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key := uint64(0x8800)
			switch fault {
			case "cycle":
				binary.LittleEndian.PutUint64(data[0x2018:], 0x2010)
				key = 0xffff
			case "bound":
				cfg.MaxNodes = 1
				key = 0x8700
			case "node-hole":
				r.Layer = data[:0x2010+23]
			case "name-hole":
				at := uint64(0x1fe0)
				r.Layer = &bpfObserved{buffer: data, failAt: &at}
			case "member-layout":
				table := r.Symbols.(*symbols.ISF)
				v := table.Types["bpf_ksym"]
				f := v.Fields["tnode"]
				f.Type.Kind = "pointer"
				v.Fields["tnode"] = f
				table.Types["bpf_ksym"] = v
			case "underflow":
				binary.LittleEndian.PutUint64(data[0x1020:], 0x20)
			case "cancel-read":
				r.Layer = &bpfObserved{buffer: data, after: cancel}
			case "cancel-before":
				cancel()
			case "zero-mask":
				cfg.AddressMask = 0
			case "layout":
				cfg.Layout = "unknown"
			case "bound-zero":
				cfg.MaxNodes = 0
			case "bound-large":
				cfg.MaxNodes = 1000001
			}
			got, err := kallsyms.LookupBPF(ctx, r, cfg, key)
			if err == nil || got != nil {
				t.Fatal("invalid lookup became absence/match", got, err)
			}
			if strings.HasPrefix(fault, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
func TestBPFProgramFailures(t *testing.T) {
	c := bpfFaultCase(t, "pack")
	for _, fault := range []string{"null-program", "null-aux", "aux-pointer-width", "function-pointer", "pages-hole", "name-hole", "overflow", "region-only-name-fault"} {
		t.Run(fault, func(t *testing.T) {
			r, data, _ := bpfReader(t, c)
			prog := uint64(0x21000)
			table := r.Symbols.(*symbols.ISF)
			switch fault {
			case "null-program":
				prog = 0
			case "null-aux":
				binary.LittleEndian.PutUint64(data[prog:], 0)
			case "aux-pointer-width":
				table.Bases["narrow"] = symbols.Type{Kind: "int", Size: 4, Endian: "little"}
				v := table.Types["bpf_prog"]
				f := v.Fields["aux"]
				f.Type.Base = "narrow"
				v.Fields["aux"] = f
				table.Types["bpf_prog"] = v
			case "function-pointer":
				v := table.Types["bpf_prog"]
				f := v.Fields["bpf_func"]
				f.Type.Kind = "base"
				f.Type.Name = "word"
				v.Fields["bpf_func"] = f
				table.Types["bpf_prog"] = v
			case "pages-hole":
				at := uint64(0x30040)
				r.Layer = &bpfObserved{buffer: data, failAt: &at}
			case "name-hole", "region-only-name-fault":
				at := uint64(0x1fe0)
				r.Layer = &bpfObserved{buffer: data, failAt: &at}
			case "overflow":
				v := table.Types["bpf_binary_header"]
				f := v.Fields["pages"]
				f.Type.Name = "word"
				v.Size = 8
				v.Fields["pages"] = f
				table.Types["bpf_binary_header"] = v
				binary.LittleEndian.PutUint64(data[0x30040:], ^uint64(0))
			}
			if fault == "region-only-name-fault" {
				info, err := kallsyms.ReadBPFRegion(context.Background(), r, prog)
				if err != nil || info.RegionStart != 0x30040 {
					t.Fatal(info, err)
				}
				return
			}
			if _, err := kallsyms.ReadBPFProgram(context.Background(), r, prog); err == nil {
				t.Fatal("invalid BPF metadata accepted")
			}
		})
	}
}
func FuzzBPFLookup(f *testing.F) {
	for _, layout := range []string{"modern", "legacy", "pack"} {
		f.Add([]byte{0}, layout, uint8(0), uint64(0x8800))
	}
	originals := map[string]bpfCase{}
	for _, layout := range []string{"modern", "legacy", "pack"} {
		originals[layout] = bpfFaultCase(f, layout)
	}
	f.Fuzz(func(t *testing.T, payload []byte, layout string, region uint8, key uint64) {
		c, ok := originals[layout]
		if !ok || len(payload) > 128 {
			return
		}
		r, data, cfg := bpfReader(t, c)
		cfg.MaxNodes = 16
		at := []int{0x1000, 0x1020, 0x2010, 0x2210, 0x1fc0, 0x21000, 0x30040}[int(region)%7]
		copy(data[at:], payload)
		got, err := kallsyms.LookupBPF(context.Background(), r, cfg, key)
		if err != nil && got != nil {
			t.Fatal("failed BPF match")
		}
		if got != nil && got.Search.Visited > 16 {
			t.Fatal("unbounded BPF search")
		}
	})
}

type bpfBoundaryLayer struct {
	buffer
	calls, fail, cancelAt int
	cancel                context.CancelFunc
}

func (l *bpfBoundaryLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.calls++
	if l.calls == l.fail {
		return 0, memory.ErrUnmapped
	}
	n, err := l.buffer.ReadAt(ctx, p, at)
	if l.calls == l.cancelAt {
		l.cancel()
	}
	return n, err
}
func TestBPFLookupEveryAcquisitionBoundary(t *testing.T) {
	for _, layout := range []string{"modern", "legacy", "pack"} {
		c := bpfFaultCase(t, layout)
		r, data, cfg := bpfReader(t, c)
		probe := &bpfBoundaryLayer{buffer: data}
		r.Layer = probe
		key := uint64(0x8800)
		if layout == "legacy" {
			key = 0x30000
		}
		if layout == "pack" {
			key = 0x30040
		}
		result, err := kallsyms.LookupBPF(context.Background(), r, cfg, key)
		if err != nil || result == nil {
			t.Fatal(layout, result, err)
		}
		reads := probe.calls
		for boundary := 1; boundary <= reads; boundary++ {
			for _, cancelInside := range []bool{false, true} {
				ctx, cancel := context.WithCancel(context.Background())
				layer := &bpfBoundaryLayer{buffer: data, cancel: cancel}
				if cancelInside {
					layer.cancelAt = boundary
				} else {
					layer.fail = boundary
				}
				r.Layer = layer
				result, err := kallsyms.LookupBPF(ctx, r, cfg, key)
				cancel()
				if err == nil || result != nil {
					t.Fatal(layout, boundary, cancelInside, result, err)
				}
				if cancelInside && !errors.Is(err, context.Canceled) {
					t.Fatal(layout, boundary, err)
				}
				// No failed state may poison a later successful query on the same Reader.
				r.Layer = data
				result, err = kallsyms.LookupBPF(context.Background(), r, cfg, key)
				if err != nil || result == nil {
					t.Fatal("retry", layout, boundary, result, err)
				}
			}
		}
	}
}

type bpfPagingReads struct {
	memory.MemoryLayer
	original buffer
	t        *testing.T
	reads    uint64
}

func (l *bpfPagingReads) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if err == nil {
		expected := make([]byte, len(p))
		m, cause := l.original.ReadAt(ctx, expected, at)
		if cause != nil || m != n || !bytes.Equal(expected, p) {
			l.t.Fatal("paged BPF acquisition differs", at, n, m, cause)
		}
		l.reads++
	}
	return n, err
}
func TestBPFLookupIntelPaging(t *testing.T) {
	for _, c := range bpfCases(t) {
		modes := []string{"x64"}
		if c.Width == 4 {
			modes = []string{"x86", "pae"}
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("%s/%t/%d/%s/%s", mode, c.Nested, c.Sequence, c.Layout, c.Scenario), func(t *testing.T) {
				flat, data, cfg := bpfReader(t, c)
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
				for i := uint64(0); i < 0x50; i++ {
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
				for i, query := range c.Expected {
					expected, wantErr := kallsyms.LookupBPF(context.Background(), flat, cfg, query.Query)
					got, err := kallsyms.LookupBPF(context.Background(), paged, cfg, query.Query)
					if !reflect.DeepEqual(got, expected) || (err == nil) != (wantErr == nil) {
						t.Fatal(i, got, expected, err, wantErr)
					}
				}
				if c.Scenario != "missing-root" && trace.reads == 0 {
					t.Fatal("paging not exercised")
				}
			})
		}
	}
}
