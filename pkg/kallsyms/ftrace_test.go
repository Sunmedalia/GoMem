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
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/kallsyms"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type ftraceCase struct {
	Width    int
	Scenario string
	ISF      json.RawMessage
	Writes   [][]json.RawMessage
	Expected []struct {
		Query  uint64
		Result *struct {
			coreRow
			Module, Subsystem string
		}
		Error *struct{ Class, Message string }
	}
}

func ftraceCases(t testing.TB) []ftraceCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/ftrace-lookup-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []ftraceCase
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 46 {
		t.Fatal("ftrace oracle provenance/count")
	}
	return v.Cases
}
func ftraceReader(t testing.TB, c ftraceCase) (*object.Reader, buffer, kallsyms.FtraceConfig, error) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := make(buffer, 0x30000)
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
	mask := uint64(0xffffffff)
	if c.Width == 8 {
		mask = 0x0000ffffffffffff
	}
	cfg, err := kallsyms.FtraceFromSymbols(table, 0, mask, 64)
	return &object.Reader{Layer: data, Symbols: table}, data, cfg, err
}
func TestPinnedFtraceLookup(t *testing.T) {
	queries := 0
	for _, c := range ftraceCases(t) {
		t.Run(fmt.Sprintf("%d/%s", c.Width, c.Scenario), func(t *testing.T) {
			r, data, cfg, err := ftraceReader(t, c)
			if c.Scenario == "missing-maps-symbol" {
				if err == nil {
					t.Fatal("missing map symbol accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			trace := &bpfObserved{buffer: data}
			r.Layer = trace
			for i, want := range c.Expected {
				queries++
				trace.reads = nil
				got, err := kallsyms.LookupFtrace(context.Background(), r, cfg, want.Query)
				for _, read := range trace.reads {
					raw, cause := memory.Read(context.Background(), data, read.at, read.want)
					if (cause == nil) != (read.err == nil) || !bytes.Equal(raw, read.data) {
						t.Fatal("independent ftrace acquisition", cause, read.err)
					}
				}
				if want.Error != nil {
					if err == nil || got != nil {
						t.Fatal(i, want.Error, got, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(i, err)
				}
				if want.Result == nil {
					if got != nil {
						t.Fatal(i, got)
					}
					continue
				}
				if got == nil || !reflect.DeepEqual(bpfRow(got.Symbol), &want.Result.coreRow) || got.Module != want.Result.Module || got.Subsystem != want.Result.Subsystem {
					t.Fatalf("query %d %#x got %+v want %+v", i, want.Query, got, want.Result)
				}
			}
		})
	}
	t.Logf("%d native queries (missing-root symbol rejected during configuration)", queries)
}
func ftraceNormal(t testing.TB) ftraceCase {
	for _, c := range ftraceCases(t) {
		if c.Width == 8 && c.Scenario == "normal" {
			return c
		}
	}
	t.Fatal("missing fixture")
	return ftraceCase{}
}
func TestFtraceLookupEveryAcquisitionBoundary(t *testing.T) {
	for _, key := range []uint64{0x8600, 0x8700, 0xffff} {
		r, data, cfg, err := ftraceReader(t, ftraceNormal(t))
		if err != nil {
			t.Fatal(err)
		}
		probe := &bpfBoundaryLayer{buffer: data}
		r.Layer = probe
		expected, err := kallsyms.LookupFtrace(context.Background(), r, cfg, key)
		if err != nil {
			t.Fatal(err)
		}
		for boundary := 1; boundary <= probe.calls; boundary++ {
			for _, cancelInside := range []bool{false, true} {
				ctx, cancel := context.WithCancel(context.Background())
				layer := &bpfBoundaryLayer{buffer: data, cancel: cancel}
				if cancelInside {
					layer.cancelAt = boundary
				} else {
					layer.fail = boundary
				}
				r.Layer = layer
				got, err := kallsyms.LookupFtrace(ctx, r, cfg, key)
				cancel()
				if err == nil || got != nil {
					t.Fatal(key, boundary, cancelInside, got, err)
				}
				if cancelInside && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				r.Layer = data
				got, err = kallsyms.LookupFtrace(context.Background(), r, cfg, key)
				if err != nil || !reflect.DeepEqual(got, expected) {
					t.Fatal("retry", got, expected, err)
				}
			}
		}
	}
}
func TestFtraceLookupFailures(t *testing.T) {
	for _, fault := range []string{"cycle", "bound", "zero-bound", "large-bound", "zero-mask", "truncated", "negative", "overflow", "bad-list-type", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			r, data, cfg, err := ftraceReader(t, ftraceNormal(t))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key := uint64(0xffff)
			switch fault {
			case "cycle":
				binary.LittleEndian.PutUint64(data[0x19d00:], 0x19d00)
			case "bound":
				cfg.MaxNodes = 1
			case "zero-bound":
				cfg.MaxNodes = 0
			case "large-bound":
				cfg.MaxNodes = 1000001
			case "zero-mask":
				cfg.AddressMask = 0
			case "truncated":
				r.Layer = data[:0x19f20]
			case "negative":
				table := r.Symbols.(*symbols.ISF)
				scalar := table.Types["u32"]
				scalar.Signed = true
				table.Types["u32"] = scalar
				binary.LittleEndian.PutUint32(data[0x19d20:], 0xffffffff)
			case "overflow":
				cfg.AddressMask = ^uint64(0)
				binary.LittleEndian.PutUint64(data[0x1a110:], ^uint64(0)-3)
			case "bad-list-type":
				table := r.Symbols.(*symbols.ISF)
				v := table.Types["ftrace_mod_func"]
				f := v.Fields["list"]
				f.Type.Kind = "pointer"
				v.Fields["list"] = f
				table.Types["ftrace_mod_func"] = v
			case "cancel":
				cancel()
			}
			got, err := kallsyms.LookupFtrace(ctx, r, cfg, key)
			if err == nil || got != nil {
				t.Fatal(got, err)
			}
		})
	}
}
func FuzzFtraceLookup(f *testing.F) {
	c := ftraceNormal(f)
	f.Add(uint64(0x8600), uint8(0), []byte{0})
	f.Add(uint64(0x8700), uint8(4), []byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, key uint64, region uint8, payload []byte) {
		if len(payload) > 512 {
			t.Skip()
		}
		r, data, cfg, err := ftraceReader(t, c)
		if err != nil {
			t.Fatal(err)
		}
		cfg.MaxNodes = 8
		at := []int{0x17c20, 0x19c00, 0x19d00, 0x19f00, 0x1a100}[int(region)%5]
		copy(data[at:], payload)
		got, err := kallsyms.LookupFtrace(context.Background(), r, cfg, key)
		if err != nil && got != nil {
			t.Fatal("failed lookup returned a symbol")
		}
		if got != nil && got.Visited > 8 {
			t.Fatal("unbounded ftrace traversal")
		}
	})
}

func TestFtraceLookupIntelPaging(t *testing.T) {
	for _, c := range ftraceCases(t) {
		modes := []string{"x64"}
		if c.Width == 4 {
			modes = []string{"x86", "pae"}
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("%s/%s", mode, c.Scenario), func(t *testing.T) {
				flat, data, cfg, err := ftraceReader(t, c)
				if c.Scenario == "missing-maps-symbol" {
					return
				}
				if err != nil {
					t.Fatal(err)
				}
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
				for i, query := range c.Expected {
					expected, wantErr := kallsyms.LookupFtrace(context.Background(), flat, cfg, query.Query)
					got, err := kallsyms.LookupFtrace(context.Background(), paged, cfg, query.Query)
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

func TestFtraceSharedBoundAndSymbolRoots(t *testing.T) {
	r, _, cfg, err := ftraceReader(t, ftraceNormal(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxNodes = 2
	if got, err := kallsyms.LookupFtrace(context.Background(), r, cfg, 0x8600); err != nil || got == nil || got.Visited != 2 {
		t.Fatal(got, err)
	}
	if got, err := kallsyms.LookupFtrace(context.Background(), r, cfg, 0x8700); err == nil || got != nil {
		t.Fatal("trampoline escaped aggregate bound", got, err)
	}
	slid, err := kallsyms.FtraceFromSymbols(r.Symbols, 0x1000, cfg.AddressMask, 64)
	if err != nil || slid.Maps != cfg.Maps+0x1000 || slid.Trampolines != cfg.Trampolines+0x1000 {
		t.Fatal(slid, err)
	}
	if _, err := kallsyms.FtraceFromSymbols(r.Symbols, ^uint64(0), cfg.AddressMask, 64); err == nil {
		t.Fatal("root address overflow accepted")
	}
	if _, err := kallsyms.FtraceFromSymbols(nil, 0, cfg.AddressMask, 64); err == nil {
		t.Fatal("nil symbols accepted")
	}
	if got, err := kallsyms.LookupFtrace(context.Background(), nil, cfg, 0); err == nil || got != nil {
		t.Fatal("nil reader accepted")
	}
}

func TestFtraceAbsentAndZeroAddressRoot(t *testing.T) {
	r, data, cfg, err := ftraceReader(t, ftraceNormal(t))
	if err != nil {
		t.Fatal(err)
	}
	empty := cfg
	empty.HasMaps = false
	empty.HasTrampolines = false
	trace := &bpfObserved{buffer: data}
	r.Layer = trace
	if got, err := kallsyms.LookupFtrace(context.Background(), r, empty, 0x8600); err != nil || got != nil || len(trace.reads) != 0 {
		t.Fatal(got, err, trace.reads)
	}
	// Address zero is a configured list head, not the absent-source sentinel.
	copy(data[:16], data[cfg.Maps:cfg.Maps+16])
	binary.LittleEndian.PutUint64(data[0x19c00:], 0)
	binary.LittleEndian.PutUint64(data[0x19c08:], 0)
	cfg.Maps = 0
	r.Layer = data
	got, err := kallsyms.LookupFtrace(context.Background(), r, cfg, 0x8600)
	if err != nil || got == nil || got.Symbol.Name != "ftrace_entry" {
		t.Fatal(got, err)
	}
	if got, err := kallsyms.LookupFtrace(context.Background(), r, cfg, 0x8700); err != nil || got == nil || got.Kind != "trampoline" {
		t.Fatal(got, err)
	}
}
