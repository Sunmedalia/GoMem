package kallsyms_test

import (
	"bytes"
	"context"
	"encoding/binary"
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

type moduleCase struct {
	ftraceCase
	Layout   string
	Sequence uint64
	Nested   bool
	Expected []struct {
		Query      uint64
		Explicit   bool
		TreeObject *uint64
		Result     *struct {
			coreRow
			Module, Subsystem string
		}
		Error *struct{ Class, Message string }
	}
}

func moduleCases(t testing.TB) []moduleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/module-lookup-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []moduleCase
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 240 {
		t.Fatal("module oracle provenance/count")
	}
	return v.Cases
}
func moduleReader(t testing.TB, c moduleCase) (*object.Reader, buffer, kallsyms.ModuleConfig) {
	t.Helper()
	r, data, f, err := ftraceReader(t, c.ftraceCase)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := kallsyms.ModuleFromSymbols(r.Symbols, 0, f.AddressMask, 64, 100)
	if err != nil {
		t.Fatal(err)
	}
	return r, data, cfg
}
func TestPinnedModuleLookup(t *testing.T) {
	for _, c := range moduleCases(t) {
		t.Run(fmt.Sprintf("%d/%s/%s/%d/%t", c.Width, c.Layout, c.Scenario, c.Sequence, c.Nested), func(t *testing.T) {
			r, data, cfg := moduleReader(t, c)
			trace := &bpfObserved{buffer: data}
			r.Layer = trace
			for i, want := range c.Expected {
				var module *uint64
				if want.Explicit {
					at := uint64(0x18000)
					module = &at
				}
				trace.reads = nil
				got, err := kallsyms.LookupModule(context.Background(), r, cfg, want.Query, module)
				for _, read := range trace.reads {
					raw, cause := memory.Read(context.Background(), data, read.at, read.want)
					if (cause == nil) != (read.err == nil) || !bytes.Equal(raw, read.data) {
						t.Fatal("module independent reread", cause, read.err)
					}
				}
				if !reflect.DeepEqual(got.TreeModule, want.TreeObject) {
					t.Fatal("tree owner differs from baseline", i, got.TreeModule, want.TreeObject)
				}
				if want.Error != nil {
					if err == nil || got.Match != nil {
						t.Fatal(i, want.Query, want.Explicit, want.Error, got, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(i, want.Query, want.Explicit, err)
				}
				if want.Result == nil {
					if got.Match != nil {
						t.Fatal(i, got.Match)
					}
					continue
				}
				if got.Match == nil || !reflect.DeepEqual(bpfRow(got.Match.Symbol), &want.Result.coreRow) || got.Match.Module != want.Result.Module || got.Match.Subsystem != want.Result.Subsystem {
					t.Fatalf("query %d %#x explicit %t: got %+v want %+v", i, want.Query, want.Explicit, got.Match, want.Result)
				}
				at := got.Match.Entry
				value, size := uint64(0), uint64(0)
				if c.Width == 8 {
					value = binary.LittleEndian.Uint64(data[at+8 : at+16])
					size = binary.LittleEndian.Uint64(data[at+16 : at+24])
				} else {
					value = uint64(binary.LittleEndian.Uint32(data[at+4 : at+8]))
					size = uint64(binary.LittleEndian.Uint32(data[at+8 : at+12]))
				}
				if got.Match.RawABIValue != value || got.Match.RawABISize != size {
					t.Fatal("ABI evidence", got.Match, value, size)
				}
				if (c.Scenario == "tree" || c.Scenario == "tree-empty") && !want.Explicit && got.Search.Sequence != c.Sequence {
					t.Fatal("selected tree", got.Search)
				}
			}
		})
	}
}
func moduleNormal(t testing.TB, tree bool) moduleCase {
	for _, c := range moduleCases(t) {
		if c.Width == 8 && c.Layout == "typetab" && c.Sequence == 0 && !c.Nested && ((tree && c.Scenario == "tree") || (!tree && c.Scenario == "normal")) {
			return c
		}
	}
	t.Fatal("missing module fixture")
	return moduleCase{}
}
func TestModuleLookupEveryAcquisitionBoundary(t *testing.T) {
	for _, tree := range []bool{false, true} {
		for _, explicit := range []bool{false, true} {
			for _, key := range []uint64{0x8500, 0x8520} {
				r, data, cfg := moduleReader(t, moduleNormal(t, tree))
				var module *uint64
				if explicit {
					at := uint64(0x18000)
					module = &at
				}
				probe := &bpfBoundaryLayer{buffer: data}
				r.Layer = probe
				expected, err := kallsyms.LookupModule(context.Background(), r, cfg, key, module)
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
						got, err := kallsyms.LookupModule(ctx, r, cfg, key, module)
						cancel()
						if err == nil || got.Match != nil {
							t.Fatal(tree, explicit, key, boundary, cancelInside, got, err)
						}
						if cancelInside && !errors.Is(err, context.Canceled) {
							t.Fatal(err)
						}
						r.Layer = data
						got, err = kallsyms.LookupModule(context.Background(), r, cfg, key, module)
						if err != nil || !reflect.DeepEqual(got, expected) {
							t.Fatal("retry", got, expected, err)
						}
					}
				}
			}
		}
	}
}
func TestModuleLookupMalformed(t *testing.T) {
	for _, fault := range []string{"cycle", "node-bound", "symbol-bound", "name-hole", "truncated", "list-layout", "tree-layout", "tree-module-hole", "negative-tree-size", "zero-mask", "large-bound", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			tree := fault == "tree-layout" || fault == "tree-module-hole" || fault == "negative-tree-size"
			r, data, cfg := moduleReader(t, moduleNormal(t, tree))
			key := uint64(0x8500)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "cycle":
				binary.LittleEndian.PutUint64(data[0x18000:], 0x18000)
			case "node-bound":
				cfg.MaxNodes = 0
			case "symbol-bound":
				cfg.MaxSymbols = 2
			case "name-hole":
				binary.LittleEndian.PutUint64(data[0x18208:], 0x40000)
			case "truncated":
				r.Layer = data[:0x18410]
			case "list-layout":
				table := r.Symbols.(*symbols.ISF)
				typ := table.Types["module"]
				f := typ.Fields["list"]
				f.Type.Kind = "pointer"
				typ.Fields["list"] = f
				table.Types["module"] = typ
			case "tree-layout":
				table := r.Symbols.(*symbols.ISF)
				typ := table.Types["mod_tree_root"]
				f := typ.Fields["root"]
				f.Type.Kind = "pointer"
				typ.Fields["root"] = f
				table.Types["mod_tree_root"] = typ
			case "tree-module-hole":
				binary.LittleEndian.PutUint64(data[0x1ff0:], 0x40000)
			case "negative-tree-size":
				table := r.Symbols.(*symbols.ISF)
				typ := table.Types["word"]
				typ.Signed = true
				table.Types["word"] = typ
				binary.LittleEndian.PutUint64(data[0x2088:], ^uint64(0))
			case "zero-mask":
				cfg.AddressMask = 0
			case "large-bound":
				cfg.MaxSymbols = 10000001
			case "cancel":
				cancel()
			}
			got, err := kallsyms.LookupModule(ctx, r, cfg, key, nil)
			if err == nil || got.Match != nil {
				t.Fatal(got, err)
			}
		})
	}
}

func TestModuleLookupIntelPaging(t *testing.T) {
	for _, c := range moduleCases(t) {
		modes := []string{"x64"}
		if c.Width == 4 {
			modes = []string{"x86", "pae"}
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("%s/%s/%s/%d/%t", mode, c.Layout, c.Scenario, c.Sequence, c.Nested), func(t *testing.T) {
				flat, data, cfg := moduleReader(t, c)
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
					var module *uint64
					if query.Explicit {
						at := uint64(0x18000)
						module = &at
					}
					expected, wantErr := kallsyms.LookupModule(context.Background(), flat, cfg, query.Query, module)
					got, err := kallsyms.LookupModule(context.Background(), paged, cfg, query.Query, module)
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

func TestModuleLookupBoundaryEvidenceAndConfiguration(t *testing.T) {
	for _, c := range moduleCases(t) {
		if c.Width != 8 || c.Layout != "typetab" || c.Scenario != "last-size" {
			continue
		}
		r, _, cfg := moduleReader(t, c)
		at := uint64(0x18000)
		got, err := kallsyms.LookupModule(context.Background(), r, cfg, 0x8500, &at)
		if err != nil || got.Match != nil || len(got.Ranges) != 1 || !got.Ranges[0].Reversed || got.Ranges[0].Start != 0x8500 || got.Ranges[0].End != 0 || got.Ranges[0].LastRawValue != 0x8580 || got.Ranges[0].LastRawSize != 64 {
			t.Fatal(got, err)
		}
		// Backing bytes at boundary-symbol addresses are zero: symbol coordinates
		// themselves form the fixed gate, rather than dereferenced memory values.
		if cfg.AddressMin != 0x8400 || cfg.AddressMax != 0x9000 {
			t.Fatal(cfg)
		}
		slid, err := kallsyms.ModuleFromSymbols(r.Symbols, 0x1000, cfg.AddressMask, 64, 100)
		if err != nil || slid.AddressMin != 0x9400 || slid.AddressMax != 0xa000 || slid.List != cfg.List+0x1000 {
			t.Fatal(slid, err)
		}
		if _, err := kallsyms.ModuleFromSymbols(r.Symbols, ^uint64(0), cfg.AddressMask, 64, 100); err == nil {
			t.Fatal("slide overflow accepted")
		}
		if _, err := kallsyms.ModuleFromSymbols(nil, 0, cfg.AddressMask, 64, 100); err == nil {
			t.Fatal("nil table accepted")
		}
		return
	}
	t.Fatal("missing bounds fixture")
}
func FuzzModuleLookup(f *testing.F) {
	plain, tree := moduleNormal(f, false), moduleNormal(f, true)
	f.Add(uint64(0x8500), uint8(0), false, []byte{0})
	f.Add(uint64(0x8500), uint8(4), true, []byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, key uint64, region uint8, useTree bool, payload []byte) {
		if len(payload) > 512 {
			t.Skip()
		}
		c := plain
		if useTree {
			c = tree
		}
		r, data, cfg := moduleReader(t, c)
		cfg.MaxNodes = 8
		cfg.MaxSymbols = 16
		at := []int{0x17c00, 0x18000, 0x18200, 0x18400, 0x1020, 0x2010, 0x1ff0}[int(region)%7]
		copy(data[at:], payload)
		got, err := kallsyms.LookupModule(context.Background(), r, cfg, key, nil)
		if err != nil && got.Match != nil {
			t.Fatal("failed module match")
		}
		if got.ListVisited+got.Search.Visited > 8 || got.SymbolsRead > 16 {
			t.Fatal("unbounded module lookup", got)
		}
	})
}

func TestModuleLookupAggregateBounds(t *testing.T) {
	r, _, cfg := moduleReader(t, moduleNormal(t, true))
	cfg.MaxNodes = 2
	got, err := kallsyms.LookupModule(context.Background(), r, cfg, 0x84ff, nil)
	if err == nil || got.Match != nil || got.Search.Visited != 2 || got.ListVisited != 0 {
		t.Fatal("fallback escaped shared node bound", got, err)
	}
	cfg.MaxNodes = 3
	got, err = kallsyms.LookupModule(context.Background(), r, cfg, 0x84ff, nil)
	if err != nil || got.Match != nil || got.Search.Visited != 2 || got.ListVisited != 1 {
		t.Fatal(got, err)
	}
	for _, c := range moduleCases(t) {
		if c.Width != 8 || c.Layout != "typetab" || c.Scenario != "two-modules" {
			continue
		}
		r, _, cfg := moduleReader(t, c)
		cfg.MaxSymbols = 3
		got, err = kallsyms.LookupModule(context.Background(), r, cfg, 0x8500, nil)
		if err == nil || got.Match != nil || got.SymbolsRead != 3 {
			t.Fatal("module list escaped symbol bound", got, err)
		}
		cfg.MaxSymbols = 6
		got, err = kallsyms.LookupModule(context.Background(), r, cfg, 0x8500, nil)
		if err != nil || got.Match == nil || len(got.Ranges) != 2 || got.SymbolsRead != 6 {
			t.Fatal(got, err)
		}
		return
	}
	t.Fatal("missing multiple module control")
}
