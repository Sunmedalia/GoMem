package plugins

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestLinuxModulePinnedPolicies(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-modxview-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Taints, Dynamic []struct{ Value, Plain, Parsed string }
		Validity        []struct {
			Core, Text, Init, Self uint64
			Readable, Valid        bool
		}
		Aggregates []struct {
			Sources map[string][][]any
			Rows    []struct {
				Name               string
				Offset             uint64
				Lsmod, Sysfs, Scan bool
			}
			Flattened []struct{ Offset, Base uint64 }
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	if len(oracle.Taints) != 14 || len(oracle.Dynamic) != 32 || len(oracle.Validity) != 12 || len(oracle.Aggregates) != 3 {
		t.Fatal("oracle drift")
	}
	for _, tc := range oracle.Taints {
		value, err := strconv.ParseUint(tc.Value, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		got := linuxTaintPlain(value, true)
		if got != tc.Plain || linuxTaintParsed(got) != tc.Parsed {
			t.Fatal(tc, got, linuxTaintParsed(got))
		}
	}
	for _, tc := range oracle.Validity {
		if got := linuxModuleCandidateValid(tc.Core, tc.Text, tc.Init, tc.Self, 1, tc.Readable); got != tc.Valid {
			t.Fatal(tc, got)
		}
	}
	for _, tc := range oracle.Aggregates {
		sources := map[string][]linuxModuleInfo{}
		for source, values := range tc.Sources {
			for _, v := range values {
				sources[source] = append(sources[source], linuxModuleInfo{uint64(v[0].(float64)), uint64(v[2].(float64)), uint64(v[3].(float64) - v[2].(float64)), v[1].(string), source})
			}
		}
		flat := linuxFlattenModuleSources(sources, ^uint64(0))
		if len(flat) != len(tc.Flattened) {
			t.Fatal(flat, tc)
		}
		for i, v := range flat {
			if v.offset != tc.Flattened[i].Offset || v.base != tc.Flattened[i].Base {
				t.Fatal(flat, tc)
			}
		}
		aggregates := linuxAggregateModuleSources(sources)
		if len(aggregates) != len(tc.Rows) {
			t.Fatal(aggregates, tc)
		}
		for i, a := range aggregates {
			want := tc.Rows[i]
			if a.offset != want.Offset {
				t.Fatal(a, want)
			}
			has := func(source string) bool {
				for _, v := range a.gatherers {
					if source == v {
						return true
					}
				}
				return false
			}
			if has("Lsmod") != want.Lsmod || has("SysFs") != want.Sysfs || has("Scanner") != want.Scan {
				t.Fatal(a, want)
			}
		}
	}
	layer := capabilityLayer(make([]byte, 4096))
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	ref := symbols.TypeRef{Kind: "struct", Name: "taint_flag"}
	array := symbols.TypeRef{Kind: "array", Count: 5, Subtype: &ref}
	table := &symbols.ISF{Bases: map[string]symbols.Type{"u32": {Kind: "int", Size: 4, Endian: "little"}, "pointer": {Kind: "int", Size: 8, Endian: "little"}}, Types: map[string]symbols.Type{"taint_flag": {Kind: "struct", Size: 12, Fields: map[string]symbols.Field{"c_true": {Type: u32}, "c_false": {Offset: 4, Type: u32}, "module": {Offset: 8, Type: u32}}}}, Symbols: map[string]symbols.Symbol{"taint_flags": {Address: 0x100, Type: &array}}}
	for i, flag := range []struct{ yes, no, mod uint32 }{{'P', 'G', 1}, {'F', ' ', 0}, {'?', '-', 1}, {0x110000, ' ', 1}, {'O', ' ', 1}} {
		at := 0x100 + i*12
		binary.LittleEndian.PutUint32(layer[at:], flag.yes)
		binary.LittleEndian.PutUint32(layer[at+4:], flag.no)
		binary.LittleEndian.PutUint32(layer[at+8:], flag.mod)
	}
	env := plugin.Environment{Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}}
	for _, tc := range oracle.Dynamic {
		var failures pluginFailures
		n := &linuxModuleRead{context.Background(), env, map[string]evidence.Value{}, &failures}
		value, _ := strconv.ParseUint(tc.Value, 10, 64)
		got, err := linuxModuleTaints(n, value)
		if err != nil || failures.count != 0 || got != tc.Plain || linuxTaintParsed(got) != tc.Parsed {
			t.Fatal(tc, got, err)
		}
	}
}

func FuzzLinuxModuleMemoryLayouts(f *testing.F) {
	f.Add(uint64(7), uint64(0), uint64(0), uint64(1024))
	f.Add(^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0))
	f.Fuzz(func(t *testing.T, count, index, address, value uint64) {
		layer := capabilityLayer(make([]byte, 1024))
		for at := 8; at < len(layer); at += 16 {
			binary.LittleEndian.PutUint64(layer[at:], value)
		}
		u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
		mem := symbols.TypeRef{Kind: "struct", Name: "module_memory"}
		table := &symbols.ISF{Bases: map[string]symbols.Type{"u64": {Kind: "int", Size: 8, Endian: "little"}, "pointer": {Kind: "int", Size: 8, Endian: "little"}}, Types: map[string]symbols.Type{"module": {Kind: "struct", Size: 1024, Fields: map[string]symbols.Field{"mem": {Type: symbols.TypeRef{Kind: "array", Count: count, Subtype: &mem}}}}, "module_memory": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"size": {Offset: 8, Type: u64}, "base": {Type: u64}}}}, Enums: map[string]symbols.Enumeration{"mod_mem_type": {Size: 4, Base: "u64", Constants: map[string]json.Number{"MOD_TEXT": json.Number(strconv.FormatUint(index, 10)), "MOD_DATA": "1", "MOD_RODATA": "2", "MOD_RO_AFTER_INIT": "3", "MOD_INIT_TEXT": "4", "MOD_INIT_DATA": "5", "MOD_INIT_RODATA": "6"}}}}
		env := plugin.Environment{Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}}
		var failures pluginFailures
		n := &linuxModuleRead{context.Background(), env, map[string]evidence.Value{}, &failures}
		for _, kind := range []string{"base", "core", "text", "init"} {
			n.layout(address, kind)
		}
	})
}
