package plugins

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestLinuxIDTTypePriority(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-idt-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Selections []struct {
			Width    int
			Present  []string
			Selected *string
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Selections) != 16 {
		t.Fatal(err)
	}
	for _, test := range oracle.Selections {
		table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: uint64(test.Width)}}, Types: map[string]symbols.Type{}}
		for _, typ := range test.Present {
			table.Types[typ] = symbols.Type{Kind: "struct", Size: 16}
		}
		got, size, err := linuxIDTType(plugin.Environment{Symbols: table})
		if test.Selected == nil {
			if err == nil {
				t.Fatal(test, got)
			}
		} else if err != nil || got != *test.Selected || size != 16 {
			t.Fatal(test, got, size, err)
		}
	}
	// The first declared supported name wins even if its extent is corrupt.
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Size: 8}}, Types: map[string]symbols.Type{"gate_struct64": {Size: 0}, "gate_struct": {Size: 16}}}
	if _, _, err := linuxIDTType(plugin.Environment{Symbols: table}); err == nil {
		t.Fatal("invalid preferred descriptor silently bypassed")
	}
}

// Mutate descriptor bytes and field extents together. Invalid or truncated
// members must return a read/layout error, never panic or fabricate a handler.
func FuzzLinuxIDTDescriptor(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, uint16(0), uint8(0))
	f.Add([]byte{1, 2}, uint16(65535), uint8(1))
	f.Fuzz(func(t *testing.T, raw []byte, offset uint16, mode uint8) {
		if len(raw) > 64 {
			raw = raw[:64]
		}
		_, env, n := moduleLookupFixture(8, false)
		env.Kernel = capabilityLayer(raw)
		env.Objects = &object.Reader{Layer: env.Kernel, Symbols: env.Symbols}
		n.e = env
		table := env.Symbols.(*symbols.ISF)
		ref := symbols.TypeRef{Kind: "base", Name: "u32"}
		fields := map[string]symbols.Field{}
		at := uint64(offset)
		if mode&1 == 0 {
			fields["a"] = symbols.Field{Offset: at, Type: ref}
			fields["b"] = symbols.Field{Offset: 4, Type: ref}
		} else {
			table.Bases["u16"] = symbols.Type{Kind: "int", Size: 2, Endian: "little"}
			fields["offset_low"] = symbols.Field{Offset: at, Type: symbols.TypeRef{Kind: "base", Name: "u16"}}
			fields["offset_middle"] = symbols.Field{Offset: 6, Type: symbols.TypeRef{Kind: "base", Name: "u16"}}
			if mode&2 != 0 {
				fields["offset_high"] = symbols.Field{Offset: 8, Type: ref}
			}
		}
		table.Types["gate"] = symbols.Type{Kind: "struct", Size: 16, Fields: fields}
		address, err := linuxIDTAddress(n, 0, "gate", 0xffffffffffff)
		if err == nil {
			if address > 0xffffffffffff || mode&1 == 0 && address > 0xffffffff {
				t.Fatal("decoded handler escaped its address mask", address)
			}
			if len(raw) < 8 || at >= 16 {
				t.Fatal("invalid descriptor accepted", len(raw), at)
			}
		}
	})
}
