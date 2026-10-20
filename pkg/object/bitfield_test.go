package object_test

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestPackedBitfieldReadsOnlyResidentBytes(t *testing.T) {
	for _, endian := range []string{"little", "big"} {
		t.Run(endian, func(t *testing.T) {
			position, data := uint64(9), byte(0x36)
			if endian == "big" {
				position, data = 18, 0x6c
			}
			underlying := symbols.TypeRef{Kind: "enum", Name: "state"}
			field := symbols.TypeRef{Kind: "bitfield", BitType: &underlying, BitPosition: position, BitLength: 5}
			table := &symbols.ISF{Bases: map[string]symbols.Type{"int": {Kind: "int", Size: 4, Signed: true, Endian: endian}},
				Types: map[string]symbols.Type{"packed": {Kind: "struct", Size: 2, Fields: map[string]symbols.Field{"value": {Type: field}}}},
				Enums: map[string]symbols.Enumeration{"state": {Base: "int", Size: 4, Constants: map[string]json.Number{"negative_five": "-5"}}}}
			path := filepath.Join(t.TempDir(), "one-byte")
			if err := os.WriteFile(path, []byte{data}, 0600); err != nil {
				t.Fatal(err)
			}
			source, err := memory.OpenFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			// The other bytes of the declared four-byte int are absent.
			layer, err := memory.NewMapped(source, "sparse", []memory.Range{{Start: 0x1001, Length: 1}})
			if err != nil {
				t.Fatal(err)
			}
			r := &object.Reader{Layer: layer, Symbols: table}
			value, err := r.Int(context.Background(), 0x1000, "packed", "value")
			if err != nil || value != -5 {
				t.Fatal(value, err)
			}
			raw, names, err := r.Enum(context.Background(), 0x1000, "packed", "value")
			if err != nil || raw != 27 || len(names) != 1 || names[0] != "negative_five" {
				t.Fatal(raw, names, err)
			}
			width, err := r.Size(field)
			if err != nil || width != 4 {
				t.Fatal("declared size lost", width, err)
			}
			typ := table.Types["packed"]
			typ.Size = 1
			table.Types["packed"] = typ
			if _, err := r.Field("packed", "value"); err == nil {
				t.Fatal("packed field exceeds its containing type")
			}
			bad := field
			bad.BitPosition = math.MaxUint64
			if _, err := r.Scalar(context.Background(), 0x1000, bad); err == nil {
				t.Fatal("overflowing bit range accepted")
			}
		})
	}
}
