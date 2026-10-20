package object_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestSignedEnumsAndAnonymousFaults(t *testing.T) {
	for _, endian := range []string{"little", "big"} {
		t.Run(endian, func(t *testing.T) {
			data := make([]byte, 32)
			var order binary.ByteOrder = binary.LittleEndian
			if endian == "big" {
				order = binary.BigEndian
			}
			order.PutUint32(data, 0xfffffffe)
			order.PutUint32(data[4:], 17)
			order.PutUint64(data[8:], ^uint64(0))
			table := &symbols.ISF{Meta: map[string]json.RawMessage{"format": json.RawMessage(`"6.2.0"`)}, Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: 8, Endian: endian}, "i32": {Kind: "int", Size: 4, Endian: endian, Signed: true}, "u64": {Kind: "int", Size: 8, Endian: endian}, "void": {Kind: "void", Endian: endian}}, Types: map[string]symbols.Type{"root": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"signed": {Type: symbols.TypeRef{Kind: "base", Name: "i32"}}, "enum": {Offset: 4, Type: symbols.TypeRef{Kind: "enum", Name: "unknown"}}, "max": {Offset: 8, Type: symbols.TypeRef{Kind: "base", Name: "u64"}}}}}, Enums: map[string]symbols.Enumeration{"unknown": {Base: "void", Size: 4, Constants: map[string]json.Number{"known": "1"}}, "incomplete": {Base: "void", Size: 0, Constants: map[string]json.Number{}}}, Symbols: map[string]symbols.Symbol{"root": {Address: 0}}}
			encoded, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			table, err = symbols.Parse(encoded)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "memory")
			os.WriteFile(path, data, 0600)
			source, err := memory.OpenFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			layer, err := memory.NewMapped(source, "data", []memory.Range{{Start: 0, Length: 32, FileOffset: 0}})
			if err != nil {
				t.Fatal(err)
			}
			r := &object.Reader{Layer: layer, Symbols: table}
			v, err := r.Int(context.Background(), 0, "root", "signed")
			if err != nil || v != -2 {
				t.Fatal(v, err)
			}
			if _, err = r.Int(context.Background(), 0, "root", "enum"); err == nil {
				t.Fatal("unspecified enum signedness guessed")
			}
			raw, names, err := r.Enum(context.Background(), 0, "root", "enum")
			if err != nil || raw != 17 || len(names) != 0 {
				t.Fatal(raw, names, err)
			}
			if _, err = r.Int(context.Background(), 0, "root", "max"); err == nil {
				t.Fatal("unsigned overflow became negative")
			}
			table.Types["leaf"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"value": {Type: symbols.TypeRef{Kind: "base", Name: "i32"}}}}
			table.Types["ambiguous"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"a": {Anonymous: true, Type: symbols.TypeRef{Kind: "struct", Name: "leaf"}}, "b": {Offset: 4, Anonymous: true, Type: symbols.TypeRef{Kind: "struct", Name: "leaf"}}}}
			table.Types["outer"] = symbols.Type{Kind: "struct", Size: 12, Fields: map[string]symbols.Field{"a": {Anonymous: true, Type: symbols.TypeRef{Kind: "struct", Name: "ambiguous"}}, "b": {Offset: 8, Anonymous: true, Type: symbols.TypeRef{Kind: "struct", Name: "leaf"}}}}
			if _, err = r.Field("outer", "value"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatal("nested ambiguity ignored", err)
			}
			table.Types["bad"] = symbols.Type{Kind: "struct", Size: 2, Fields: table.Types["leaf"].Fields}
			table.Types["outer"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"bad": {Anonymous: true, Type: symbols.TypeRef{Kind: "struct", Name: "bad"}}}}
			if _, err = r.Field("outer", "value"); err == nil {
				t.Fatal("anonymous child boundary ignored")
			}
		})
	}
}
