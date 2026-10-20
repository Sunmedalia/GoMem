package object_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestPointerBaseOverridesNativeWidth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "four-bytes")
	if err := os.WriteFile(path, []byte{0x78, 0x56, 0x34, 0x12}, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := memory.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	layer, err := memory.NewMapped(source, "pointer32", []memory.Range{{Length: 4}})
	if err != nil {
		t.Fatal(err)
	}
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: 8, Endian: "little"}, "pointer32": {Kind: "int", Size: 4, Endian: "little"}}}
	r := object.Reader{Symbols: table, Layer: layer}
	value, err := r.Scalar(context.Background(), 0, symbols.TypeRef{Kind: "pointer", Base: "pointer32"})
	if err != nil || value != 0x12345678 {
		t.Fatal(value, err)
	}
}
