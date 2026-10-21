package object

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// ErrNullPointer distinguishes an absent target from an unreadable pointer.
var ErrNullPointer = errors.New("null object pointer")

// View binds an object's bytes and its pointer targets to explicit layers.
// Embedded members, casts and containers retain the data layer. Dereference
// switches to the native layer, including for all subsequent pointer hops.
// No address-value heuristic or fallback to a different layer is used.
// A View is immutable; the supplied layers and symbol table must outlive it.
type View struct {
	reader  Reader
	native  memory.MemoryLayer
	address uint64
	typ     string
}

// NewView validates the declared aggregate type without reading its contents.
// A nil native layer permits local reads but makes Dereference fail explicitly.
func NewView(data, native memory.MemoryLayer, table symbols.SymbolTable, address uint64, typ string) (View, error) {
	if data == nil || table == nil {
		return View{}, fmt.Errorf("object view requires a data layer and symbols")
	}
	t, err := table.Type(typ)
	if err != nil {
		return View{}, err
	}
	if t.Kind != "struct" && t.Kind != "union" {
		return View{}, fmt.Errorf("object view type %s is not an aggregate", typ)
	}
	if t.Size == 0 || t.Size-1 > ^uint64(0)-address {
		return View{}, fmt.Errorf("invalid object view range for %s at %#x", typ, address)
	}
	return View{reader: Reader{Layer: data, Symbols: table}, native: native, address: address, typ: typ}, nil
}

func (v View) Address() uint64                 { return v.address }
func (v View) Type() string                    { return v.typ }
func (v View) Layer() memory.MemoryLayer       { return v.reader.Layer }
func (v View) NativeLayer() memory.MemoryLayer { return v.native }

func (v View) valid() error {
	if v.reader.Layer == nil || v.reader.Symbols == nil || v.typ == "" {
		return fmt.Errorf("uninitialized object view")
	}
	return nil
}

func (v View) Field(path string) (symbols.Field, error) {
	if err := v.valid(); err != nil {
		return symbols.Field{}, err
	}
	return v.reader.Field(v.typ, path)
}
func (v View) Uint(ctx context.Context, path string) (uint64, error) {
	if err := v.valid(); err != nil {
		return 0, err
	}
	return v.reader.Uint(ctx, v.address, v.typ, path)
}
func (v View) Int(ctx context.Context, path string) (int64, error) {
	if err := v.valid(); err != nil {
		return 0, err
	}
	return v.reader.Int(ctx, v.address, v.typ, path)
}
func (v View) Enum(ctx context.Context, path string) (uint64, []string, error) {
	if err := v.valid(); err != nil {
		return 0, nil, err
	}
	return v.reader.Enum(ctx, v.address, v.typ, path)
}
func (v View) String(ctx context.Context, path string, maximum int) (string, error) {
	if err := v.valid(); err != nil {
		return "", err
	}
	return v.reader.String(ctx, v.address, v.typ, path, maximum)
}

// Bytes reads a bounded prefix of a declared field, never its pointer target.
// Like Reader's scalar methods, a partial read returns an error, not zeroes.
// Callers collecting partial acquisition evidence should read Layer directly.
func (v View) Bytes(ctx context.Context, path string, length int) ([]byte, error) {
	f, err := v.Field(path)
	if err != nil {
		return nil, err
	}
	size, err := v.reader.extent(f.Type)
	if err != nil {
		return nil, err
	}
	if length < 0 || uint64(length) > size {
		return nil, fmt.Errorf("read exceeds field %s.%s", v.typ, path)
	}
	a, err := memory.Add(v.address, f.Offset)
	if err != nil {
		return nil, err
	}
	return memory.Read(ctx, v.reader.Layer, a, length)
}

func (v View) Embedded(path string) (View, error) {
	f, err := v.Field(path)
	if err != nil {
		return View{}, err
	}
	if f.Type.Kind != "struct" && f.Type.Kind != "union" {
		return View{}, fmt.Errorf("%s.%s is not an embedded aggregate", v.typ, path)
	}
	a, err := memory.Add(v.address, f.Offset)
	if err != nil {
		return View{}, err
	}
	return NewView(v.reader.Layer, v.native, v.reader.Symbols, a, f.Type.Name)
}

// Cast retains the exact address, data layer and native layer. It is distinct
// from Container, which subtracts a declared embedded-member offset.
func (v View) Cast(typ string) (View, error) {
	if err := v.valid(); err != nil {
		return View{}, err
	}
	return NewView(v.reader.Layer, v.native, v.reader.Symbols, v.address, typ)
}

func (v View) Container(typ, member string) (View, error) {
	if err := v.valid(); err != nil {
		return View{}, err
	}
	f, err := v.reader.Field(typ, member)
	if err != nil {
		return View{}, err
	}
	if (f.Type.Kind != "struct" && f.Type.Kind != "union") || f.Type.Name != v.typ {
		return View{}, fmt.Errorf("%s.%s does not embed %s", typ, member, v.typ)
	}
	if v.address < f.Offset {
		return View{}, fmt.Errorf("object container underflow")
	}
	return NewView(v.reader.Layer, v.native, v.reader.Symbols, v.address-f.Offset, typ)
}

// Dereference requires a declared pointer to a struct/union. The pointer bytes
// are read from the current data layer; its target is read in the native layer.
// Nulls are rejected even if address zero is mapped. No target bytes are read
// until an accessor is invoked on the returned view.
func (v View) Dereference(ctx context.Context, path string) (View, error) {
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	f, err := v.Field(path)
	if err != nil {
		return View{}, err
	}
	if f.Type.Kind != "pointer" || f.Type.Subtype == nil || (f.Type.Subtype.Kind != "struct" && f.Type.Subtype.Kind != "union") {
		return View{}, fmt.Errorf("%s.%s is not a pointer to an aggregate", v.typ, path)
	}
	if v.native == nil {
		return View{}, fmt.Errorf("object view has no native pointer layer")
	}
	a, err := v.Uint(ctx, path)
	if err != nil {
		return View{}, err
	}
	if a == 0 {
		return View{}, fmt.Errorf("%w: %s.%s", ErrNullPointer, v.typ, path)
	}
	return NewView(v.native, v.native, v.reader.Symbols, a, f.Type.Subtype.Name)
}
