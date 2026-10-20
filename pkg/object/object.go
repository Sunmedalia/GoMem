// Package object reads typed fields without silently substituting zeroes for faults.
package object

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

var ErrFieldAbsent = errors.New("field is absent")

type ObjectReader interface {
	Field(string, string) (symbols.Field, error)
	Uint(context.Context, uint64, string, string) (uint64, error)
	Int(context.Context, uint64, string, string) (int64, error)
	Enum(context.Context, uint64, string, string) (uint64, []string, error)
	String(context.Context, uint64, string, string, int) (string, error)
}
type Reader struct {
	Layer   memory.MemoryLayer
	Symbols symbols.SymbolTable
}

func (r *Reader) Field(typ, path string) (symbols.Field, error) {
	var off uint64
	var field symbols.Field
	parts := strings.Split(path, ".")
	for index, name := range parts {
		t, e := r.Symbols.Type(typ)
		if e != nil {
			return field, e
		}
		f, e := r.findField(typ, name, map[string]bool{}, 0)
		if e != nil {
			return field, e
		}
		width, e := r.extent(f.Type)
		if e != nil {
			return field, e
		}
		if f.Offset > t.Size || width > t.Size-f.Offset {
			return field, fmt.Errorf("field %s.%s exceeds its containing type", typ, name)
		}
		if index+1 < len(parts) && f.Type.Kind != "struct" && f.Type.Kind != "union" {
			return field, fmt.Errorf("nested field %s.%s is not an embedded structure", typ, name)
		}
		off, e = memory.Add(off, f.Offset)
		if e != nil {
			return field, e
		}
		field = f
		typ = f.Type.Name
	}
	field.Offset = off
	return field, nil
}
func (r *Reader) findField(typ, name string, seen map[string]bool, depth int) (symbols.Field, error) {
	if depth > 128 || seen[typ] {
		return symbols.Field{}, fmt.Errorf("anonymous field recursion in %s", typ)
	}
	t, err := r.Symbols.Type(typ)
	if err != nil {
		return symbols.Field{}, err
	}
	if f, ok := t.Fields[name]; ok {
		width, err := r.extent(f.Type)
		if err != nil {
			return f, err
		}
		if f.Offset > t.Size || width > t.Size-f.Offset {
			return f, fmt.Errorf("field %s.%s exceeds its containing type", typ, name)
		}
		return f, nil
	}
	seen[typ] = true
	defer delete(seen, typ)
	var found *symbols.Field
	for _, f := range t.Fields {
		if !f.Anonymous || f.Type.Kind != "struct" && f.Type.Kind != "union" {
			continue
		}
		child, e := r.findField(f.Type.Name, name, seen, depth+1)
		if e != nil {
			if errors.Is(e, ErrFieldAbsent) {
				continue
			}
			return child, e
		}
		child.Offset, e = memory.Add(f.Offset, child.Offset)
		if e != nil {
			return child, e
		}
		if found != nil {
			return child, fmt.Errorf("ambiguous anonymous field %s.%s", typ, name)
		}
		copy := child
		found = &copy
	}
	if found == nil {
		return symbols.Field{}, fmt.Errorf("%w: %s.%s", ErrFieldAbsent, typ, name)
	}
	return *found, nil
}
func (r *Reader) Size(t symbols.TypeRef) (uint64, error) {
	return r.size(t, 0)
}
func (r *Reader) extent(t symbols.TypeRef) (uint64, error) {
	n, err := r.Size(t)
	if err != nil || t.Kind != "bitfield" {
		return n, err
	}
	base, err := r.scalarType(t)
	if err != nil {
		return 0, err
	}
	skip, length, _, err := symbols.BitfieldSpan(t, n, base.Endian)
	return skip + length, err
}
func (r *Reader) size(t symbols.TypeRef, depth int) (uint64, error) {
	if depth > 128 {
		return 0, fmt.Errorf("type nesting exceeds limit")
	}
	switch t.Kind {
	case "pointer":
		if t.Base != "" {
			base, err := r.Symbols.Type(t.Base)
			return base.Size, err
		}
		return uint64(r.Symbols.PointerSize()), nil
	case "array":
		if t.Subtype == nil {
			return 0, fmt.Errorf("array has no subtype")
		}
		s, e := r.size(*t.Subtype, depth+1)
		if e != nil {
			return 0, e
		}
		if t.Count > memory.MaxRead || s > memory.MaxRead || s*t.Count > memory.MaxRead {
			return 0, fmt.Errorf("array exceeds read limit")
		}
		return s * t.Count, nil
	case "bitfield":
		if t.Underlying() == nil {
			return 0, fmt.Errorf("bitfield has no base")
		}
		return r.size(*t.Underlying(), depth+1)
	default:
		b, e := r.Symbols.Type(t.Name)
		return b.Size, e
	}
}
func (r *Reader) Uint(ctx context.Context, base uint64, typ, path string) (uint64, error) {
	f, e := r.Field(typ, path)
	if e != nil {
		return 0, e
	}
	a, e := memory.Add(base, f.Offset)
	if e != nil {
		return 0, e
	}
	return r.Scalar(ctx, a, f.Type)
}
func (r *Reader) Scalar(ctx context.Context, a uint64, t symbols.TypeRef) (uint64, error) {
	if t.Kind != "base" && t.Kind != "enum" && t.Kind != "pointer" && t.Kind != "bitfield" {
		return 0, fmt.Errorf("%s is not a scalar type", t.Kind)
	}
	n, e := r.Size(t)
	if e != nil {
		return 0, e
	}
	if n < 1 || n > 8 {
		return 0, fmt.Errorf("non-scalar width %d", n)
	}
	var order binary.ByteOrder = binary.LittleEndian
	underlying, err := r.scalarType(t)
	if err != nil {
		return 0, err
	}
	if underlying.Endian == "big" {
		order = binary.BigEndian
	}
	var shift uint64
	if t.Kind == "bitfield" {
		skip, length, bitShift, err := symbols.BitfieldSpan(t, n, underlying.Endian)
		if err != nil {
			return 0, err
		}
		a, err = memory.Add(a, skip)
		if err != nil {
			return 0, err
		}
		n, shift = length, bitShift
	}
	b, e := memory.Read(ctx, r.Layer, a, int(n))
	if e != nil {
		return 0, e
	}
	var u uint64
	if order == binary.BigEndian {
		for _, v := range b {
			u = u<<8 | uint64(v)
		}
	} else {
		for i, v := range b {
			u |= uint64(v) << (8 * i)
		}
	}
	if t.Kind == "bitfield" {
		u >>= shift
		if t.BitLength < 64 {
			u &= (uint64(1) << t.BitLength) - 1
		}
	}
	return u, nil
}
func (r *Reader) scalarType(t symbols.TypeRef) (symbols.Type, error) {
	for depth := 0; depth < 64; depth++ {
		if t.Kind == "pointer" {
			if t.Base != "" {
				return r.Symbols.Type(t.Base)
			}
			return r.Symbols.Type("pointer")
		}
		if t.Kind != "bitfield" {
			return r.Symbols.Type(t.Name)
		}
		if t.Underlying() == nil {
			return symbols.Type{}, fmt.Errorf("bitfield has no base")
		}
		t = *t.Underlying()
	}
	return symbols.Type{}, fmt.Errorf("scalar type recursion exceeds limit")
}
func (r *Reader) ScalarType(t symbols.TypeRef) (symbols.Type, error) { return r.scalarType(t) }
func (r *Reader) Int(ctx context.Context, base uint64, typ, path string) (int64, error) {
	f, err := r.Field(typ, path)
	if err != nil {
		return 0, err
	}
	a, err := memory.Add(base, f.Offset)
	if err != nil {
		return 0, err
	}
	u, err := r.Scalar(ctx, a, f.Type)
	if err != nil {
		return 0, err
	}
	bt, err := r.scalarType(f.Type)
	if err != nil {
		return 0, err
	}
	if bt.SignedUnknown {
		return 0, fmt.Errorf("enum signedness is not specified by its symbol table")
	}
	width, err := r.Size(f.Type)
	if err != nil {
		return 0, err
	}
	bits := width * 8
	if f.Type.Kind == "bitfield" {
		bits = f.Type.BitLength
	}
	if bt.Signed && bits < 64 && u&(uint64(1)<<(bits-1)) != 0 {
		u |= ^uint64(0) << bits
	}
	if !bt.Signed && u > math.MaxInt64 {
		return 0, fmt.Errorf("unsigned value does not fit int64")
	}
	return int64(u), nil
}
func (r *Reader) Enum(ctx context.Context, base uint64, typ, path string) (uint64, []string, error) {
	f, err := r.Field(typ, path)
	if err != nil {
		return 0, nil, err
	}
	ref := f.Type
	if ref.Kind == "bitfield" && ref.Underlying() != nil {
		ref = *ref.Underlying()
	}
	if ref.Kind != "enum" {
		return 0, nil, fmt.Errorf("field is not an enumeration")
	}
	en, err := r.Symbols.Enumeration(ref.Name)
	if err != nil {
		return 0, nil, err
	}
	u, err := r.Uint(ctx, base, typ, path)
	if err != nil {
		return 0, nil, err
	}
	lookup := u
	if f.Type.Kind == "bitfield" {
		base, err := r.scalarType(f.Type)
		if err != nil {
			return 0, nil, err
		}
		bits := f.Type.BitLength
		if base.Signed && bits < 64 && u&(uint64(1)<<(bits-1)) != 0 {
			lookup |= ^uint64(0) << bits
		}
	}
	return u, en.Names(lookup), nil
}
func (r *Reader) String(ctx context.Context, base uint64, typ, path string, maxBytes int) (string, error) {
	if maxBytes < 0 || maxBytes > memory.MaxRead {
		return "", fmt.Errorf("invalid string bound")
	}
	f, e := r.Field(typ, path)
	if e != nil {
		return "", e
	}
	if f.Type.Kind != "array" || f.Type.Subtype == nil {
		return "", fmt.Errorf("string field is not a byte array")
	}
	element, err := r.Size(*f.Type.Subtype)
	if err != nil {
		return "", err
	}
	if element != 1 {
		return "", fmt.Errorf("string field has non-byte elements")
	}
	n, e := r.Size(f.Type)
	if e != nil {
		return "", e
	}
	if n > uint64(maxBytes) {
		return "", fmt.Errorf("string exceeds %d bytes", maxBytes)
	}
	a, e := memory.Add(base, f.Offset)
	if e != nil {
		return "", e
	}
	b, e := memory.Read(ctx, r.Layer, a, int(n))
	if e != nil {
		return "", e
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b), nil
}

// WalkList follows an intrusive doubly-linked list and checks both directions.
// The list head is a sentinel; it is never returned as an object.
func (r *Reader) WalkList(ctx context.Context, head, offset uint64, maxNodes int, emit func(uint64) error) error {
	if maxNodes <= 0 || maxNodes > 1000000 {
		return fmt.Errorf("invalid list limit")
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	next, e := r.Scalar(ctx, head, ptr)
	if e != nil {
		return e
	}
	prev := head
	seen := make(map[uint64]bool)
	for next != head {
		if e := ctx.Err(); e != nil {
			return e
		}
		if next == 0 || next < offset {
			return fmt.Errorf("invalid linked-list pointer %#x", next)
		}
		if seen[next] {
			return fmt.Errorf("cycle in linked list at %#x", next)
		}
		if len(seen) >= maxNodes {
			return fmt.Errorf("linked list exceeded %d nodes", maxNodes)
		}
		seen[next] = true
		backAddr, e := memory.Add(next, uint64(r.Symbols.PointerSize()))
		if e != nil {
			return e
		}
		back, e := r.Scalar(ctx, backAddr, ptr)
		if e != nil {
			return e
		}
		if back != prev {
			return fmt.Errorf("inconsistent back link at %#x: have %#x want %#x", next, back, prev)
		}
		if e := emit(next - offset); e != nil {
			return e
		}
		prev = next
		next, e = r.Scalar(ctx, next, ptr)
		if e != nil {
			return e
		}
	}
	tailAddress, e := memory.Add(head, uint64(r.Symbols.PointerSize()))
	if e != nil {
		return e
	}
	tail, e := r.Scalar(ctx, tailAddress, ptr)
	if e != nil {
		return e
	}
	if tail != prev {
		return fmt.Errorf("inconsistent list tail")
	}
	return nil
}
