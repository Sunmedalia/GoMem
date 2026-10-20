package symbols

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
)

type cvMember struct {
	name      string
	typ       uint32
	offset    uint64
	anonymous bool
	constant  *json.Number
}

func (b *codeView) fields(id uint32, depth int, seen map[uint32]bool, emit func(cvMember) error) error {
	if id == 0 {
		return nil
	}
	if depth > 128 || seen[id] {
		return fmt.Errorf("CodeView field-list cycle/depth limit")
	}
	if id < b.first || uint64(id-b.first) >= uint64(len(b.records)) || b.records[id-b.first].leaf != 0x1203 {
		return fmt.Errorf("invalid CodeView field-list index %#x", id)
	}
	seen[id] = true
	defer delete(seen, id)
	c := cvCursor{data: b.records[id-b.first].data}
	for c.pos < len(c.data) {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		if c.err != nil {
			return c.err
		}
		leaf := c.u16()
		m := cvMember{}
		storage := false
		switch leaf {
		case 0x150d, 0x1405: // data member
			c.u16()
			m.typ = c.u32()
			m.offset = c.unsigned()
			m.name = c.name(leaf < 0x1500)
			storage = true
		case 0x1502, 0x0403: // enumerator
			c.u16()
			value := c.number()
			m.constant = &value
			m.name = c.name(leaf < 0x1500)
			storage = true
		case 0x1404: // continuation
			c.u16()
			next := c.u32()
			if c.err == nil {
				if err := b.fields(next, depth+1, seen, emit); err != nil {
					return err
				}
			}
		case 0x1400, 0x151a: // fixed base class
			c.u16()
			m.typ = c.u32()
			m.offset = c.unsigned()
			m.name = fmt.Sprintf("__base_%x_%x", id, c.pos)
			m.anonymous = true
			storage = true
		case 0x1401, 0x1402:
			return fmt.Errorf("virtual base class requires dynamic object layout")
		case 0x1409: // vtable pointer
			c.u16()
			m.typ = c.u32()
			m.name = "__vfptr"
			storage = true
		case 0x150e, 0x1406: // static member has no embedded storage
			c.u16()
			c.u32()
			c.name(leaf < 0x1500)
		case 0x1510, 0x1408: // nested type declaration
			c.u16()
			c.u32()
			c.name(leaf < 0x1500)
		case 0x150f, 0x1407: // overload set
			c.u16()
			c.u32()
			c.name(leaf < 0x1500)
		case 0x1511, 0x140b: // method
			attributes := c.u16()
			c.u32()
			kind := attributes >> 2 & 7
			if kind == 4 || kind == 6 {
				c.u32()
			}
			c.name(leaf < 0x1500)
		default:
			return fmt.Errorf("unsupported CodeView field leaf %#x at %#x+%#x", leaf, id, c.pos-2)
		}
		if c.err != nil {
			return c.err
		}
		if storage {
			if err := emit(m); err != nil {
				return err
			}
		}
		c.padding()
	}
	return c.err
}

func (b *codeView) primitive(id uint32) (TypeRef, error) {
	// Primitive CodeView indices encode kind in the low byte and an optional
	// pointer representation in the next byte. Sizes follow the Windows ABI.
	ref := TypeRef{Kind: "base"}
	kind := id & 0xff
	t := Type{Kind: "int", Endian: "little"}
	switch kind {
	case 0, 3:
		ref.Name = "void"
		t.Kind = "void"
		t.Signed = true // conventional ISF metadata; void has no numeric value
	case 8:
		ref.Name = "HRESULT"
		t.Size = 4
		t.Signed = true
	case 0x10, 0x70:
		ref.Name = "char"
		t.Kind = "char"
		t.Size = 1
		t.Signed = true
	case 0x20:
		ref.Name = "unsigned char"
		t.Kind = "char"
		t.Size = 1
	case 0x68:
		ref.Name = "int8"
		t.Size = 1
		t.Signed = true
	case 0x69:
		ref.Name = "uint8"
		t.Size = 1
	case 0x11, 0x72:
		ref.Name = "short"
		t.Size = 2
		t.Signed = true
	case 0x21, 0x73:
		ref.Name = "unsigned short"
		t.Size = 2
	case 0x12:
		ref.Name = "long"
		t.Size = 4
		t.Signed = true
	case 0x22:
		ref.Name = "unsigned long"
		t.Size = 4
	case 0x74:
		ref.Name = "int"
		t.Size = 4
		t.Signed = true
	case 0x75:
		ref.Name = "unsigned int"
		t.Size = 4
	case 0x13, 0x76:
		ref.Name = "long long"
		t.Size = 8
		t.Signed = true
	case 0x23, 0x77:
		ref.Name = "unsigned long long"
		t.Size = 8
	case 0x14, 0x78:
		ref.Name = "int128"
		t.Size = 16
		t.Signed = true
	case 0x24, 0x79:
		ref.Name = "uint128"
		t.Size = 16
	case 0x71, 0x7a:
		ref.Name = "wchar"
		t.Size = 2
	case 0x7b:
		ref.Name = "char32"
		t.Size = 4
	case 0x7c:
		ref.Name = "char8"
		t.Size = 1
	case 0x30, 0x31, 0x32, 0x33, 0x34:
		ref.Name = fmt.Sprintf("bool%d", 8<<(kind-0x30))
		t.Kind = "bool"
		t.Size = uint64(1) << (kind - 0x30)
	case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46:
		widths := map[uint32]uint64{0x40: 4, 0x41: 8, 0x42: 10, 0x43: 16, 0x44: 6, 0x45: 4, 0x46: 2}
		ref.Name = fmt.Sprintf("float_%x", kind)
		t.Kind = "float"
		t.Size = widths[kind]
		t.Signed = true
	default:
		return ref, fmt.Errorf("unsupported CodeView primitive %#x", id)
	}
	b.table.Bases[ref.Name] = t
	mode := id & 0xf00
	if mode != 0 {
		width := map[uint32]uint64{0x100: 2, 0x400: 4, 0x600: 8}[mode]
		if width == 0 {
			return ref, fmt.Errorf("unsupported CodeView primitive pointer %#x", id)
		}
		sub := ref
		ref = TypeRef{Kind: "pointer", Subtype: &sub}
		if width != uint64(b.table.PointerSize()) {
			ref.Base = fmt.Sprintf("pointer%d", width*8)
			b.table.Bases[ref.Base] = Type{Kind: "int", Size: width, Endian: "little"}
		}
	}
	return ref, nil
}
func (b *codeView) validateLayouts() error {
	for name, t := range b.table.Types {
		for member, f := range t.Fields {
			size, err := b.table.refSize(f.Type, 0)
			if err != nil {
				return err
			}
			if f.Type.Kind == "bitfield" {
				skip, n, _, e := BitfieldSpan(f.Type, size, "little")
				if e != nil {
					return e
				}
				size = skip + n
			}
			if f.Offset > t.Size || size > t.Size-f.Offset {
				return fmt.Errorf("PDB member %s.%s exceeds its containing type", name, member)
			}
		}
	}
	return nil
}
func (b *codeView) alias(name string, ref TypeRef) error {
	switch ref.Kind {
	case "base":
		value := b.table.Bases[ref.Name]
		if old, ok := b.table.Bases[name]; ok && !reflect.DeepEqual(old, value) {
			return fmt.Errorf("conflicting PDB base alias %s", name)
		}
		b.table.Bases[name] = value
	case "enum":
		value := b.table.Enums[ref.Name]
		if old, ok := b.table.Enums[name]; ok && !reflect.DeepEqual(old, value) {
			if strings.HasPrefix(ref.Name, name+"@0x") {
				return nil
			}
			return fmt.Errorf("conflicting PDB enum alias %s", name)
		}
		b.table.Enums[name] = value
	case "struct", "union":
		t := b.table.Types[ref.Name]
		if old, ok := b.table.Types[name]; ok && !reflect.DeepEqual(old, t) {
			if strings.HasPrefix(ref.Name, name+"@0x") {
				return nil
			}
			return fmt.Errorf("conflicting PDB type alias %s", name)
		}
		b.table.Types[name] = t
	}
	return nil
}

func signedEnum(value json.Number, base Type) json.Number {
	if !base.Signed || base.Size == 0 || base.Size > 16 {
		return value
	}
	n, ok := new(big.Int).SetString(string(value), 10)
	if !ok || n.Sign() < 0 {
		return value
	}
	bits := uint(base.Size * 8)
	if n.BitLen() == int(bits) {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), bits))
		return json.Number(n.String())
	}
	return value
}
