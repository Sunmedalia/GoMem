package symbols

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

type cvCursor struct {
	data []byte
	pos  int
	err  error
}

func (c *cvCursor) take(n int) []byte {
	if c.err != nil {
		return make([]byte, n)
	}
	if n > len(c.data)-c.pos {
		c.err = io.ErrUnexpectedEOF
		return make([]byte, n)
	}
	b := c.data[c.pos : c.pos+n]
	c.pos += n
	return b
}
func (c *cvCursor) u8() uint8   { return c.take(1)[0] }
func (c *cvCursor) u16() uint16 { return binary.LittleEndian.Uint16(c.take(2)) }
func (c *cvCursor) u32() uint32 { return binary.LittleEndian.Uint32(c.take(4)) }
func (c *cvCursor) name(pascal bool) string {
	if pascal {
		name := string(c.take(int(c.u8())))
		if !utf8.ValidString(name) {
			c.err = fmt.Errorf("CodeView name is not UTF-8")
		}
		return name
	}
	if c.err != nil {
		return ""
	}
	end := bytes.IndexByte(c.data[c.pos:], 0)
	if end < 0 {
		c.err = fmt.Errorf("unterminated CodeView name")
		return ""
	}
	name := string(c.data[c.pos : c.pos+end])
	if !utf8.ValidString(name) {
		c.err = fmt.Errorf("CodeView name is not UTF-8")
	}
	c.pos += end + 1
	return name
}
func (c *cvCursor) number() json.Number {
	leaf := c.u16()
	if leaf < 0x8000 {
		return json.Number(strconv.FormatUint(uint64(leaf), 10))
	}
	width, signed := 0, false
	switch leaf {
	case 0x8000:
		width, signed = 1, true
	case 0x8001:
		width, signed = 2, true
	case 0x8002:
		width = 2
	case 0x8003:
		width, signed = 4, true
	case 0x8004:
		width = 4
	case 0x8009:
		width, signed = 8, true
	case 0x800a:
		width = 8
	case 0x8017:
		width, signed = 16, true
	case 0x8018:
		width = 16
	default:
		c.err = fmt.Errorf("unsupported CodeView numeric leaf %#x", leaf)
		return "0"
	}
	raw := c.take(width)
	bigEndian := make([]byte, width)
	for i := range raw {
		bigEndian[width-i-1] = raw[i]
	}
	n := new(big.Int).SetBytes(bigEndian)
	if signed && bigEndian[0]&0x80 != 0 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(width*8)))
	}
	return json.Number(n.String())
}
func (c *cvCursor) unsigned() uint64 {
	n := c.number()
	v, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil {
		c.err = fmt.Errorf("CodeView offset/size is not uint64: %s", n)
	}
	return v
}
func (c *cvCursor) padding() {
	if c.err != nil || c.pos == len(c.data) {
		return
	}
	if c.data[c.pos] < 0xf0 {
		return
	}
	n := int(c.u8() & 15)
	if n == 0 {
		c.err = fmt.Errorf("invalid CodeView zero-length padding")
		return
	}
	for j := n - 1; j > 0; j-- {
		if c.u8() != uint8(0xf0+j) {
			c.err = fmt.Errorf("invalid CodeView padding")
		}
	}
}

type cvRecord struct {
	leaf uint16
	data []byte
}
type cvNamed struct {
	name, kind         string
	size               uint64
	fields, underlying uint32
	forward            bool
}
type codeView struct {
	ctx          context.Context
	table        *ISF
	first        uint32
	records      []cvRecord
	named        map[uint32]cvNamed
	definitions  map[string]uint32
	refs         map[uint32]TypeRef
	resolving    map[uint32]bool
	max, entries int
	variants     int
	absolute     map[string]string
	removed      map[string]string
	collisions   int
}

func newCodeView(ctx context.Context, data []byte, table *ISF, max int) (*codeView, error) {
	if len(data) < 56 {
		return nil, fmt.Errorf("truncated TPI header")
	}
	c := cvCursor{data: data}
	version, header, first, last, length := c.u32(), c.u32(), c.u32(), c.u32(), c.u32()
	if version != 20040203 || header < 56 || uint64(header)+uint64(length) != uint64(len(data)) || first < 0x1000 || last < first || uint64(last-first) > uint64(max) {
		return nil, fmt.Errorf("unsupported or inconsistent TPI header")
	}
	b := &codeView{ctx: ctx, table: table, first: first, max: max, named: map[uint32]cvNamed{}, definitions: map[string]uint32{}, refs: map[uint32]TypeRef{}, resolving: map[uint32]bool{}}
	for offset := uint64(header); offset < uint64(len(data)); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(b.records) >= max || offset+4 > uint64(len(data)) {
			return nil, fmt.Errorf("TPI record count/truncation")
		}
		n := uint64(binary.LittleEndian.Uint16(data[offset:]))
		if n < 2 || offset+n+2 > uint64(len(data)) {
			return nil, fmt.Errorf("invalid TPI record length")
		}
		b.records = append(b.records, cvRecord{binary.LittleEndian.Uint16(data[offset+2:]), data[offset+4 : offset+2+n]})
		offset += n + 2
	}
	if uint64(len(b.records)) != uint64(last-first) {
		return nil, fmt.Errorf("TPI index range does not match records")
	}
	b.entries = len(b.records)
	for n, r := range b.records {
		id := first + uint32(n)
		c := cvCursor{data: r.data}
		var t cvNamed
		switch r.leaf {
		case 0x1504, 0x1505, 0x1519, 0x1004, 0x1005:
			c.u16()
			props := c.u16()
			t.fields = c.u32()
			c.u32()
			c.u32()
			t.size = c.unsigned()
			t.forward = props&0x80 != 0
			t.kind = "struct"
		case 0x1608, 0x1609:
			props := c.u32()
			t.fields = c.u32()
			c.u32()
			c.u32()
			c.u16()
			t.size = c.unsigned()
			t.forward = props&0x80 != 0
			t.kind = "struct"
		case 0x1506, 0x1006:
			c.u16()
			props := c.u16()
			t.fields = c.u32()
			t.size = c.unsigned()
			t.forward = props&0x80 != 0
			t.kind = "union"
		case 0x1507, 0x1007:
			c.u16()
			props := c.u16()
			t.underlying = c.u32()
			t.fields = c.u32()
			t.forward = props&0x80 != 0
			t.kind = "enum"
		default:
			continue
		}
		t.name = c.name(r.leaf < 0x1500)
		if c.err != nil {
			return nil, fmt.Errorf("TPI %#x: %w", id, c.err)
		}
		if t.name == "" || strings.Contains(t.name, "unnamed") || strings.Contains(t.name, "anonymous") {
			t.name = fmt.Sprintf("__pdb_anon_%x", id)
		}
		b.named[id] = t
		if !t.forward {
			b.definitions[t.kind+":"+t.name] = id
		}
	}
	// Linked PDBs can contain different definitions with the same source name.
	// Preserve every indexed variant. The final definition retains the ordinary
	// name, matching the baseline's deterministic name-resolution policy.
	for id, t := range b.named {
		if !t.forward && b.definitions[t.kind+":"+t.name] != id {
			t.name = fmt.Sprintf("%s@0x%x", t.name, id)
			b.named[id] = t
			b.variants++
		}
	}
	return b, nil
}
func (b *codeView) convert() error {
	for n := range b.records {
		id := b.first + uint32(n)
		if _, ok := b.named[id]; ok {
			if _, err := b.ref(id, 0); err != nil {
				return fmt.Errorf("TPI %#x: %w", id, err)
			}
		}
	}
	return nil
}
func (b *codeView) ref(id uint32, depth int) (ref TypeRef, err error) {
	if err = b.ctx.Err(); err != nil {
		return ref, err
	}
	if depth > 128 {
		return ref, fmt.Errorf("CodeView type recursion limit")
	}
	if id < 0x1000 {
		return b.primitive(id)
	}
	if ref, ok := b.refs[id]; ok {
		return ref, nil
	}
	if id < b.first || uint64(id-b.first) >= uint64(len(b.records)) {
		return ref, fmt.Errorf("invalid CodeView type index %#x", id)
	}
	if b.resolving[id] {
		return ref, fmt.Errorf("CodeView non-structure type cycle %#x", id)
	}
	b.resolving[id] = true
	defer delete(b.resolving, id)
	r := b.records[id-b.first]
	c := cvCursor{data: r.data}
	if named, ok := b.named[id]; ok {
		if named.forward {
			if target, ok := b.definitions[named.kind+":"+named.name]; ok {
				b.refs[id] = TypeRef{Kind: named.kind, Name: named.name}
				return b.ref(target, depth+1)
			}
			// An incomplete declaration may be used behind a pointer. It has
			// no readable fields; sized value use is rejected by layout checks.
		}
		ref = TypeRef{Kind: named.kind, Name: named.name}
		b.refs[id] = ref
		if named.kind == "enum" {
			base, e := b.ref(named.underlying, depth+1)
			if e != nil {
				return ref, e
			}
			if base.Kind != "base" {
				return ref, fmt.Errorf("enum base is not scalar")
			}
			constants := map[string]json.Number{}
			if err = b.fields(named.fields, depth+1, map[uint32]bool{}, func(m cvMember) error {
				if m.constant == nil {
					return fmt.Errorf("non-enumerator in enum")
				}
				constants[m.name] = signedEnum(*m.constant, b.table.Bases[base.Name])
				return nil
			}); err != nil {
				return ref, err
			}
			en := Enumeration{Base: base.Name, Size: b.table.Bases[base.Name].Size, Constants: constants}
			if old, exists := b.table.Enums[named.name]; exists && !reflect.DeepEqual(old, en) {
				return ref, fmt.Errorf("conflicting enum %s", named.name)
			}
			b.table.Enums[named.name] = en
		} else {
			t := Type{Kind: named.kind, Size: named.size, Fields: map[string]Field{}}
			prior, exists := b.table.Types[named.name]
			if !exists || prior.Size == 0 && len(prior.Fields) == 0 {
				b.table.Types[named.name] = t // publish before following recursive pointers
			}
			if err = b.fields(named.fields, depth+1, map[uint32]bool{}, func(m cvMember) error {
				if m.constant != nil {
					return fmt.Errorf("enumerator in structure")
				}
				typ, e := b.ref(m.typ, depth+1)
				if e != nil {
					return e
				}
				name := m.name
				if name == "" {
					name = fmt.Sprintf("__anonymous_%d", len(t.Fields))
				}
				if _, ok := t.Fields[name]; ok {
					return fmt.Errorf("duplicate member %s.%s", named.name, name)
				}
				t.Fields[name] = Field{Offset: m.offset, Type: typ, Anonymous: m.name == "" || m.anonymous}
				return nil
			}); err != nil {
				return ref, fmt.Errorf("%s: %w", named.name, err)
			}
			if exists && prior.Size != 0 && !reflect.DeepEqual(prior, t) {
				if named.forward {
					return ref, nil
				}
				return ref, fmt.Errorf("conflicting CodeView type definitions for %s", named.name)
			}
			b.table.Types[named.name] = t
		}
		return ref, nil
	}
	switch r.leaf {
	case 0x1001:
		ref, err = b.ref(c.u32(), depth+1)
	case 0x1002:
		target, attrs := c.u32(), c.u32()
		mode := attrs >> 5 & 7
		if mode == 2 || mode == 3 {
			return ref, fmt.Errorf("CodeView member pointers have no supported scalar layout")
		}
		width := uint64(attrs >> 13 & 63)
		if width == 0 {
			switch attrs & 31 {
			case 0:
				width = 2
			case 10, 11:
				width = 4
			case 12:
				width = 8
			default:
				return ref, fmt.Errorf("unsupported pointer kind")
			}
		}
		var sub TypeRef
		if named, ok := b.named[target]; ok {
			// A pointer does not require the target's fields to be built yet.
			// Materializing them here would recurse through other pointer
			// records before this pointer itself can be cached.
			sub = TypeRef{Kind: named.kind, Name: named.name}
		} else {
			var e error
			sub, e = b.ref(target, depth+1)
			if e != nil {
				return ref, e
			}
		}
		ref = TypeRef{Kind: "pointer", Subtype: &sub}
		if width != 2 && width != 4 && width != 8 && width != 16 {
			return ref, fmt.Errorf("invalid CodeView pointer width %d", width)
		}
		if width != uint64(b.table.PointerSize()) {
			ref.Base = fmt.Sprintf("pointer%d", width*8)
			b.table.Bases[ref.Base] = Type{Kind: "int", Size: width, Endian: "little"}
		}
	case 0x1503, 0x1003:
		target := c.u32()
		c.u32()
		size := c.unsigned()
		sub, e := b.ref(target, depth+1)
		if e != nil {
			return ref, e
		}
		width, e := b.table.refSize(sub, 0)
		if e != nil {
			return ref, e
		}
		count := uint64(0)
		if size > 0 {
			if width == 0 || size%width != 0 {
				return ref, fmt.Errorf("array size is not a multiple of its element")
			}
			count = size / width
		}
		ref = TypeRef{Kind: "array", Count: count, Subtype: &sub}
	case 0x1205:
		sub, e := b.ref(c.u32(), depth+1)
		if e != nil {
			return ref, e
		}
		ref = TypeRef{Kind: "bitfield", BitType: &sub, BitLength: uint64(c.u8()), BitPosition: uint64(c.u8())}
	case 0x1008, 0x1009:
		if r.leaf == 0x1008 {
			c.take(12)
		} else {
			c.take(24)
		}
		ref = TypeRef{Kind: "function"}
	default:
		return ref, fmt.Errorf("unsupported referenced CodeView leaf %#x (index %#x)", r.leaf, id)
	}
	if c.err != nil {
		return ref, c.err
	}
	if err == nil {
		b.refs[id] = ref
	}
	return ref, err
}
