package symbols

import (
	"bufio"
	"context"
	"crypto/sha256"
	"debug/dwarf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type die struct {
	entry    *dwarf.Entry
	children []dwarf.Offset
	local    bool
}
type dwarfBuilder struct {
	ctx         context.Context
	file        *nativeFile
	table       *ISF
	dies        map[dwarf.Offset]*die
	definitions map[string]dwarf.Offset
	refs        map[dwarf.Offset]TypeRef
	resolving   map[dwarf.Offset]bool
	names       map[dwarf.Offset]string
	entries     int
}

// ConvertDWARF reads ELF or Mach-O directly. It does not execute a compiler,
// dwarf2json, Python or other external process. Resource and cancellation limits
// cover section ingestion, DIE traversal, reference resolution and source hashing.
func ConvertDWARF(ctx context.Context, path string, options DWARFOptions) (table *ISF, report Conversion, err error) {
	defer func() {
		if p := recover(); p != nil {
			table = nil
			err = fmt.Errorf("malformed debug input: %v", p)
		}
	}()
	options, err = normalizeDWARFOptions(options)
	if err != nil {
		return nil, report, err
	}
	if err = ctx.Err(); err != nil {
		return nil, report, err
	}
	file, err := openNative(ctx, path, options)
	if err != nil {
		return nil, report, err
	}
	defer file.file.Close()
	data, err := file.DWARF()
	if err != nil {
		return nil, report, fmt.Errorf("DWARF: %w", err)
	}
	endian := "little"
	if file.order.String() == "BigEndian" {
		endian = "big"
	}
	table = &ISF{Meta: map[string]json.RawMessage{"format": json.RawMessage(`"6.2.0"`), "producer": json.RawMessage(`{"name":"gomem-dwarf","version":"1"}`)}, Bases: map[string]Type{"pointer": {Kind: "int", Size: uint64(file.pointer), Endian: endian}, "void": {Kind: "void", Size: 0, Endian: endian}}, Types: map[string]Type{}, Symbols: map[string]Symbol{}, Enums: map[string]Enumeration{}}
	table.architecture = file.arch
	b := &dwarfBuilder{ctx: ctx, file: file, table: table, dies: map[dwarf.Offset]*die{}, definitions: map[string]dwarf.Offset{}, refs: map[dwarf.Offset]TypeRef{}, resolving: map[dwarf.Offset]bool{}, names: map[dwarf.Offset]string{}}
	if err = b.read(data); err != nil {
		return nil, report, err
	}
	offsets := make([]dwarf.Offset, 0, len(b.dies))
	for off := range b.dies {
		offsets = append(offsets, off)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	for _, off := range offsets {
		d := b.dies[off]
		if typeTag(d.entry.Tag) {
			if _, err = b.ref(off, 0); err != nil {
				return nil, report, fmt.Errorf("DWARF type %#x: %w", off, err)
			}
		}
	}
	// A typedef may have been resolved while its recursive target structure was
	// still being built. Materialize aliases after all definitions are complete.
	for _, off := range offsets {
		d := b.dies[off]
		if d.entry.Tag != dwarf.TagTypedef {
			continue
		}
		name, _ := d.entry.Val(dwarf.AttrName).(string)
		if name == "" {
			continue
		}
		ref, ok := b.refs[off]
		if !ok {
			continue
		}
		switch ref.Kind {
		case "struct", "union":
			if value, exists := table.Types[ref.Name]; exists {
				if err = b.userType(name, value); err != nil {
					return nil, report, err
				}
			}
		case "base":
			if value, exists := table.Bases[ref.Name]; exists {
				if err = b.base(name, value); err != nil {
					return nil, report, err
				}
			}
		case "enum":
			table.Enums[name] = table.Enums[ref.Name]
		}
	}
	pendingTypes := map[string]TypeRef{}
	for _, off := range offsets {
		d := b.dies[off]
		if d.entry.Tag != dwarf.TagVariable && d.entry.Tag != dwarf.TagSubprogram {
			continue
		}
		if d.entry.Tag == dwarf.TagVariable && d.local {
			continue
		}
		name, _ := b.attribute(off, dwarf.AttrName).(string)
		if name == "" {
			continue
		}
		if linkage, ok := b.attribute(off, dwarf.AttrLinkageName).(string); ok && linkage != "" {
			name = linkage
		}
		if d.entry.Tag == dwarf.TagVariable {
			if target, ok := b.attribute(off, dwarf.AttrType).(dwarf.Offset); ok {
				ref, e := b.ref(target, 0)
				if e != nil {
					return nil, report, e
				}
				pendingTypes[name] = ref
			}
		}
		var address uint64
		var found bool
		if d.entry.Tag == dwarf.TagSubprogram {
			address, found = unsigned(b.attribute(off, dwarf.AttrLowpc))
		} else if expr, ok := b.attribute(off, dwarf.AttrLocation).([]byte); ok && len(expr) == file.pointer+1 && expr[0] == 0x03 {
			if file.pointer == 8 {
				address = file.order.Uint64(expr[1:])
			} else {
				address = uint64(file.order.Uint32(expr[1:]))
			}
			found = true
		}
		if !found {
			continue
		}
		s := Symbol{Address: address}
		if d.entry.Tag == dwarf.TagSubprogram {
			function := TypeRef{Kind: "function"}
			s.Type = &function
		} else if target, ok := b.attribute(off, dwarf.AttrType).(dwarf.Offset); ok {
			ref, e := b.ref(target, 0)
			if e != nil {
				return nil, report, e
			}
			s.Type = &ref
		}
		table.Symbols[name] = s
	}
	for name, typ := range table.Types {
		for member, field := range typ.Fields {
			size, e := b.refSize(field.Type, 0)
			if e != nil {
				return nil, report, fmt.Errorf("%s.%s: %w", name, member, e)
			}
			if field.Offset > typ.Size || size > typ.Size-field.Offset {
				return nil, report, fmt.Errorf("field %s.%s exceeds containing type", name, member)
			}
		}
	}
	merge := func(n nativeSymbol) error {
		s := table.Symbols[n.name]
		s.Address = n.address
		if n.function {
			function := TypeRef{Kind: "function"}
			s.Type = &function
		}
		table.Symbols[n.name] = s
		return nil
	}
	if err = file.eachSymbol(merge); err != nil {
		return nil, report, err
	}
	primary, err := file.source("dwarf")
	if err != nil {
		return nil, report, err
	}
	report = Conversion{Format: file.platform, Architecture: file.arch, BuildID: file.buildID, Entries: b.entries, Sources: []SymbolSource{primary}}
	symbolSource := file
	if options.SymbolsFrom != "" {
		extra, e := openNative(ctx, options.SymbolsFrom, options)
		if e != nil {
			return nil, report, e
		}
		defer extra.file.Close()
		if extra.platform != file.platform || extra.arch != file.arch || extra.order != file.order || extra.pointer != file.pointer {
			return nil, report, fmt.Errorf("separate symbol file architecture disagrees with DWARF file")
		}
		if extra.buildID != "" && file.buildID != "" && extra.buildID != file.buildID {
			return nil, report, fmt.Errorf("separate symbol file build identity mismatch")
		}
		if extra.buildID == "" || file.buildID == "" {
			report.Warnings = append(report.Warnings, "separate symbol file has no comparable build identity")
		}
		if err = extra.eachSymbol(merge); err != nil {
			return nil, report, err
		}
		source, e := extra.source("symtab")
		if e != nil {
			return nil, report, e
		}
		report.Sources = append(report.Sources, source)
		symbolSource = extra
	}
	if options.SystemMap != "" {
		if file.platform != "linux" {
			return nil, report, fmt.Errorf("System.map applies only to ELF/Linux")
		}
		source, e := mergeSystemMap(ctx, options.SystemMap, table, options.MaxEntries)
		if e != nil {
			return nil, report, e
		}
		report.Sources = append(report.Sources, source)
	}
	for name, typ := range pendingTypes {
		if symbol, ok := table.Symbols[name]; ok && symbol.Type == nil {
			copy := typ
			symbol.Type = &copy
			table.Symbols[name] = symbol
		}
	}
	banner := "linux_banner"
	if file.platform == "mac" {
		banner = "version"
	}
	if s, ok := table.Symbols[banner]; ok {
		bytes, e := symbolSource.banner(s.Address)
		if e != nil {
			report.Warnings = append(report.Warnings, "kernel identity unavailable: "+e.Error())
		} else {
			s.ConstantData = base64.StdEncoding.EncodeToString(bytes)
			table.Symbols[banner] = s
		}
	} else {
		report.Warnings = append(report.Warnings, "no kernel banner symbol; analysis requires an independently verifiable kernel identity")
	}
	types := []SymbolSource{primary}
	symbols := append([]SymbolSource{{Name: primary.Name, SHA256: primary.SHA256, Kind: "symtab"}}, report.Sources[1:]...)
	metadata, e := json.Marshal(map[string]any{"types": nixSources(types), "symbols": nixSources(symbols)})
	if e != nil {
		return nil, report, e
	}
	table.Meta[file.platform] = metadata
	if err = table.finalize(); err != nil {
		return nil, report, err
	}
	report.Types = len(table.Types)
	report.Symbols = len(table.Symbols)
	report.Enums = len(table.Enums)
	return table, report, nil
}
func nixSources(sources []SymbolSource) []map[string]string {
	out := make([]map[string]string, 0, len(sources))
	for _, s := range sources {
		out = append(out, map[string]string{"kind": s.Kind, "name": s.Name, "hash_type": "sha256", "hash_value": s.SHA256})
	}
	return out
}
func typeTag(tag dwarf.Tag) bool {
	switch tag {
	case dwarf.TagArrayType, dwarf.TagClassType, dwarf.TagEnumerationType, dwarf.TagPointerType, dwarf.TagReferenceType, dwarf.TagStructType, dwarf.TagSubroutineType, dwarf.TagTypedef, dwarf.TagUnionType, dwarf.TagBaseType, dwarf.TagConstType, dwarf.TagVolatileType, dwarf.TagRestrictType, dwarf.TagUnspecifiedType, dwarf.Tag(0x42), dwarf.Tag(0x47):
		return true
	}
	return false
}
func (b *dwarfBuilder) read(data *dwarf.Data) error {
	r := data.Reader()
	type frame struct {
		offset dwarf.Offset
		stored bool
		local  bool
	}
	var stack []frame
	for {
		if err := b.ctx.Err(); err != nil {
			return err
		}
		entry, err := r.Next()
		if err != nil {
			return err
		}
		if entry == nil {
			break
		}
		b.entries++
		if b.entries > b.file.options.MaxEntries {
			return fmt.Errorf("DWARF entry count exceeds limit")
		}
		if entry.Tag == 0 {
			if len(stack) == 0 {
				return fmt.Errorf("unbalanced DWARF child terminator")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if entry.Tag == dwarf.TagCompileUnit && r.AddressSize() != b.file.pointer {
			return fmt.Errorf("DWARF address size disagrees with object format")
		}
		stored := typeTag(entry.Tag) || entry.Tag == dwarf.TagMember || entry.Tag == dwarf.TagSubrangeType || entry.Tag == dwarf.TagEnumerator || entry.Tag == dwarf.TagVariable || entry.Tag == dwarf.TagSubprogram
		local := len(stack) > 0 && stack[len(stack)-1].local
		if stored {
			b.dies[entry.Offset] = &die{entry: entry, local: local}
			if len(stack) > 0 && stack[len(stack)-1].stored {
				parent := b.dies[stack[len(stack)-1].offset]
				parent.children = append(parent.children, entry.Offset)
			}
			if typeTag(entry.Tag) {
				name, _ := entry.Val(dwarf.AttrName).(string)
				decl, _ := entry.Val(dwarf.AttrDeclaration).(bool)
				if name != "" && !decl {
					key := fmt.Sprintf("%d:%s", entry.Tag, name)
					if _, ok := b.definitions[key]; !ok {
						b.definitions[key] = entry.Offset
					}
				}
			}
		}
		if entry.Children {
			if len(stack) >= 256 {
				return fmt.Errorf("DWARF scope nesting exceeds limit")
			}
			stack = append(stack, frame{entry.Offset, stored, local || entry.Tag == dwarf.TagSubprogram || entry.Tag == dwarf.TagLexDwarfBlock})
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("unterminated DWARF children")
	}
	return nil
}
func (b *dwarfBuilder) attribute(off dwarf.Offset, attr dwarf.Attr) any {
	seen := map[dwarf.Offset]bool{}
	for depth := 0; depth < 32; depth++ {
		d := b.dies[off]
		if d == nil || seen[off] {
			return nil
		}
		seen[off] = true
		if v := d.entry.Val(attr); v != nil {
			return v
		}
		next, ok := d.entry.Val(dwarf.AttrSpecification).(dwarf.Offset)
		if !ok {
			next, ok = d.entry.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset)
		}
		if !ok {
			return nil
		}
		off = next
	}
	return nil
}
func (b *dwarfBuilder) name(off dwarf.Offset, depth int) (string, error) {
	if name, ok := b.names[off]; ok {
		return name, nil
	}
	d := b.dies[off]
	if d == nil {
		return "", fmt.Errorf("missing type reference %#x", off)
	}
	name, _ := d.entry.Val(dwarf.AttrName).(string)
	if name == "" {
		shape, err := b.shape(off, map[dwarf.Offset]bool{}, depth)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(shape))
		name = "__anon_" + hex.EncodeToString(sum[:12])
	}
	b.names[off] = name
	return name, nil
}
func (b *dwarfBuilder) shape(off dwarf.Offset, seen map[dwarf.Offset]bool, depth int) (string, error) {
	if depth > 128 {
		return "", fmt.Errorf("anonymous type nesting exceeds limit")
	}
	if off == 0 {
		return "void", nil
	}
	d := b.dies[off]
	if d == nil {
		return "", fmt.Errorf("missing type reference %#x", off)
	}
	if name, ok := d.entry.Val(dwarf.AttrName).(string); ok && name != "" {
		return fmt.Sprintf("%d:%s", d.entry.Tag, name), nil
	}
	if seen[off] {
		return fmt.Sprintf("recursive:%d", d.entry.Tag), nil
	}
	seen[off] = true
	defer delete(seen, off)
	var s strings.Builder
	fmt.Fprintf(&s, "%d:%v:%v", d.entry.Tag, d.entry.Val(dwarf.AttrByteSize), d.entry.Val(dwarf.AttrEncoding))
	if target, ok := d.entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
		child, e := b.shape(target, seen, depth+1)
		if e != nil {
			return "", e
		}
		s.WriteString(child)
	}
	for _, child := range d.children {
		c := b.dies[child]
		fmt.Fprintf(&s, "/%d:%v:%v:%v:%v:%v:%v:%v:%v", c.entry.Tag, c.entry.Val(dwarf.AttrName), c.entry.Val(dwarf.AttrDataMemberLoc), c.entry.Val(dwarf.AttrDataBitOffset), c.entry.Val(dwarf.AttrBitSize), c.entry.Val(dwarf.AttrConstValue), c.entry.Val(dwarf.AttrCount), c.entry.Val(dwarf.AttrUpperBound), c.entry.Val(dwarf.AttrLowerBound))
		if target, ok := c.entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
			shape, e := b.shape(target, seen, depth+1)
			if e != nil {
				return "", e
			}
			s.WriteString(shape)
		}
	}
	return s.String(), nil
}
func (b *dwarfBuilder) ref(off dwarf.Offset, depth int) (ref TypeRef, err error) {
	if err = b.ctx.Err(); err != nil {
		return ref, err
	}
	if depth > 128 {
		return ref, fmt.Errorf("type reference nesting exceeds limit")
	}
	if off == 0 {
		return TypeRef{Kind: "base", Name: "void"}, nil
	}
	if ref, ok := b.refs[off]; ok {
		return ref, nil
	}
	d := b.dies[off]
	if d == nil {
		return ref, fmt.Errorf("missing type DIE %#x", off)
	}
	name, e := b.name(off, depth)
	if e != nil {
		return ref, e
	}
	decl, _ := d.entry.Val(dwarf.AttrDeclaration).(bool)
	if decl {
		if target, ok := b.definitions[fmt.Sprintf("%d:%s", d.entry.Tag, name)]; ok && target != off {
			return b.ref(target, depth+1)
		}
	}
	if b.resolving[off] {
		return ref, fmt.Errorf("cyclic non-struct type reference at %#x", off)
	}
	if d.entry.Tag == dwarf.TagTypedef {
		target, _ := d.entry.Val(dwarf.AttrType).(dwarf.Offset)
		seen := map[dwarf.Offset]bool{}
		for i := 0; i < 128; i++ {
			child := b.dies[target]
			if child == nil || seen[target] {
				break
			}
			seen[target] = true
			tag := child.entry.Tag
			if tag == dwarf.TagStructType || tag == dwarf.TagUnionType || tag == dwarf.TagClassType {
				name, e := b.name(target, depth+1)
				if e != nil {
					return ref, e
				}
				kind := "struct"
				if tag == dwarf.TagUnionType {
					kind = "union"
				}
				b.refs[off] = TypeRef{Kind: kind, Name: name}
				break
			}
			if tag != dwarf.TagTypedef && tag != dwarf.TagConstType && tag != dwarf.TagVolatileType {
				break
			}
			target, _ = child.entry.Val(dwarf.AttrType).(dwarf.Offset)
		}
	}
	b.resolving[off] = true
	defer delete(b.resolving, off)
	target, _ := d.entry.Val(dwarf.AttrType).(dwarf.Offset)
	size, _ := unsigned(d.entry.Val(dwarf.AttrByteSize))
	endian := b.table.Bases["pointer"].Endian
	switch d.entry.Tag {
	case dwarf.TagConstType, dwarf.TagVolatileType, dwarf.TagRestrictType, dwarf.Tag(0x47):
		ref, err = b.ref(target, depth+1)
	case dwarf.TagTypedef:
		ref, err = b.ref(target, depth+1)
		if err != nil {
			return ref, err
		}
		switch ref.Kind {
		case "base":
			if v, ok := b.table.Bases[ref.Name]; ok {
				if err = b.base(name, v); err != nil {
					return ref, err
				}
			}
		case "struct", "union":
			if v, ok := b.table.Types[ref.Name]; ok {
				if err = b.userType(name, v); err != nil {
					return ref, err
				}
			}
		case "enum":
			b.table.Enums[name] = b.table.Enums[ref.Name]
		}
	case dwarf.TagBaseType:
		encoding, _ := unsigned(d.entry.Val(dwarf.AttrEncoding))
		kind, signed := "int", false
		switch encoding {
		case 2:
			kind = "bool"
		case 3, 4:
			kind = "float"
		case 5:
			signed = true
		case 6:
			kind = "char"
			signed = true
		case 8, 16:
			kind = "char"
		}
		if size == 0 {
			return ref, fmt.Errorf("zero-sized base type %s", name)
		}
		err = b.base(name, Type{Kind: kind, Size: size, Endian: endian, Signed: signed})
		ref = TypeRef{Kind: "base", Name: name}
	case dwarf.TagUnspecifiedType:
		ref = TypeRef{Kind: "base", Name: "void"}
	case dwarf.TagPointerType, dwarf.TagReferenceType, dwarf.Tag(0x42):
		if size != 0 && size != uint64(b.file.pointer) {
			return ref, fmt.Errorf("non-native pointer width")
		}
		sub, e := b.ref(target, depth+1)
		if e != nil {
			return ref, e
		}
		ref = TypeRef{Kind: "pointer", Subtype: &sub}
	case dwarf.TagSubroutineType:
		ref = TypeRef{Kind: "function"}
	case dwarf.TagArrayType:
		sub, e := b.ref(target, depth+1)
		if e != nil {
			return ref, e
		}
		var counts []uint64
		for _, child := range d.children {
			entry := b.dies[child].entry
			if entry.Tag != dwarf.TagSubrangeType {
				continue
			}
			if entry.Val(dwarf.Attr(0x2e)) != nil || entry.Val(dwarf.Attr(0x51)) != nil {
				return ref, fmt.Errorf("strided arrays are unsupported")
			}
			count, ok := unsigned(entry.Val(dwarf.AttrCount))
			if !ok {
				upper, exists := unsigned(entry.Val(dwarf.AttrUpperBound))
				lower, _ := unsigned(entry.Val(dwarf.AttrLowerBound))
				if exists {
					if upper < lower || upper == ^uint64(0) {
						return ref, fmt.Errorf("invalid array bound")
					}
					count = upper - lower + 1
				}
			}
			counts = append(counts, count)
		}
		if len(counts) == 0 {
			counts = []uint64{0}
		}
		ref = sub
		for i := len(counts) - 1; i >= 0; i-- {
			inner := ref
			ref = TypeRef{Kind: "array", Count: counts[i], Subtype: &inner}
		}
	case dwarf.TagEnumerationType:
		if size == 0 || size > 8 {
			return ref, fmt.Errorf("unsupported enum width %d", size)
		}
		en := Enumeration{Size: size, Constants: map[string]json.Number{}}
		signed := false
		for _, child := range d.children {
			entry := b.dies[child].entry
			if entry.Tag != dwarf.TagEnumerator {
				continue
			}
			key, _ := entry.Val(dwarf.AttrName).(string)
			n, e := numeric(entry.Val(dwarf.AttrConstValue))
			if e != nil {
				return ref, e
			}
			if strings.HasPrefix(string(n), "-") {
				signed = true
			}
			en.Constants[key] = n
		}
		if target != 0 {
			base, e := b.ref(target, depth+1)
			if e != nil {
				return ref, e
			}
			if base.Kind != "base" {
				return ref, fmt.Errorf("enum base is not an integer")
			}
			en.Base = base.Name
		} else {
			en.Base = fmt.Sprintf("__enum_%d_%t", size, signed)
			if err = b.base(en.Base, Type{Kind: "int", Size: size, Endian: endian, Signed: signed}); err != nil {
				return ref, err
			}
		}
		if prior, ok := b.table.Enums[name]; ok && !reflect.DeepEqual(prior, en) {
			return ref, fmt.Errorf("conflicting enumeration definitions for %s", name)
		}
		b.table.Enums[name] = en
		ref = TypeRef{Kind: "enum", Name: name}
	case dwarf.TagStructType, dwarf.TagClassType, dwarf.TagUnionType:
		kind := "struct"
		if d.entry.Tag == dwarf.TagUnionType {
			kind = "union"
		}
		ref = TypeRef{Kind: kind, Name: name}
		b.refs[off] = ref
		t := Type{Kind: kind, Size: size, Fields: map[string]Field{}}
		for _, child := range d.children {
			member := b.dies[child].entry
			if member.Tag != dwarf.TagMember {
				continue
			}
			if kind != "union" && member.Val(dwarf.AttrDataMemberLoc) == nil && member.Val(dwarf.AttrDataBitOffset) == nil {
				external, _ := member.Val(dwarf.AttrExternal).(bool)
				declaration, _ := member.Val(dwarf.AttrDeclaration).(bool)
				if external || declaration {
					continue
				}
				return ref, fmt.Errorf("member of %s lacks a fixed location", name)
			}
			fieldName, _ := member.Val(dwarf.AttrName).(string)
			if fieldName == "" {
				fieldName = fmt.Sprintf("__anonymous_%d", len(t.Fields))
			}
			field, e := b.member(member, size, depth+1)
			if e != nil {
				return ref, fmt.Errorf("%s.%s: %w", name, fieldName, e)
			}
			field.Anonymous = member.Val(dwarf.AttrName) == nil || member.Val(dwarf.AttrName) == ""
			if _, exists := t.Fields[fieldName]; exists {
				return ref, fmt.Errorf("duplicate member %s.%s", name, fieldName)
			}
			t.Fields[fieldName] = field
		}
		err = b.userType(name, t)
	default:
		return ref, fmt.Errorf("unsupported DWARF tag %s", d.entry.Tag)
	}
	if err == nil {
		b.refs[off] = ref
	}
	return ref, err
}
func (b *dwarfBuilder) base(name string, t Type) error {
	if old, ok := b.table.Bases[name]; ok && !reflect.DeepEqual(old, t) {
		return fmt.Errorf("conflicting base type %s", name)
	}
	b.table.Bases[name] = t
	return nil
}
func (b *dwarfBuilder) userType(name string, t Type) error {
	if prior, ok := b.table.Types[name]; ok && !reflect.DeepEqual(prior, t) {
		if prior.Size == 0 && len(prior.Fields) == 0 {
			b.table.Types[name] = t
			return nil
		}
		if t.Size == 0 && len(t.Fields) == 0 {
			return nil
		}
		return fmt.Errorf("conflicting type definitions for %s", name)
	}
	b.table.Types[name] = t
	return nil
}
func (b *dwarfBuilder) refSize(t TypeRef, depth int) (uint64, error) {
	if depth > 128 {
		return 0, fmt.Errorf("size recursion exceeds limit")
	}
	switch t.Kind {
	case "pointer":
		return uint64(b.file.pointer), nil
	case "base":
		v, ok := b.table.Bases[t.Name]
		if !ok {
			return 0, fmt.Errorf("missing base %s", t.Name)
		}
		return v.Size, nil
	case "enum":
		return b.table.Enums[t.Name].Size, nil
	case "struct", "union":
		return b.table.Types[t.Name].Size, nil
	case "array":
		if t.Subtype == nil {
			return 0, fmt.Errorf("array lacks subtype")
		}
		n, e := b.refSize(*t.Subtype, depth+1)
		if e != nil {
			return 0, e
		}
		if n != 0 && t.Count > ^uint64(0)/n {
			return 0, fmt.Errorf("array size overflow")
		}
		return n * t.Count, nil
	case "bitfield":
		if t.Underlying() == nil {
			return 0, fmt.Errorf("bitfield lacks storage type")
		}
		return b.refSize(*t.Underlying(), depth+1)
	}
	return 0, fmt.Errorf("type %s has no storage size", t.Kind)
}
func (b *dwarfBuilder) member(e *dwarf.Entry, parentSize uint64, depth int) (Field, error) {
	var f Field
	target, _ := e.Val(dwarf.AttrType).(dwarf.Offset)
	ref, err := b.ref(target, depth)
	if err != nil {
		return f, err
	}
	offset, err := memberOffset(e.Val(dwarf.AttrDataMemberLoc))
	if err != nil {
		return f, err
	}
	bits, _ := unsigned(e.Val(dwarf.AttrBitSize))
	if bits != 0 {
		if bits > 64 {
			return f, fmt.Errorf("bitfield exceeds 64 bits")
		}
		storage, err := b.refSize(ref, 0)
		if err != nil {
			return f, err
		}
		if width, ok := unsigned(e.Val(dwarf.AttrByteSize)); ok {
			storage = width
		}
		var position uint64
		little := b.table.Bases["pointer"].Endian == "little"
		if bitOffset, ok := unsigned(e.Val(dwarf.AttrDataBitOffset)); ok {
			offset = bitOffset / 8
			remainder := bitOffset % 8
			storage = (remainder + bits + 7) / 8
			if little {
				position = remainder
			} else {
				position = storage*8 - remainder - bits
			}
		} else {
			msb, _ := unsigned(e.Val(dwarf.AttrBitOffset))
			if storage > 8 || msb > storage*8 || bits > storage*8-msb {
				return f, fmt.Errorf("invalid legacy bit offset")
			}
			position = storage*8 - msb - bits
			if little {
				storage = (position + bits + 7) / 8
			} else if offset <= parentSize && storage > parentSize-offset {
				trim := storage - (parentSize - offset)
				if trim*8 > position {
					return f, fmt.Errorf("bitfield exceeds containing structure")
				}
				storage -= trim
				position -= trim * 8
			}
		}
		if storage == 0 || storage > 8 {
			return f, fmt.Errorf("invalid bitfield storage")
		}
		original, err := b.refSize(ref, 0)
		if err != nil {
			return f, err
		}
		if original != storage {
			signed := false
			if base, ok := b.table.Bases[ref.Name]; ok {
				signed = base.Signed
			} else if en, ok := b.table.Enums[ref.Name]; ok {
				signed = b.table.Bases[en.Base].Signed
			}
			name := fmt.Sprintf("__bitfield_%d_%t", storage, signed)
			if err = b.base(name, Type{Kind: "int", Size: storage, Signed: signed, Endian: b.table.Bases["pointer"].Endian}); err != nil {
				return f, err
			}
			ref = TypeRef{Kind: "base", Name: name}
		}
		underlying := ref
		ref = TypeRef{Kind: "bitfield", BitPosition: position, BitLength: bits, BitType: &underlying}
	}
	if offset > parentSize {
		return f, fmt.Errorf("member lies outside type")
	}
	f = Field{Offset: offset, Type: ref}
	return f, nil
}
func unsigned(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	case uint32:
		return uint64(n), true
	case int:
		return uint64(n), n >= 0
	}
	return 0, false
}
func numeric(v any) (json.Number, error) {
	switch n := v.(type) {
	case int64:
		return json.Number(strconv.FormatInt(n, 10)), nil
	case uint64:
		return json.Number(strconv.FormatUint(n, 10)), nil
	}
	return "", fmt.Errorf("unsupported DWARF integer constant %T", v)
}
func memberOffset(v any) (uint64, error) {
	if v == nil {
		return 0, nil
	}
	if n, ok := unsigned(v); ok {
		return n, nil
	}
	expr, ok := v.([]byte)
	if !ok {
		return 0, fmt.Errorf("nonconstant member location")
	}
	if len(expr) > 0 && expr[0] == 0x23 {
		n, used, err := uleb(expr[1:])
		if err == nil && used == len(expr)-1 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("unsupported member location expression")
}
func uleb(b []byte) (uint64, int, error) {
	var result uint64
	for i, n := range b {
		if i >= 10 || i == 9 && n > 1 {
			return 0, 0, fmt.Errorf("ULEB128 overflow")
		}
		result |= uint64(n&0x7f) << uint(i*7)
		if n&0x80 == 0 {
			return result, i + 1, nil
		}
	}
	return 0, 0, io.ErrUnexpectedEOF
}
func mergeSystemMap(ctx context.Context, path string, t *ISF, max int) (SymbolSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return SymbolSource{}, err
	}
	defer f.Close()
	h := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(contextReader{ctx, f}, h))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || len(fields[1]) != 1 {
			return SymbolSource{}, fmt.Errorf("malformed System.map line %d", count+1)
		}
		address, e := strconv.ParseUint(fields[0], 16, 64)
		if e != nil {
			return SymbolSource{}, fmt.Errorf("System.map address: %w", e)
		}
		s := t.Symbols[fields[2]]
		s.Address = address
		t.Symbols[fields[2]] = s
		count++
		if count > max {
			return SymbolSource{}, fmt.Errorf("System.map exceeds symbol limit")
		}
	}
	if err = scanner.Err(); err != nil {
		return SymbolSource{}, err
	}
	return SymbolSource{Name: f.Name(), SHA256: hex.EncodeToString(h.Sum(nil)), Kind: "system-map"}, nil
}
