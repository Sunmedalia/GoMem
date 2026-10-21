package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/elfimage"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type linuxModuleGap struct {
	offset, address, size uint64
	cause                 error
}
type linuxModuleData struct {
	section   elfimage.ModuleSection
	source    uint64
	requested uint64
	gaps      []linuxModuleGap
}

func linuxModuleDumpParameters() []plugin.Parameter {
	return []plugin.Parameter{{Name: "dump", Kind: "bool", Default: "false", Description: "Reconstruct selected kernel modules as ELF with explicit padding provenance"}, {Name: "max-module-bytes", Kind: "uint", Default: "67108864", Description: "Per-module source/output allocation bound, 4096..1073741824 bytes"}}
}

func linuxModuleDumpOptions(p map[string]string) (bool, uint64, error) {
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return false, 0, err
	}
	max, err := strconv.ParseUint(p["max-module-bytes"], 0, 64)
	if err != nil || max < 4096 || max > 1<<30 {
		return false, 0, fmt.Errorf("max-module-bytes must be 4096..1073741824")
	}
	return dump, max, nil
}

func linuxModuleContainer(n *linuxModuleRead, base uint64, typ, field, fallback string) (uint64, string, error) {
	f, err := n.e.Objects.Field(typ, field)
	if err != nil {
		return 0, "", err
	}
	if f.Type.Kind == "struct" || f.Type.Kind == "union" {
		at, err := memory.Add(base, f.Offset)
		return at, f.Type.Name, err
	}
	if f.Type.Kind != "pointer" {
		return 0, "", fmt.Errorf("%s.%s is not a structure or pointer", typ, field)
	}
	target := fallback
	if sub := f.Type.Underlying(); sub != nil {
		if sub.Kind != "struct" && sub.Kind != "union" {
			return 0, "", fmt.Errorf("%s.%s has non-structure target", typ, field)
		}
		target = sub.Name
	}
	at, err := n.uint(base, typ, field)
	if err != nil {
		return 0, "", err
	}
	if at == 0 {
		return 0, "", fmt.Errorf("%s.%s is null", typ, field)
	}
	return at, target, nil
}

func linuxModuleELFBounds(n *linuxModuleRead) (uint64, uint64, error) {
	if sym, err := n.e.Symbols.Lookup("mod_tree"); err == nil {
		if sym.Type == nil || sym.Type.Kind != "struct" {
			return 0, 0, fmt.Errorf("mod_tree lacks structure metadata")
		}
		at, err := n.e.Symbol("mod_tree")
		if err != nil {
			return 0, 0, err
		}
		low, err := n.uint(at, sym.Type.Name, "addr_min")
		if err != nil {
			return 0, 0, err
		}
		high, err := n.uint(at, sym.Type.Name, "addr_max")
		return low, high, err
	}
	values := []uint64{}
	for _, name := range []string{"module_addr_min", "module_addr_max"} {
		sym, err := n.e.Symbols.Lookup(name)
		if err != nil {
			return 0, 0, err
		}
		if sym.Type == nil || sym.Type.Kind == "void" {
			return 0, 0, fmt.Errorf("%s lacks scalar metadata", name)
		}
		at, err := n.e.Symbol(name)
		if err != nil {
			return 0, 0, err
		}
		v, err := n.scalar(at, *sym.Type)
		if err != nil {
			return 0, 0, err
		}
		values = append(values, v)
	}
	return values[0], values[1], nil
}

func linuxModuleSectionName(n *linuxModuleRead, at uint64, typ string) (string, error) {
	if battr, err := n.has(typ, "battr"); err != nil {
		return "", err
	} else if battr {
		ptr, err := n.uint(at, typ, "battr.attr.name")
		if err != nil {
			return "", err
		}
		return linuxModuleNameAt(n, ptr, 255)
	}
	f, err := n.e.Objects.Field(typ, "name")
	if err == nil {
		if f.Type.Kind == "array" {
			address, err := memory.Add(at, f.Offset)
			if err != nil {
				return "", err
			}
			if f.Type.Count == 0 {
				return "", fmt.Errorf("empty section name array")
			}
			return linuxModuleNameAt(n, address, int(min(f.Type.Count, 255)))
		}
		if f.Type.Kind == "pointer" {
			ptr, err := n.uint(at, typ, "name")
			if err != nil {
				return "", err
			}
			return linuxModuleNameAt(n, ptr, 255)
		}
	}
	ptr, err := n.uint(at, typ, "mattr.attr.name")
	if err != nil {
		return "", err
	}
	return linuxModuleNameAt(n, ptr, 255)
}
func linuxModuleNameAt(n *linuxModuleRead, at uint64, size int) (string, error) {
	if at == 0 {
		return "", fmt.Errorf("section name pointer is null")
	}
	text, proof, err := linuxBoundedText(n.ctx, n.e, at, size)
	n.fields[fmt.Sprintf("section_name@%x", at)] = proof
	if err != nil {
		return "", err
	}
	if text == "" {
		return "", fmt.Errorf("empty section name")
	}
	return text, nil
}

func linuxModuleSections(n *linuxModuleRead, module uint64) ([]elfimage.ModuleSection, error) {
	attrs, typ, err := linuxModuleContainer(n, module, "module", "sect_attrs", "module_sect_attrs")
	if err != nil {
		return nil, err
	}
	var count uint64
	if present, err := n.has(typ, "nsections"); err != nil {
		return nil, err
	} else if present {
		count, err = n.uint(attrs, typ, "nsections")
		if err != nil {
			return nil, err
		}
	} else {
		field := "grp.attrs"
		if ok, _ := n.has(typ, "grp.bin_attrs"); ok {
			field = "grp.bin_attrs"
		}
		list, err := n.uint(attrs, typ, field)
		if err != nil {
			return nil, err
		}
		if list == 0 {
			return nil, fmt.Errorf("section attribute list is null")
		}
		for ; count < 100; count++ {
			at, err := memory.Add(list, count*uint64(n.e.Symbols.PointerSize()))
			if err != nil {
				return nil, err
			}
			v, err := n.scalar(at, symbols.TypeRef{Kind: "pointer"})
			if err != nil {
				return nil, err
			}
			if v == 0 {
				break
			}
		}
		if count == 100 {
			return nil, fmt.Errorf("section pointer list exceeds pinned 100-entry guard")
		}
	}
	if count == 0 || count > 4096 {
		return nil, fmt.Errorf("module section count %d outside 1..4096", count)
	}
	array, err := n.e.Objects.Field(typ, "attrs")
	if err != nil {
		return nil, err
	}
	if array.Type.Kind != "array" || array.Type.Underlying() == nil || array.Type.Underlying().Kind != "struct" {
		return nil, fmt.Errorf("section attrs must be an inline structure array")
	}
	subtype := *array.Type.Underlying()
	stride, err := n.e.Objects.Size(subtype)
	if err != nil || stride == 0 || stride > 4096 {
		return nil, fmt.Errorf("invalid module section stride")
	}
	start, err := memory.Add(attrs, array.Offset)
	if err != nil {
		return nil, err
	}
	low, high, err := linuxModuleELFBounds(n)
	if err != nil {
		return nil, err
	}
	mask, err := linuxModuleAddressMask(n.e)
	if err != nil {
		return nil, err
	}
	low &= mask
	high &= mask
	if low >= high {
		return nil, fmt.Errorf("empty or inverted module allocation bounds")
	}
	var sections []elfimage.ModuleSection
	indexes := map[uint64]int{}
	for i := uint64(0); i < count; i++ {
		if err := n.ctx.Err(); err != nil {
			return nil, err
		}
		at, err := memory.Add(start, i*stride)
		if err != nil {
			return nil, err
		}
		address, err := n.uint(at, subtype.Name, "address")
		if err != nil {
			return nil, err
		}
		if address&mask < low || address&mask >= high {
			continue
		}
		name, err := linuxModuleSectionName(n, at, subtype.Name)
		if err != nil {
			return nil, err
		}
		section := elfimage.ModuleSection{Name: name, Address: address}
		if index, ok := indexes[address]; ok {
			sections[index] = section
		} else {
			indexes[address] = len(sections)
			sections = append(sections, section)
		}
	}
	if len(sections) == 0 {
		return nil, fmt.Errorf("no module sections inside allocation bounds")
	}
	return sections, nil
}

// Data reads are page bounded and padded with explicit source-address gaps.
// Metadata and symbol tables are read strictly: holes cannot be decoded as zero.
func linuxReadModuleData(ctx context.Context, layer memory.MemoryLayer, address, size, max uint64) ([]byte, []linuxModuleGap, error) {
	if size > max || size > 1<<30 {
		return nil, nil, fmt.Errorf("module section exceeds byte limit")
	}
	if size > 0 {
		if _, err := memory.Add(address, size-1); err != nil {
			return nil, nil, err
		}
	}
	data := make([]byte, int(size))
	var gaps []linuxModuleGap
	for off := uint64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		at := address + off
		n := min(size-off, 4096-(at&4095))
		got, err := layer.ReadAt(ctx, data[off:off+n], at)
		if got < 0 || uint64(got) > n {
			return nil, nil, fmt.Errorf("module source returned invalid read length")
		}
		if uint64(got) < n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			clear(data[off+uint64(got) : off+n])
			gaps = append(gaps, linuxModuleGap{off + uint64(got), at + uint64(got), n - uint64(got), err})
		} else if err != nil {
			return nil, nil, err
		}
		off += n
	}
	return data, gaps, nil
}

func linuxBuildModuleELF(n *linuxModuleRead, module, max uint64) (*elfimage.ModuleImage, []linuxModuleGap, error) {
	if _, err := linuxModuleAddressMask(n.e); err != nil {
		return nil, nil, err
	}
	pointer, err := n.e.Symbols.Type("pointer")
	if err != nil || pointer.Endian != "little" && pointer.Endian != "" {
		return nil, nil, fmt.Errorf("module ELF reconstruction requires little-endian pointers")
	}
	sections, err := linuxModuleSections(n, module)
	if err != nil {
		return nil, nil, err
	}
	base, typ := module, "module"
	if ok, err := n.has("module", "kallsyms"); err != nil {
		return nil, nil, err
	} else if ok {
		base, typ, err = linuxModuleContainer(n, module, "module", "kallsyms", "mod_kallsyms")
		if err != nil {
			return nil, nil, err
		}
	}
	count, err := n.uint(base, typ, "num_symtab")
	if err != nil {
		return nil, nil, err
	}
	if count == 0 || count > 65536 {
		return nil, nil, fmt.Errorf("module symbol count outside 1..65536")
	}
	symtab, err := n.uint(base, typ, "symtab")
	if err != nil {
		return nil, nil, err
	}
	strtab, err := n.uint(base, typ, "strtab")
	if err != nil {
		return nil, nil, err
	}
	if symtab == 0 || strtab == 0 {
		return nil, nil, fmt.Errorf("nonempty module symbol/string table is null")
	}
	bits := n.e.Symbols.PointerSize() * 8
	stride := uint64(24)
	symType := "Elf64_Sym"
	if bits == 32 {
		stride = 16
		symType = "Elf32_Sym"
	} else if bits != 64 {
		return nil, nil, fmt.Errorf("unsupported module ELF width")
	}
	symbolType, err := n.e.Symbols.Type(symType)
	if err != nil || symbolType.Size != stride {
		return nil, nil, fmt.Errorf("invalid %s layout/size: %v", symType, err)
	}
	// These fixed ABI fields must agree with the ISF before interpreting raw bytes.
	expected := map[string]uint64{"st_name": 0, "st_info": 4, "st_other": 5, "st_shndx": 6, "st_value": 8, "st_size": 16}
	if bits == 32 {
		expected = map[string]uint64{"st_name": 0, "st_value": 4, "st_size": 8, "st_info": 12, "st_other": 13, "st_shndx": 14}
	}
	for field, offset := range expected {
		f, err := n.e.Objects.Field(symType, field)
		if err != nil || f.Offset != offset {
			return nil, nil, fmt.Errorf("%s.%s differs from Intel ELF ABI", symType, field)
		}
		width, err := n.e.Objects.Size(f.Type)
		wanted := map[string]uint64{"st_name": 4, "st_info": 1, "st_other": 1, "st_shndx": 2, "st_value": uint64(bits / 8), "st_size": uint64(bits / 8)}[field]
		if err != nil || width != wanted {
			return nil, nil, fmt.Errorf("%s.%s has invalid field width", symType, field)
		}
	}
	if count*stride > max {
		return nil, nil, fmt.Errorf("module symbol table exceeds byte limit")
	}
	raw, rawProof, err := linuxCaptureRange(n.ctx, n.e.Kernel, symtab, int(count*stride))
	n.fields["SymbolTableRaw"] = rawProof
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(raw)
	n.fields["SymbolTableSource"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Address": evidence.Address(symtab), "Bytes": evidence.Number(uint64(len(raw))), "SHA256": evidence.Text(hex.EncodeToString(digest[:]))}}
	sorted := append([]elfimage.ModuleSection(nil), sections...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Address < sorted[j].Address })
	observed := map[uint64]linuxModuleData{}
	total := uint64(len(raw))
	hasSym, hasStr := false, false
	for i, s := range sorted {
		if s.Name == ".symtab" {
			hasSym = true
			continue
		}
		size, source := uint64(0x10000), s.Address
		if i+1 < len(sorted) {
			size = sorted[i+1].Address - s.Address
		}
		if s.Name == ".strtab" {
			size, source = count*256, strtab
			hasStr = true
		}
		if total > max || size > max-total {
			return nil, nil, fmt.Errorf("module source data exceeds byte limit")
		}
		data, gaps, err := linuxReadModuleData(n.ctx, n.e.Kernel, source, size, max-total)
		if err != nil {
			return nil, nil, err
		}
		if s.Name == ".strtab" {
			if end := bytes.Index(data, []byte{0, 0}); end >= 0 {
				data = data[:end+1]
			}
		}
		total += uint64(len(data))
		s.Data = data
		observed[s.Address] = linuxModuleData{section: s, source: source, requested: size, gaps: gaps}
	}
	if !hasSym || !hasStr {
		return nil, nil, fmt.Errorf("module has no recoverable .symtab/.strtab")
	}
	for i, s := range sections {
		if data, ok := observed[s.Address]; ok {
			sections[i] = data.section
		}
	}
	image, err := elfimage.RebuildModule(n.ctx, bits, sections, raw, max)
	if err != nil {
		return nil, nil, err
	}
	var gaps []linuxModuleGap
	var proof []map[string]evidence.Value
	for index, s := range image.Sections {
		generated := index == len(image.Sections)-1
		source := s.Address
		requested := s.Size
		if s.Name == ".symtab" {
			source = symtab
			requested = count * stride
		}
		if data, ok := observed[s.Address]; ok && s.Name != ".symtab" && !generated {
			source = data.source
			requested = data.requested
			for _, g := range data.gaps {
				if g.offset < s.Size {
					g.size = min(g.size, s.Size-g.offset)
					g.offset += s.Offset
					gaps = append(gaps, g)
				}
			}
		}
		sourceValue := evidence.Address(source)
		if generated {
			sourceValue = evidence.Missing("generated_section_names", nil)
			requested = 0
		}
		proof = append(proof, map[string]evidence.Value{"Name": evidence.Text(s.Name), "Address": evidence.Address(s.Address), "Source": sourceValue, "SourceReadBytes": evidence.Number(requested), "FileOffset": evidence.Number(s.Offset), "Size": evidence.Number(s.Size)})
	}
	n.fields["Sections"] = evidence.Value{Kind: "structure", Data: proof}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].offset < gaps[j].offset })
	return image, gaps, nil
}

func linuxDumpModule(s *linuxModuleSources, row *evidence.Row, address, max uint64) {
	if row.Cells["Name"].Kind != "string" {
		err := fmt.Errorf("module name unavailable for extraction")
		s.failures.add(err)
		row.Cells["DumpEvidence"] = evidence.Missing("module_name_unavailable", err)
		row.Cells["File Output"] = evidence.Missing("module_elf_unavailable", err)
		return
	}

	fields := map[string]evidence.Value{}
	n := s.reader(fields)
	row.Cells["DumpEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	image, gaps, err := linuxBuildModuleELF(n, address, max)
	if err == nil && s.e.Artifacts == nil {
		err = fmt.Errorf("module extraction requires an artifact sink")
	}
	if err != nil {
		s.failures.add(err)
		row.Cells["File Output"] = evidence.Missing("module_elf_unavailable", err)
		return
	}
	name := row.Cells["Name"].String()
	mask, maskErr := linuxModuleAddressMask(s.e)
	if maskErr != nil {
		s.failures.add(maskErr)
		row.Cells["File Output"] = evidence.Missing("module_elf_unavailable", maskErr)
		return
	}
	w, err := s.e.Artifacts.Create(s.ctx, evidence.ArtifactRequest{Name: fmt.Sprintf("kernel_module.%s.%#x.elf", name, address&mask), Size: uint64(len(image.Data)), Layer: s.e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)})
	if err != nil {
		s.failures.add(err)
		row.Cells["File Output"] = evidence.Missing("module_elf_unavailable", err)
		return
	}
	write := func(data []byte) error {
		n, err := w.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	position := uint64(0)
	for _, gap := range gaps {
		if err = s.ctx.Err(); err != nil {
			break
		}
		if err = write(image.Data[position:gap.offset]); err != nil {
			break
		}
		if err = w.PadZero(s.ctx, gap.size, gap.address, s.e.Kernel.Name(), gap.cause); err != nil {
			break
		}
		position = gap.offset + gap.size
	}
	if err == nil {
		err = s.ctx.Err()
	}
	if err == nil {
		err = write(image.Data[position:])
	}
	artifact, finishErr := w.Finish(s.ctx, err)
	row.Cells["File Output"] = evidence.Value{Kind: "artifact", Data: artifact}
	s.failures.add(errors.Join(err, finishErr))
}
