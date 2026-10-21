package elfimage

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// ModuleSection holds a kernel section observation. Input order matters: the
// pinned extractor uses insertion order for symbol indexes, address order for
// file data, and moves .symtab to the end. Duplicate addresses replace data/name
// without moving their original position.
type ModuleSection struct {
	Name    string
	Address uint64
	Data    []byte
}
type ModuleOutputSection struct {
	Name                  string
	Address, Offset, Size uint64
}
type ModuleImage struct {
	Data     []byte
	Sections []ModuleOutputSection
}

// RebuildModule reproduces the locked Intel ModuleExtract ELF encoding. It does
// not claim to restore the original disk ELF or repair the baseline's unusual
// section indexes. Source reads and padding provenance belong to the caller.
func RebuildModule(ctx context.Context, bits int, input []ModuleSection, symbols []byte, maxBytes uint64) (*ModuleImage, error) {
	if bits != 32 && bits != 64 {
		return nil, fmt.Errorf("module ELF requires 32 or 64 bits")
	}
	if len(input) == 0 || len(input) > 4096 || maxBytes == 0 || maxBytes > 1<<30 {
		return nil, fmt.Errorf("invalid module section count or byte limit")
	}
	hdr, shsize, stride := uint64(64), uint64(64), 24
	if bits == 32 {
		hdr, shsize, stride = 52, 40, 16
	}
	if len(symbols) == 0 || len(symbols)%stride != 0 || len(symbols)/stride > 65536 {
		return nil, fmt.Errorf("invalid module symbol table extent")
	}
	sections := map[uint64]ModuleSection{}
	original := []uint64{}
	for _, s := range input {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if s.Name == "" || len(s.Name) > 255 || !utf8.ValidString(s.Name) || strings.IndexByte(s.Name, 0) >= 0 {
			return nil, fmt.Errorf("invalid module section name")
		}
		if _, ok := sections[s.Address]; !ok {
			original = append(original, s.Address)
		}
		sections[s.Address] = s
	}
	sorted := append([]uint64(nil), original...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var ordered []ModuleSection
	strIndex, symIndex := -1, -1
	var symAddress uint64
	hasSym := false
	total := hdr
	nameBytes := uint64(1)
	for i, at := range sorted {
		s := sections[at]
		if s.Name == ".symtab" {
			symAddress, hasSym = at, true
			continue
		}
		if s.Name == ".strtab" {
			strIndex = i
		}
		if uint64(len(s.Data)) > maxBytes || total > maxBytes-uint64(len(s.Data)) {
			return nil, fmt.Errorf("module data exceeds byte limit")
		}
		total += uint64(len(s.Data))
		nameBytes += uint64(len(s.Name) + 1)
		ordered = append(ordered, s)
	}
	if !hasSym || symAddress == 0 || strIndex < 0 {
		return nil, fmt.Errorf("module requires .symtab and .strtab sections")
	}
	symIndex = len(ordered)
	fixed := append([]byte(nil), symbols...)
	for off := 0; off < len(fixed); off += stride {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s := fixed[off : off+stride]
		name := binary.LittleEndian.Uint32(s)
		valueAt, indexAt, infoAt := 8, 6, 4
		if bits == 32 {
			valueAt, indexAt, infoAt = 4, 14, 12
		}
		value := uint64(binary.LittleEndian.Uint32(s[valueAt:]))
		if bits == 64 {
			value = binary.LittleEndian.Uint64(s[valueAt:])
		}
		matched := ""
		relative := value
		for i, at := range original {
			sect := sections[at]
			size := uint64(len(sect.Data))
			if sect.Name == ".symtab" {
				continue
			}
			if value >= at && value-at < size {
				matched = sect.Name
				relative = value - at
				binary.LittleEndian.PutUint16(s[indexAt:], uint16(i+1))
				break
			}
		}
		info := byte(3) // unnamed local section symbol
		if name > 0 {
			info = 0x10
			if value != 0 && matched != "" {
				info = 0x11
				if strings.Contains(matched, ".text") && !strings.Contains(matched, ".rela") {
					info = 0x12
				}
			}
		}
		s[infoAt] = info
		if bits == 64 {
			binary.LittleEndian.PutUint64(s[valueAt:], relative)
		} else {
			binary.LittleEndian.PutUint32(s[valueAt:], uint32(relative))
		}
	}
	ordered = append(ordered, ModuleSection{Name: ".symtab", Address: symAddress, Data: fixed})
	nameBytes += uint64(len(".symtab") + 1 + len(".shstrtab") + 1)
	overhead := uint64(len(fixed)) + nameBytes + uint64(len(ordered)+2)*shsize
	if overhead > maxBytes || total > maxBytes-overhead {
		return nil, fmt.Errorf("module ELF exceeds byte limit")
	}
	total += overhead
	if bits == 32 && total > 0xffffffff {
		return nil, fmt.Errorf("32-bit module ELF offset overflow")
	}
	result := &ModuleImage{Data: make([]byte, hdr, int(total))}
	names := []byte{0}
	nameIndexes := []uint32{}
	nameIndex := uint32(1)
	for _, s := range ordered {
		nameIndexes = append(nameIndexes, nameIndex)
		names = append(names, []byte(s.Name)...)
		names = append(names, 0)
		// Python len(str) counts Unicode code points, not UTF-8 bytes.
		nameIndex += uint32(utf8.RuneCountInString(s.Name) + 1)
		result.Sections = append(result.Sections, ModuleOutputSection{s.Name, s.Address, uint64(len(result.Data)), uint64(len(s.Data))})
		result.Data = append(result.Data, s.Data...)
	}
	names = append(names, []byte(".shstrtab\x00")...)
	result.Sections = append(result.Sections, ModuleOutputSection{".shstrtab", 0, uint64(len(result.Data)), uint64(len(names))})
	result.Data = append(result.Data, names...)
	shoff := uint64(len(result.Data))
	result.Data = append(result.Data, make([]byte, shsize)...)
	nameIndexes = append(nameIndexes, nameIndex)
	for i, s := range result.Sections {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sh, err := moduleSectionHeader(bits, s, nameIndexes[i], strIndex, symIndex)
		if err != nil {
			return nil, err
		}
		result.Data = append(result.Data, sh...)
	}
	h := result.Data[:hdr]
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(h[16:], 1)
	binary.LittleEndian.PutUint32(h[20:], 1)
	if bits == 64 {
		binary.LittleEndian.PutUint16(h[18:], 62)
		binary.LittleEndian.PutUint64(h[40:], shoff)
		binary.LittleEndian.PutUint16(h[52:], 64)
		binary.LittleEndian.PutUint16(h[58:], 64)
		binary.LittleEndian.PutUint16(h[60:], uint16(len(result.Sections)+1))
		binary.LittleEndian.PutUint16(h[62:], uint16(len(result.Sections)))
	} else {
		h[4] = 1
		binary.LittleEndian.PutUint16(h[18:], 3)
		binary.LittleEndian.PutUint32(h[32:], uint32(shoff))
		binary.LittleEndian.PutUint16(h[40:], 52)
		binary.LittleEndian.PutUint16(h[46:], 40)
		binary.LittleEndian.PutUint16(h[48:], uint16(len(result.Sections)+1))
		binary.LittleEndian.PutUint16(h[50:], uint16(len(result.Sections)))
	}
	return result, nil
}

func moduleSectionHeader(bits int, s ModuleOutputSection, name uint32, strIndex, symIndex int) ([]byte, error) {
	typ, flags, link, entsize := uint32(1), uint64(2), uint32(0), uint64(0)
	switch s.Name {
	case ".note.gnu.build-id":
		typ = 7
	case ".symtab":
		typ = 2
	case ".strtab", ".shstrtab":
		typ = 3
	}
	if strings.Contains(s.Name, ".rela.") {
		typ = 4
		link = uint32(symIndex)
		entsize = 24
	} else if typ == 2 {
		link = uint32(strIndex)
		entsize = 24
		if bits == 32 {
			entsize = 16
		}
	}
	switch s.Name {
	case ".text", ".init.text", ".exit.text", ".static_call.text":
		flags |= 4
	case ".data", ".init.data", ".exit.data", ".bss", "__tracepoints", ".data.once", "_ftrace_events", ".gnu.linkonce.this_module":
		flags |= 1
	}
	sh := make([]byte, 64)
	binary.LittleEndian.PutUint32(sh, name)
	binary.LittleEndian.PutUint32(sh[4:], typ)
	if bits == 64 {
		for _, v := range []struct {
			at int
			v  uint64
		}{{8, flags}, {16, s.Address}, {24, s.Offset}, {32, s.Size}, {48, 1}, {56, entsize}} {
			binary.LittleEndian.PutUint64(sh[v.at:], v.v)
		}
		binary.LittleEndian.PutUint32(sh[40:], link)
	} else {
		if s.Address > 0xffffffff || s.Offset > 0xffffffff || s.Size > 0xffffffff {
			return nil, fmt.Errorf("32-bit module section overflow")
		}
		sh = sh[:40]
		for _, v := range []struct {
			at int
			v  uint32
		}{{8, uint32(flags)}, {12, uint32(s.Address)}, {16, uint32(s.Offset)}, {20, uint32(s.Size)}, {24, link}, {32, 1}, {36, uint32(entsize)}} {
			binary.LittleEndian.PutUint32(sh[v.at:], v.v)
		}
	}
	return sh, nil
}
