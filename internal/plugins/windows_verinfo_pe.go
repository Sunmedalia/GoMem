package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
)

const (
	verMaxSections         = 0x800
	verMaxResourceDepth    = 32
	verMaxDirectoryEntries = 4096
	verMaxResourceEntries  = 0x8000
	verRTVersion           = 16
)

type verSection struct {
	va, vaAdj         uint32
	raw, rawAdj       uint32
	rawSize, virtSize uint32
	nextVA            *uint32
}

type verParser struct {
	ctx        context.Context
	layer      memory.MemoryLayer
	image      *pe.Image
	sections   []verSection
	headerSize uint64
	entries    int
	found      *versionQuad
}

func newVerParser(ctx context.Context, layer memory.MemoryLayer, image *pe.Image) (*verParser, error) {
	parser := &verParser{ctx: ctx, layer: layer, image: image}
	if err := parser.loadSections(); err != nil {
		return nil, err
	}
	return parser, nil
}

func (p *verParser) productVersion() (versionQuad, error) {
	rva, size, ok, err := p.resourceDirectory()
	if err != nil || !ok || rva == 0 {
		if err != nil {
			return versionQuad{}, err
		}
		return versionQuad{}, errors.New("PE has no resource directory")
	}
	_ = size
	if _, err = p.walk(rva, rva, 0, nil); err != nil {
		return versionQuad{}, err
	}
	if p.found == nil {
		return versionQuad{}, errors.New("PE resource directory has no VS_FIXEDFILEINFO")
	}
	return *p.found, nil
}

func (p *verParser) resourceDirectory() (uint32, uint32, bool, error) {
	dos, err := p.bytes(0, 64)
	if err != nil || len(dos) < 64 {
		return 0, 0, false, err
	}
	nt := uint64(binary.LittleEndian.Uint32(dos[60:]))
	file, err := p.bytes(nt, 24)
	if err != nil || len(file) < 24 {
		return 0, 0, false, err
	}
	optionalSize := uint64(binary.LittleEndian.Uint16(file[20:]))
	opt, err := p.bytes(nt+24, int(optionalSize))
	if err != nil || len(opt) < 2 {
		return 0, 0, false, err
	}
	magic := binary.LittleEndian.Uint16(opt)
	structSize := 96
	if magic == 0x20b {
		structSize = 112
	}
	if len(opt) < structSize {
		return 0, 0, false, nil
	}
	count := binary.LittleEndian.Uint32(opt[structSize-4:])
	if count > 0x10 {
		count = 0x10
	}
	// pefile stops once the directory offset leaves the fixed optional header plus 16 entries.
	if count <= 2 {
		return 0, 0, false, nil
	}
	entry, err := p.bytes(nt+24+uint64(structSize)+16, 8)
	if err != nil || len(entry) < 8 {
		return 0, 0, false, err
	}
	return binary.LittleEndian.Uint32(entry), binary.LittleEndian.Uint32(entry[4:]), true, nil
}

func (p *verParser) loadSections() error {
	dos, err := p.bytes(0, 64)
	if err != nil || len(dos) < 64 {
		return err
	}
	nt := uint64(binary.LittleEndian.Uint32(dos[60:]))
	file, err := p.bytes(nt, 24)
	if err != nil || len(file) < 24 {
		return err
	}
	number := int(binary.LittleEndian.Uint16(file[6:]))
	optionalSize := uint64(binary.LittleEndian.Uint16(file[20:]))
	opt, err := p.bytes(nt+24, int(optionalSize))
	if err != nil || len(opt) < 64 {
		return err
	}
	magic := binary.LittleEndian.Uint16(opt)
	fileAlign := binary.LittleEndian.Uint32(opt[36:])
	sectionAlign := binary.LittleEndian.Uint32(opt[32:])
	if magic == 0x10b {
		// PE32 stores SectionAlignment and FileAlignment at the same offsets as PE32+.
	}
	sectionOffset := nt + 24 + optionalSize
	limit := number
	if limit > verMaxSections {
		limit = verMaxSections
	}
	var parsed []verSection
	for i := 0; i < limit; i++ {
		raw, err := p.bytes(sectionOffset+uint64(i)*40, 40)
		if err != nil {
			return err
		}
		if len(raw) != 40 || bytesAllZero(raw) {
			break
		}
		section := verSection{
			virtSize: binary.LittleEndian.Uint32(raw[8:]),
			va:       binary.LittleEndian.Uint32(raw[12:]),
			rawSize:  binary.LittleEndian.Uint32(raw[16:]),
			raw:      binary.LittleEndian.Uint32(raw[20:]),
		}
		section.vaAdj = alignSection(section.va, sectionAlign, fileAlign)
		section.rawAdj = section.raw &^ 0x1FF
		if sectionAlign < 0x1000 && section.raw == section.va {
			section.rawAdj = section.va
		}
		if sectionWarnings(section, p.image.Size, fileAlign) >= 3 {
			break
		}
		parsed = append(parsed, section)
	}
	sort.SliceStable(parsed, func(i, j int) bool { return parsed[i].va < parsed[j].va })
	for i := range parsed {
		if i+1 < len(parsed) {
			next := parsed[i+1].va
			parsed[i].nextVA = &next
		}
	}
	p.sections = parsed
	end := sectionOffset
	if number > 0 && len(parsed) > 0 {
		end = sectionOffset + uint64(number)*40
	}
	var lowest uint32
	have := false
	for _, section := range parsed {
		adj := section.raw &^ 0x1FF
		if section.raw > 0 && (!have || adj < lowest) {
			lowest, have = adj, true
		}
	}
	p.headerSize = end
	if have && uint64(lowest) >= end {
		p.headerSize = uint64(lowest)
	}
	return nil
}

func sectionWarnings(section verSection, imageSize uint64, fileAlign uint32) int {
	warnings := 0
	if uint64(section.rawSize)+uint64(section.raw) > imageSize {
		warnings++
	}
	if uint64(section.raw&^0x1FF) > imageSize {
		warnings++
	}
	if section.virtSize > 0x10000000 {
		warnings++
	}
	if section.vaAdj > 0x10000000 {
		warnings++
	}
	if fileAlign != 0 && section.raw%fileAlign != 0 {
		warnings++
	}
	return warnings
}

func alignSection(value, sectionAlign, fileAlign uint32) uint32 {
	align := sectionAlign
	if align < 0x1000 {
		align = fileAlign
	}
	if align != 0 && value%align != 0 {
		return align * (value / align)
	}
	return value
}

type verDir struct{ entries []verEntry }
type verEntry struct {
	id   uint32
	dir  *verDir
	data *verData
}
type verData struct{ offset, size uint32 }

func (p *verParser) walk(rva, root uint32, level int, dirs []uint32) (*verDir, error) {
	if level > verMaxResourceDepth {
		return nil, nil
	}
	header, err := p.data(rva, 16)
	if err != nil || len(header) != 16 {
		return nil, err
	}
	named := binary.LittleEndian.Uint16(header[12:])
	ids := binary.LittleEndian.Uint16(header[14:])
	count := int(named) + int(ids)
	if count > verMaxDirectoryEntries {
		return nil, nil
	}
	p.entries += count
	if p.entries > verMaxResourceEntries {
		return nil, nil
	}
	dir := &verDir{}
	entryRVA := rva + 16
	var lastBegin, lastEnd uint32
	haveLast := false
	for i := 0; i < count; i++ {
		if p.found != nil {
			return dir, nil
		}
		raw, err := p.data(entryRVA, 8)
		if err != nil || len(raw) != 8 {
			break
		}
		name := binary.LittleEndian.Uint32(raw)
		offset := binary.LittleEndian.Uint32(raw[4:])
		if name&0x80000000 != 0 {
			ustr := root + (name & 0x7FFFFFFF)
			length := uint32(0)
			word, wordErr := p.data(ustr, 2)
			if wordErr == nil && len(word) == 2 {
				length = uint32(binary.LittleEndian.Uint16(word))
			}
			if haveLast && lastBegin < ustr && lastEnd >= ustr {
				break
			}
			lastBegin, lastEnd, haveLast = ustr, ustr+length, true
		}
		entry := verEntry{id: name & 0xFFFF}
		child := root + (offset & 0x7FFFFFFF)
		if offset&0x80000000 != 0 {
			if containsU32(dirs, child) {
				break
			}
			sub, err := p.walk(child, root, level+1, append(append([]uint32{}, dirs...), child))
			if err != nil {
				return nil, err
			}
			if sub == nil {
				break
			}
			entry.dir = sub
			dir.entries = append(dir.entries, entry)
		} else {
			data, err := p.data(child, 16)
			if err != nil || len(data) != 16 {
				break
			}
			entry.data = &verData{offset: binary.LittleEndian.Uint32(data), size: binary.LittleEndian.Uint32(data[4:])}
			dir.entries = append(dir.entries, entry)
		}
		if level == 0 && entry.id == verRTVersion && len(dir.entries) > 0 {
			p.parseVersionDirectory(dir.entries[len(dir.entries)-1])
		}
		entryRVA += 8
	}
	return dir, nil
}

func (p *verParser) parseVersionDirectory(entry verEntry) {
	if entry.dir == nil || len(entry.dir.entries) == 0 || entry.dir.entries[0].dir == nil {
		return
	}
	for _, language := range entry.dir.entries[0].dir.entries {
		if language.data == nil {
			continue
		}
		if quad, ok := p.fixedVersion(language.data); ok {
			p.found = &quad
			return
		}
	}
}

func (p *verParser) fixedVersion(data *verData) (versionQuad, bool) {
	key, ok := p.versionKey(data.offset)
	if !ok || key != "VS_VERSION_INFO" {
		return versionQuad{}, false
	}
	rel := dwordAlign(6+2*(uint32(len(key))+1), data.offset)
	need := rel + 52
	if need > data.size {
		need = data.size
	}
	fileOff, ok := p.fileOffset(data.offset)
	if !ok {
		return versionQuad{}, false
	}
	raw, err := p.bytes(fileOff, int(need))
	if err != nil || uint32(len(raw)) < rel+52 {
		return versionQuad{}, false
	}
	ms := binary.LittleEndian.Uint32(raw[rel+16:])
	ls := binary.LittleEndian.Uint32(raw[rel+20:])
	return versionQuad{uint64(ms >> 16), uint64(ms & 0xFFFF), uint64(ls >> 16), uint64(ls & 0xFFFF)}, true
}

func (p *verParser) versionKey(dataRVA uint32) (string, bool) {
	ustr := dataRVA + 6
	maxChars := 1 << 16
	if section, ok := p.sectionByRVA(ustr); ok {
		end := uint64(section.va) + uint64(max32(section.rawSize, section.virtSize))
		if uint64(ustr) >= end {
			return "", false
		}
		maxChars = int((end - uint64(ustr)) >> 1)
	}
	if maxChars <= 0 {
		return "", false
	}
	if _, err := p.data(ustr, 2); err != nil {
		return "", false
	}
	want := maxChars * 2
	if want > 256 {
		want = 256
	}
	raw, err := p.data(ustr, want)
	if err != nil || len(raw) < 2 {
		return "", false
	}
	units := len(raw) / 2
	for i := 0; i+1 < len(raw); i += 2 {
		if raw[i] == 0 && raw[i+1] == 0 {
			units = i / 2
			break
		}
	}
	decoded := string(utf16.Decode(u16s(raw[:units*2])))
	if decoded != "VS_VERSION_INFO" {
		return decoded, true
	}
	return decoded, true
}

func (p *verParser) sectionByRVA(rva uint32) (verSection, bool) {
	for _, section := range p.sections {
		if section.contains(rva, p.image.Size) {
			return section, true
		}
	}
	return verSection{}, false
}

func (s verSection) contains(rva uint32, imageSize uint64) bool {
	if uint64(s.rawAdj) > imageSize {
		return false
	}
	size := uint64(max32(s.rawSize, s.virtSize))
	if imageSize-uint64(s.rawAdj) < uint64(s.rawSize) {
		size = uint64(s.virtSize)
	}
	if s.nextVA != nil && *s.nextVA > s.va && uint64(s.vaAdj)+size > uint64(*s.nextVA) {
		if uint64(*s.nextVA) < uint64(s.vaAdj) {
			return false
		}
		size = uint64(*s.nextVA) - uint64(s.vaAdj)
	}
	return uint64(s.vaAdj) <= uint64(rva) && uint64(rva) < uint64(s.vaAdj)+size
}

func (p *verParser) fileOffset(rva uint32) (uint64, bool) {
	section, ok := p.sectionByRVA(rva)
	if !ok {
		if uint64(rva) < p.image.Size {
			return uint64(rva), true
		}
		return 0, false
	}
	return uint64(rva) - uint64(section.vaAdj) + uint64(section.rawAdj), true
}

func (p *verParser) data(rva uint32, n int) ([]byte, error) {
	section, inSection := p.sectionByRVA(rva)
	if !inSection {
		if uint64(rva) < p.headerSize {
			end := uint64(rva) + uint64(n)
			if end > p.headerSize {
				end = p.headerSize
			}
			return p.bytes(uint64(rva), int(end-uint64(rva)))
		}
		if uint64(rva) < p.image.Size {
			return p.bytes(uint64(rva), n)
		}
		return nil, errors.New("resource RVA is outside the reconstructed PE")
	}
	offset := uint64(rva) - uint64(section.vaAdj) + uint64(section.rawAdj)
	end := offset + uint64(n)
	limit := uint64(section.raw) + uint64(section.rawSize)
	if end > limit {
		end = limit
	}
	if end < offset || offset >= p.image.Size {
		return []byte{}, nil
	}
	return p.bytes(offset, int(end-offset))
}

func (p *verParser) bytes(off uint64, n int) ([]byte, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	if n <= 0 || off >= p.image.Size {
		return []byte{}, nil
	}
	if uint64(n) > p.image.Size-off {
		n = int(p.image.Size - off)
	}
	buf := make([]byte, n)
	address, err := memory.Add(p.image.Base, off)
	if err != nil {
		return nil, err
	}
	filled := 0
	for filled < n {
		if err = p.ctx.Err(); err != nil {
			return nil, err
		}
		chunk := n - filled
		if chunk > 4096 {
			chunk = 4096
		}
		got, readErr := p.layer.ReadAt(p.ctx, buf[filled:filled+chunk], address+uint64(filled))
		if readErr != nil {
			if err = p.ctx.Err(); err != nil {
				return nil, err
			}
			if got < 0 || got > chunk {
				return nil, readErr
			}
			failAt := filled + got
			if failAt >= n {
				break
			}
			buf[failAt] = 0
			filled = failAt + 1
			continue
		}
		if got != chunk {
			filled += got
			for filled < n && filled < got+chunk {
				buf[filled] = 0
				filled++
			}
			continue
		}
		filled += chunk
	}
	applyVerPatches(p.image, off, buf)
	return buf, nil
}

func applyVerPatches(image *pe.Image, off uint64, buf []byte) {
	if len(buf) == 0 {
		return
	}
	end := off + uint64(len(buf))
	for _, patch := range image.Patches {
		start, err := strconv.ParseUint(strings.TrimPrefix(patch.Offset, "0x"), 16, 64)
		if err != nil || start >= end || start+uint64(len(patch.Replacement)) <= off {
			continue
		}
		for i, value := range patch.Replacement {
			at := start + uint64(i)
			if at >= off && at < end {
				buf[at-off] = value
			}
		}
	}
}

func dwordAlign(offset, base uint32) uint32 {
	return ((offset + base + 3) & 0xFFFFFFFC) - (base & 0xFFFFFFFC)
}

func containsU32(values []uint32, value uint32) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func bytesAllZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func u16s(data []byte) []uint16 {
	out := make([]uint16, len(data)/2)
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return out
}
