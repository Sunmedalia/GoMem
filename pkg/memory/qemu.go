package memory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// QEMUHeader describes the migration stream, not recovered CPU state.
type QEMUHeader struct {
	Version         uint32 `json:"version"`
	Machine         string `json:"machine"`
	PageSize        uint64 `json:"page_size"`
	Pages           uint64 `json:"pages"`
	Updates         uint64 `json:"updates"`
	CompressedPages uint64 `json:"compressed_pages"`
	PCIHoleStart    uint64 `json:"pci_hole_start"`
	PCIHoleEnd      uint64 `json:"pci_hole_end"`
}
type QEMULayer struct {
	source MemorySource
	ranges []Range
	header QEMUHeader
}

func (l *QEMULayer) Name() string           { return "physical:qemu" }
func (l *QEMULayer) Ranges() []Range        { return append([]Range(nil), l.ranges...) }
func (l *QEMULayer) QEMUHeader() QEMUHeader { return l.header }
func (l *QEMULayer) ReadAt(ctx context.Context, p []byte, address uint64) (int, error) {
	if len(p) > MaxRead {
		return 0, fmt.Errorf("QEMU read exceeds budget")
	}
	if _, err := Add(address, uint64(len(p))); err != nil {
		return 0, err
	}
	n := 0
	for n < len(p) {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		at := address + uint64(n)
		i := sort.Search(len(l.ranges), func(i int) bool { return l.ranges[i].Start+l.ranges[i].Length > at })
		if i == len(l.ranges) || at < l.ranges[i].Start {
			return n, &ReadError{at, len(p) - n, l.Name(), ErrUnmapped}
		}
		r := l.ranges[i]
		count := min(uint64(len(p)-n), r.Length-(at-r.Start))
		if r.Encoding == "qemu-fill" {
			var value [1]byte
			got, err := l.source.ReadAt(ctx, value[:], r.FileOffset)
			if err != nil {
				return n, err
			}
			if got != 1 {
				return n, io.ErrUnexpectedEOF
			}
			for j := 0; j < int(count); j++ {
				p[n+j] = value[0]
			}
			n += int(count)
		} else {
			got, err := l.source.ReadAt(ctx, p[n:n+int(count)], r.FileOffset+at-r.Start)
			n += got
			if err != nil {
				return n, err
			}
			if uint64(got) != count {
				return n, io.ErrUnexpectedEOF
			}
		}
	}
	return n, nil
}

// A single bounded tile amortizes small migration metadata reads. Page payloads
// are indexed and never decoded or retained while assembling the layer.
type qemuReader struct {
	ctx    context.Context
	source MemorySource
	pos    uint64
	tile   []byte
	start  uint64
}

func (r *qemuReader) read(n int) ([]byte, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if n < 0 || n > MaxRead || r.pos > r.source.Size() || uint64(n) > r.source.Size()-r.pos {
		return nil, fmt.Errorf("truncated QEMU stream at %#x", r.pos)
	}
	out := make([]byte, n)
	for copied := 0; copied < n; {
		if r.tile == nil || r.pos < r.start || r.pos-r.start >= uint64(len(r.tile)) {
			r.start = r.pos &^ uint64(65535)
			r.tile = make([]byte, min(uint64(65536), r.source.Size()-r.start))
			got, err := r.source.ReadAt(r.ctx, r.tile, r.start)
			if err != nil {
				return nil, err
			}
			if got != len(r.tile) {
				return nil, io.ErrUnexpectedEOF
			}
		}
		got := copy(out[copied:], r.tile[r.pos-r.start:])
		copied += got
		r.pos += uint64(got)
	}
	return out, nil
}
func (r *qemuReader) integer(n int) (uint64, error) {
	b, err := r.read(n)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return uint64(b[0]), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(b)), nil
	case 8:
		return binary.BigEndian.Uint64(b), nil
	}
	return 0, fmt.Errorf("invalid integer width")
}
func (r *qemuReader) skip(n uint64) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if r.pos > r.source.Size() || n > r.source.Size()-r.pos {
		return fmt.Errorf("truncated QEMU payload")
	}
	r.pos += n
	return nil
}
func (r *qemuReader) name() (string, error) {
	n, err := r.integer(1)
	if err != nil {
		return "", err
	}
	b, err := r.read(int(n))
	if err != nil {
		return "", err
	}
	if n == 0 || bytes.IndexByte(b, 0) >= 0 {
		return "", fmt.Errorf("invalid QEMU identifier")
	}
	return string(b), nil
}

type qemuDevice struct {
	Name        string       `json:"name"`
	VMSDName    string       `json:"vmsd_name"`
	Instance    uint64       `json:"instance_id"`
	Version     uint64       `json:"version"`
	Fields      []qemuField  `json:"fields"`
	Subsections []qemuDevice `json:"subsections"`
}
type qemuField struct {
	Type        string      `json:"type"`
	Size        *uint64     `json:"size"`
	ArrayLength *uint64     `json:"array_len"`
	Struct      *qemuDevice `json:"struct"`
}
type qemuDescription struct {
	PageSize uint64       `json:"page_size"`
	Devices  []qemuDevice `json:"devices"`
}

// Skip only payloads whose byte layout is explicitly declared by the captured
// VM description. Resource limits apply to expanded arrays and nested structs.
func qemuSkipDevice(r *qemuReader, device *qemuDevice, depth int, budget *uint64) error {
	if depth > 64 {
		return fmt.Errorf("QEMU device nesting exceeds 64")
	}
	if device.Fields == nil {
		return fmt.Errorf("QEMU device has no declared field layout")
	}
	for _, field := range device.Fields {
		count := uint64(1)
		if field.ArrayLength != nil {
			count = *field.ArrayLength
		}
		if count > 1<<20 || *budget > 1<<20-count {
			return fmt.Errorf("QEMU device field budget exceeded")
		}
		*budget += count
		for i := uint64(0); i < count; i++ {
			if field.Type == "struct" {
				if field.Struct == nil {
					return fmt.Errorf("QEMU struct field has no layout")
				}
				if err := qemuSkipDevice(r, field.Struct, depth+1, budget); err != nil {
					return err
				}
			} else if field.Type == "capability" {
				if _, err := r.name(); err != nil {
					return err
				}
			} else {
				if field.Size == nil {
					return fmt.Errorf("QEMU field has no captured size")
				}
				if err := r.skip(*field.Size); err != nil {
					return err
				}
			}
		}
	}
	for i := range device.Subsections {
		subsection := &device.Subsections[i]
		kind, err := r.integer(1)
		if err != nil {
			return err
		}
		if kind != 5 {
			return fmt.Errorf("missing QEMU device subsection")
		}
		name, err := r.name()
		if err != nil {
			return err
		}
		version, err := r.integer(4)
		if err != nil {
			return err
		}
		if name != subsection.VMSDName || version != subsection.Version {
			return fmt.Errorf("QEMU subsection identity/version mismatch")
		}
		if err := qemuSkipDevice(r, subsection, depth+1, budget); err != nil {
			return err
		}
	}
	return nil
}

// Locate a length-framed VM description at the tail. The parser later verifies
// that the selected frame actually follows EOF, so RAM bytes cannot impersonate it.
func qemuTail(ctx context.Context, s MemorySource) (qemuDescription, uint64, error) {
	var description qemuDescription
	length := min(s.Size(), uint64(MaxRead))
	start := s.Size() - length
	tail := make([]byte, int(length))
	n, err := s.ReadAt(ctx, tail, start)
	if err != nil {
		return description, 0, err
	}
	if n != len(tail) {
		return description, 0, io.ErrUnexpectedEOF
	}
	end := len(bytes.TrimRight(tail, "\x00"))
	for i := end - 6; i >= 0; i-- {
		if tail[i] != 6 || tail[i+5] != '{' {
			continue
		}
		size := uint64(binary.BigEndian.Uint32(tail[i+1:]))
		if size != uint64(end-i-5) {
			continue
		}
		if err := json.Unmarshal(tail[i+5:end], &description); err != nil {
			return description, 0, fmt.Errorf("invalid QEMU VM description: %w", err)
		}
		if len(description.Devices) > 65536 {
			return description, 0, fmt.Errorf("QEMU device description budget exceeded")
		}
		if description.PageSize == 0 {
			description.PageSize = 4096
		}
		if description.PageSize < 512 || description.PageSize > 1<<20 || description.PageSize&(description.PageSize-1) != 0 {
			return description, 0, fmt.Errorf("invalid QEMU page size")
		}
		return description, start + uint64(i), nil
	}
	return description, 0, fmt.Errorf("QEMU VM description missing or exceeds 16MiB tail budget")
}

var qemuMachinePattern = regexp.MustCompile(`pc-(?:i440fx|q35)-[A-Za-z0-9_.{}]+`)

func qemuMachineFallback(ctx context.Context, s MemorySource, d qemuDescription) (string, error) {
	// Chunked scan with overlap mirrors the fixed baseline's first identifier search.
	var carry []byte
	for offset := uint64(0); offset < s.Size(); {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		size := min(uint64(1<<20), s.Size()-offset)
		data := make([]byte, int(size))
		n, err := s.ReadAt(ctx, data, offset)
		if err != nil {
			return "", err
		}
		if uint64(n) != size {
			return "", io.ErrUnexpectedEOF
		}
		combined := append(carry, data...)
		if match := qemuMachinePattern.Find(combined); match != nil {
			return string(match), nil
		}
		carry = bytes.Clone(combined[max(0, len(combined)-256):])
		offset += size
	}
	for _, device := range d.Devices {
		name := strings.ToLower(device.VMSDName)
		if strings.Contains(name, "i440fx") || strings.Contains(name, "piix") {
			return "pc-i440fx-2.0", nil
		}
		if strings.Contains(name, "ich9") {
			return "pc-q35-2.0", nil
		}
	}
	// Retain a bounded fallback scan for firmware's Standard PC description.
	for _, kind := range []struct{ pattern, machine string }{{"Standard PC (i440FX", "pc-i440fx-2.0"}, {"Standard PC (Q35", "pc-q35-2.0"}} {
		found := false
		// Scan works on an ordinary linear source layer and preserves chunk boundaries.
		layer, err := NewMapped(s, "qemu:source", []Range{{Length: s.Size()}})
		if err != nil {
			return "", err
		}
		err = Scan(ctx, layer, []byte(kind.pattern), func(uint64) error { found = true; return nil })
		if err != nil {
			return "", err
		}
		if found {
			return kind.machine, nil
		}
	}
	return "", nil
}
func qemuHole(machine string) (minimum, start, end uint64) {
	switch {
	case strings.HasPrefix(machine, "pc-i440fx-0."), strings.HasPrefix(machine, "pc-i440fx-1."):
		return 0xe0000000, 0xe0000000, 0x100000000
	case strings.HasPrefix(machine, "pc-i440fx-"):
		return 0xe0000000, 0xc0000000, 0x100000000
	case strings.HasPrefix(machine, "pc-q35-"):
		return 0xb0000000, 0x80000000, 0x100000000
	case machine == "microvm":
		return 0xc0000000, 0xc0000000, 0x100000000
	case machine == "xen":
		return 0xf0000000, 0xf0000000, 0x100000000
	}
	return 0, 0, 0
}
func qemuImage(ctx context.Context, s MemorySource) (*QEMULayer, error) {
	r := &qemuReader{ctx: ctx, source: s}
	header, err := r.read(8)
	if err != nil {
		return nil, err
	}
	if string(header[:4]) != "QEVM" || binary.BigEndian.Uint32(header[4:]) != 3 {
		return nil, fmt.Errorf("unsupported QEMU magic/version")
	}
	description, descriptionOffset, err := qemuTail(ctx, s)
	if err != nil {
		return nil, err
	}
	l := &QEMULayer{source: s, header: QEMUHeader{Version: 3, PageSize: description.PageSize}}
	type section struct {
		name     string
		version  uint64
		instance uint64
	}
	sections := map[uint64]section{}
	pages := map[uint64]Range{}
	var currentID uint64
	var haveSection bool
	var currentBlock string
	var machineSet bool
	var minimum, holeStart, holeEnd uint64
	var pcRAMSize uint64
	var haveRAMSize bool
	var records uint64
	var deviceFields uint64
	ram := func() error {
		for {
			records++
			if records > 1<<26 {
				return fmt.Errorf("QEMU RAM record budget exceeded")
			}
			value, err := r.integer(8)
			if err != nil {
				return err
			}
			flags := value & (description.PageSize - 1)
			address := value &^ (description.PageSize - 1)
			switch {
			case flags == 4:
				remaining := address
				sizes := map[string]bool{}
				for remaining > 0 {
					if len(sizes) >= 65536 {
						return fmt.Errorf("QEMU RAM block budget exceeded")
					}
					name, err := r.name()
					if err != nil {
						return err
					}
					size, err := r.integer(8)
					if err != nil {
						return err
					}
					if sizes[name] || size == 0 || size > remaining || size%description.PageSize != 0 {
						return fmt.Errorf("invalid QEMU RAM block size")
					}
					sizes[name] = true
					remaining -= size
					if name == "pc.ram" {
						if haveRAMSize && pcRAMSize != size {
							return fmt.Errorf("QEMU RAM resized during migration")
						}
						pcRAMSize = size
						haveRAMSize = true
					}
				}
				if haveRAMSize && pcRAMSize < minimum {
					holeStart, holeEnd = 0, 0
				}
			case flags == 16:
				return nil
			case flags == 2 || flags == 8 || flags == 34 || flags == 40:
				if flags&32 == 0 {
					currentBlock, err = r.name()
					if err != nil {
						return err
					}
				} else if currentBlock == "" {
					return fmt.Errorf("QEMU CONTINUE without RAM block")
				}
				stored := description.PageSize
				if flags&2 != 0 {
					stored = 1
				}
				fileOffset := r.pos
				if err := r.skip(stored); err != nil {
					return err
				}
				if currentBlock != "pc.ram" {
					continue
				}
				if haveRAMSize && (address >= pcRAMSize || description.PageSize > pcRAMSize-address) {
					return fmt.Errorf("QEMU page beyond declared pc.ram")
				}
				if !machineSet {
					return fmt.Errorf("QEMU machine configuration unresolved")
				}
				if minimum == 0 && (!haveRAMSize || pcRAMSize > 0x80000000) {
					return fmt.Errorf("unknown QEMU machine with ambiguous physical mapping")
				}
				if address >= holeStart {
					address, err = Add(address, holeEnd-holeStart)
					if err != nil {
						return err
					}
				}
				if _, err = Add(address, description.PageSize); err != nil {
					return err
				}
				run := Range{Start: address, Length: description.PageSize, FileOffset: fileOffset}
				if stored == 1 {
					run.Encoding = "qemu-fill"
					run.StoredLength = 1
				}
				if _, exists := pages[address]; exists {
					l.header.Updates++
				} else if len(pages) >= 1<<24 {
					return fmt.Errorf("QEMU page index budget exceeded")
				}
				pages[address] = run
			default:
				return fmt.Errorf("unsupported QEMU RAM flags %#x (XBZRLE, hooks and mapped RAM are not decoded)", flags)
			}
		}
	}
	for count := 0; count < 1<<20; count++ {
		kind, err := r.integer(1)
		if err != nil {
			return nil, err
		}
		if kind == 0 {
			if r.pos != descriptionOffset {
				return nil, fmt.Errorf("QEMU VM description does not follow EOF")
			}
			if len(pages) == 0 {
				return nil, fmt.Errorf("QEMU contains no pc.ram pages")
			}
			l.header.Pages = uint64(len(pages))
			l.header.PCIHoleStart, l.header.PCIHoleEnd = holeStart, holeEnd
			for _, page := range pages {
				if page.Encoding != "" {
					l.header.CompressedPages++
				}
				l.ranges = append(l.ranges, page)
			}
			sort.Slice(l.ranges, func(i, j int) bool { return l.ranges[i].Start < l.ranges[j].Start })
			// Coalesce contiguous uncompressed pages; encoded pages retain explicit provenance.
			runs := l.ranges[:0]
			for _, page := range l.ranges {
				if len(runs) > 0 {
					last := &runs[len(runs)-1]
					if last.Encoding == "" && page.Encoding == "" && last.Start+last.Length == page.Start && last.FileOffset+last.Length == page.FileOffset {
						last.Length += page.Length
						continue
					}
				}
				runs = append(runs, page)
			}
			l.ranges = runs
			return l, nil
		}
		if kind == 7 {
			if machineSet || haveSection {
				return nil, fmt.Errorf("duplicate or late QEMU configuration")
			}
			size, err := r.integer(4)
			if err != nil {
				return nil, err
			}
			if size == 0 || size > 4096 {
				return nil, fmt.Errorf("QEMU machine identifier size invalid")
			}
			machine, err := r.read(int(size))
			if err != nil {
				return nil, err
			}
			if bytes.IndexByte(machine, 0) >= 0 {
				return nil, fmt.Errorf("invalid QEMU machine identifier")
			}
			l.header.Machine = string(machine)
			minimum, holeStart, holeEnd = qemuHole(l.header.Machine)
			machineSet = true
			continue
		}
		if !machineSet {
			machine, err := qemuMachineFallback(ctx, s, description)
			if err != nil {
				return nil, err
			}
			l.header.Machine = machine
			minimum, holeStart, holeEnd = qemuHole(machine)
			machineSet = true
		}
		if kind == 0x7e {
			id, err := r.integer(4)
			if err != nil {
				return nil, err
			}
			if !haveSection || id != currentID {
				return nil, fmt.Errorf("QEMU section footer mismatch")
			}
			continue
		}
		if kind < 1 || kind > 4 {
			return nil, fmt.Errorf("unsupported QEMU section %#x", kind)
		}
		id, err := r.integer(4)
		if err != nil {
			return nil, err
		}
		currentID = id
		haveSection = true
		var info section
		if kind == 1 || kind == 4 {
			if len(sections) >= 65536 {
				return nil, fmt.Errorf("QEMU section index budget exceeded")
			}
			if _, exists := sections[id]; exists {
				return nil, fmt.Errorf("duplicate QEMU section ID")
			}
			info.name, err = r.name()
			if err != nil {
				return nil, err
			}
			if info.instance, err = r.integer(4); err != nil {
				return nil, err
			}
			info.version, err = r.integer(4)
			if err != nil {
				return nil, err
			}
			sections[id] = info
		} else {
			var exists bool
			info, exists = sections[id]
			if !exists {
				return nil, fmt.Errorf("QEMU part references unknown section")
			}
		}
		switch info.name {
		case "ram":
			if info.version != 4 {
				return nil, fmt.Errorf("unsupported QEMU RAM version %d", info.version)
			}
			if err := ram(); err != nil {
				return nil, err
			}
		case "pbs-state":
			size, err := r.integer(8)
			if err != nil {
				return nil, err
			}
			if err := r.skip(size); err != nil {
				return nil, err
			}
		case "dirty-bitmap":
			if err := r.skip(1); err != nil {
				return nil, err
			}
		case "spapr/htab":
			if info.version != 1 {
				return nil, fmt.Errorf("unsupported QEMU HTAB version")
			}
			value, err := r.integer(4)
			if err != nil {
				return nil, err
			}
			if value == 0 { // Actual stream contains chunk entries, ending in three zero fields.
				for i := 0; ; i++ {
					if i >= 1<<20 {
						return nil, fmt.Errorf("QEMU HTAB budget exceeded")
					}
					chunk, err := r.read(8)
					if err != nil {
						return nil, err
					}
					index := binary.BigEndian.Uint32(chunk)
					valid := binary.BigEndian.Uint16(chunk[4:])
					invalid := binary.BigEndian.Uint16(chunk[6:])
					if index == 0 && valid == 0 && invalid == 0 {
						break
					}
					if err := r.skip(uint64(valid) * 16); err != nil {
						return nil, err
					}
				}
			}
		default:
			var matched *qemuDevice
			for i := range description.Devices {
				device := &description.Devices[i]
				if device.Name == info.name && device.Instance == info.instance {
					if matched != nil {
						return nil, fmt.Errorf("ambiguous QEMU device description")
					}
					matched = device
				}
			}
			if matched == nil || matched.Version != info.version || kind != 4 {
				return nil, fmt.Errorf("unsupported QEMU device section %q: payload boundary is unknown", info.name)
			}
			if err := qemuSkipDevice(r, matched, 0, &deviceFields); err != nil {
				return nil, err
			}

		}
	}
	return nil, fmt.Errorf("QEMU section budget exceeded")
}
