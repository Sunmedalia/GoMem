// Package elfimage plans bounded extraction of mapped ELF load segments.
// Mapped extraction concatenates page-rounded memory ranges without rewriting
// headers. RebuildModule separately implements the pinned kernel-module ELF
// reconstruction format, with explicit symbol and section-header rewriting.
package elfimage

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

const (
	MaxHeaders = 4096
	MaxSize    = uint64(1<<32 - 1)
	Mapped     = "mapped"
	Reference  = "reference"
)

type Segment struct {
	Index                                      uint16
	Offset, Vaddr, FileSize, MemorySize, Align uint64
	Flags                                      uint32
}

type Image struct {
	Base, Entry   uint64
	Class         byte
	Order         string
	Type, Machine uint16
	Segments      []Segment
	headerSize    uint64
}

type Span struct {
	Segment              Segment
	Source, Offset, Size uint64
}

type Extraction struct {
	Image  *Image
	Layout string
	Size   uint64
	Spans  []Span
}

func Parse(ctx context.Context, layer memory.MemoryLayer, base uint64) (*Image, error) {
	read := func(offset uint64, size int) ([]byte, error) {
		address, err := memory.Add(base, offset)
		if err != nil {
			return nil, err
		}
		if size > 0 && uint64(size)-1 > ^uint64(0)-address {
			return nil, fmt.Errorf("ELF header read interval overflows")
		}
		return memory.Read(ctx, layer, address, size)
	}
	ident, err := read(0, 16)
	if err != nil {
		return nil, err
	}
	if string(ident[:4]) != "\x7fELF" || ident[6] != 1 {
		return nil, fmt.Errorf("invalid ELF identity/version")
	}
	var order binary.ByteOrder
	orderName := "little"
	switch ident[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order, orderName = binary.BigEndian, "big"
	default:
		return nil, fmt.Errorf("invalid ELF byte order")
	}
	headerSize, phdrSize := uint64(64), uint64(56)
	if ident[4] == 1 {
		headerSize, phdrSize = 52, 32
	} else if ident[4] != 2 {
		return nil, fmt.Errorf("invalid ELF class")
	}
	header, err := read(0, int(headerSize))
	if err != nil {
		return nil, err
	}
	image := &Image{Base: base, Class: ident[4], Order: orderName, Type: order.Uint16(header[16:]), Machine: order.Uint16(header[18:]), headerSize: headerSize}
	if image.Type != 2 && image.Type != 3 || order.Uint32(header[20:]) != 1 {
		return nil, fmt.Errorf("unsupported ELF type/version")
	}
	var phoff uint64
	var ehsize, entsize, count uint16
	if image.Class == 1 {
		image.Entry, phoff = uint64(order.Uint32(header[24:])), uint64(order.Uint32(header[28:]))
		ehsize, entsize, count = order.Uint16(header[40:]), order.Uint16(header[42:]), order.Uint16(header[44:])
	} else {
		image.Entry, phoff = order.Uint64(header[24:]), order.Uint64(header[32:])
		ehsize, entsize, count = order.Uint16(header[52:]), order.Uint16(header[54:]), order.Uint16(header[56:])
	}
	// No extended section-table count lookup or arbitrary sparse header reads.
	if uint64(ehsize) != headerSize || uint64(entsize) != phdrSize || count == 0 || count > MaxHeaders || phoff < headerSize || phoff > 16<<20 {
		return nil, fmt.Errorf("invalid or unsupported ELF program-header bounds")
	}
	table, err := read(phoff, int(uint64(count)*phdrSize))
	if err != nil {
		return nil, err
	}
	for index := uint16(0); index < count; index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h := table[uint64(index)*phdrSize:][:phdrSize]
		if order.Uint32(h) != 1 {
			continue
		} // PT_LOAD
		s := Segment{Index: index}
		if image.Class == 1 {
			s.Offset, s.Vaddr = uint64(order.Uint32(h[4:])), uint64(order.Uint32(h[8:]))
			s.FileSize, s.MemorySize = uint64(order.Uint32(h[16:])), uint64(order.Uint32(h[20:]))
			s.Flags, s.Align = order.Uint32(h[24:]), uint64(order.Uint32(h[28:]))
		} else {
			s.Flags, s.Offset, s.Vaddr = order.Uint32(h[4:]), order.Uint64(h[8:]), order.Uint64(h[16:])
			s.FileSize, s.MemorySize, s.Align = order.Uint64(h[32:]), order.Uint64(h[40:]), order.Uint64(h[48:])
		}
		if s.FileSize > s.MemorySize || s.MemorySize > ^uint64(0)-s.Vaddr || s.FileSize > ^uint64(0)-s.Offset || s.Align > 1 && (s.Align&(s.Align-1) != 0 || s.Offset%s.Align != s.Vaddr%s.Align) {
			return nil, fmt.Errorf("invalid ELF PT_LOAD %d interval/alignment", index)
		}
		image.Segments = append(image.Segments, s)
	}
	if len(image.Segments) == 0 {
		return nil, fmt.Errorf("ELF has no PT_LOAD segments")
	}
	return image, nil
}

func (image *Image) Plan(layout string, maxSize uint64) (*Extraction, error) {
	if layout != Mapped && layout != Reference || maxSize == 0 || maxSize > MaxSize {
		return nil, fmt.Errorf("invalid ELF extraction layout/size limit")
	}
	var anchor uint64
	anchors := 0
	for _, s := range image.Segments {
		if s.Offset == 0 && s.FileSize >= image.headerSize && s.Vaddr&4095 == 0 {
			anchor = s.Vaddr
			anchors++
		}
	}
	if layout == Mapped && (anchors != 1 || image.Base&4095 != 0 || image.Type == 2 && anchor != image.Base) {
		return nil, fmt.Errorf("cannot establish unambiguous mapped ELF header load address")
	}
	// Preserve the baseline's last-header-wins rule for equal rounded starts.
	byStart := map[uint64]Span{}
	for _, s := range image.Segments {
		if s.MemorySize == 0 {
			if layout == Mapped {
				continue
			}
		}
		start, end := s.Vaddr&^uint64(4095), s.Vaddr+s.MemorySize
		if end&4095 != 0 {
			if end > ^uint64(0)-4095 {
				return nil, fmt.Errorf("ELF page rounding overflows")
			}
			end = (end + 4095) &^ uint64(4095)
		}
		size := end - start
		if size > maxSize {
			return nil, fmt.Errorf("ELF PT_LOAD %d exceeds size limit", s.Index)
		}
		if size == 0 {
			continue
		}
		var source uint64
		var err error
		if layout == Reference {
			source, err = memory.Add(image.Base, start)
		} else if start >= anchor {
			source, err = memory.Add(image.Base, start-anchor)
		} else if anchor-start > image.Base {
			err = fmt.Errorf("ELF mapped load address underflows")
		} else {
			source = image.Base - (anchor - start)
		}
		if err != nil {
			return nil, err
		}
		if size-1 > ^uint64(0)-source {
			return nil, fmt.Errorf("ELF source interval overflows")
		}
		byStart[start] = Span{Segment: s, Source: source, Size: size}
	}
	keys := make([]uint64, 0, len(byStart))
	for start := range byStart {
		keys = append(keys, start)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	plan := &Extraction{Image: image, Layout: layout}
	for _, key := range keys {
		span := byStart[key]
		if span.Size > maxSize-plan.Size {
			return nil, fmt.Errorf("ELF total extraction exceeds size limit")
		}
		span.Offset = plan.Size
		plan.Size += span.Size
		plan.Spans = append(plan.Spans, span)
	}
	if plan.Size == 0 {
		return nil, fmt.Errorf("ELF extraction has no nonempty load segments")
	}
	return plan, nil
}

// Evidence uses strings for all addresses, lengths and offsets; no JSON float
// conversion can discard an address or a source-to-output relationship.
func (p *Extraction) Evidence() map[string]any {
	hex := func(v uint64) string { return fmt.Sprintf("0x%x", v) }
	segments := make([]map[string]string, 0, len(p.Spans))
	for _, s := range p.Spans {
		segments = append(segments, map[string]string{"program_header": fmt.Sprint(s.Segment.Index), "source": hex(s.Source), "output_offset": hex(s.Offset), "length": hex(s.Size), "p_offset": hex(s.Segment.Offset), "p_vaddr": hex(s.Segment.Vaddr), "p_filesz": hex(s.Segment.FileSize), "p_memsz": hex(s.Segment.MemorySize), "p_align": hex(s.Segment.Align), "p_flags": hex(uint64(s.Segment.Flags))})
	}
	return map[string]any{"layout": p.Layout, "format": "page-rounded-PT_LOAD-concatenation", "base": hex(p.Image.Base), "class": fmt.Sprint(p.Image.Class), "byte_order": p.Image.Order, "type": fmt.Sprint(p.Image.Type), "machine": fmt.Sprint(p.Image.Machine), "entry": hex(p.Image.Entry), "size": hex(p.Size), "segments": segments, "headers_rewritten": false}
}
