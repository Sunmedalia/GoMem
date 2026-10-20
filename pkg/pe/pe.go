// Package pe plans bounded reconstruction of a mapped Intel PE image. It keeps
// memory-layout slack and rewrites ImageBase and section raw ranges, matching
// the fixed Volatility reconstruction profile rather than an original disk PE.
package pe

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

const MaxImageSize = 256 << 20

type Patch struct {
	Offset      string `json:"offset"`
	Reason      string `json:"reason"`
	Original    []byte `json:"original"`
	Replacement []byte `json:"replacement"`
	offset      uint64
}

type Image struct {
	Base    uint64
	Size    uint64
	Machine uint16
	Patches []Patch
}

func Plan(ctx context.Context, layer memory.MemoryLayer, base uint64) (*Image, error) {
	read := func(offset uint64, n int) ([]byte, error) {
		address, err := memory.Add(base, offset)
		if err != nil {
			return nil, err
		}
		return memory.Read(ctx, layer, address, n)
	}
	dos, err := read(0, 64)
	if err != nil {
		return nil, err
	}
	if string(dos[:2]) != "MZ" {
		return nil, fmt.Errorf("invalid DOS signature")
	}
	nt := uint64(binary.LittleEndian.Uint32(dos[60:]))
	if nt < 64 || nt > 16<<20 {
		return nil, fmt.Errorf("PE header offset exceeds bounds")
	}
	header, err := read(nt, 24)
	if err != nil {
		return nil, err
	}
	if string(header[:4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("invalid NT signature")
	}
	machine := binary.LittleEndian.Uint16(header[4:])
	sections := uint64(binary.LittleEndian.Uint16(header[6:]))
	optional := uint64(binary.LittleEndian.Uint16(header[20:]))
	if sections > 4096 || optional > 4096 || optional < 64 {
		return nil, fmt.Errorf("invalid PE section count/optional header size")
	}
	opt, err := read(nt+24, int(optional))
	if err != nil {
		return nil, err
	}
	magic := binary.LittleEndian.Uint16(opt)
	baseOffset, baseWidth := uint64(28), 4
	switch {
	case machine == 0x14c && magic == 0x10b:
		if optional < 96 || base > 0xffffffff {
			return nil, fmt.Errorf("invalid PE32 header/base")
		}
	case machine == 0x8664 && magic == 0x20b:
		baseOffset, baseWidth = 24, 8
		if optional < 112 {
			return nil, fmt.Errorf("truncated PE32+ header")
		}
	default:
		return nil, fmt.Errorf("unsupported PE machine/magic %#x/%#x", machine, magic)
	}
	align := uint64(binary.LittleEndian.Uint32(opt[32:]))
	size := uint64(binary.LittleEndian.Uint32(opt[56:]))
	headers := uint64(binary.LittleEndian.Uint32(opt[60:]))
	sectionOffset := nt + 24 + optional
	if size == 0 || size > MaxImageSize || size-1 > ^uint64(0)-base || sectionOffset > size || sections*40 > size-sectionOffset || headers < sectionOffset+sections*40 || headers > size {
		return nil, fmt.Errorf("invalid SizeOfImage/headers/section-table bounds")
	}
	if align == 0 || align&(align-1) != 0 || align > 1<<31 {
		return nil, fmt.Errorf("invalid PE section alignment")
	}
	image := &Image{Base: base, Size: size, Machine: machine}
	patch := func(offset uint64, reason string, original, replacement []byte) {
		image.Patches = append(image.Patches, Patch{Offset: fmt.Sprintf("0x%x", offset), Reason: reason, Original: append([]byte(nil), original...), Replacement: append([]byte(nil), replacement...), offset: offset})
	}
	newBase := make([]byte, baseWidth)
	if baseWidth == 4 {
		binary.LittleEndian.PutUint32(newBase, uint32(base))
	} else {
		binary.LittleEndian.PutUint64(newBase, base)
	}
	patch(nt+24+baseOffset, "ImageBase set to mapped load address", opt[baseOffset:baseOffset+uint64(baseWidth)], newBase)
	// The table is bounded independently of the image and read without padding:
	// headers that cannot be interpreted are never fabricated from zeroes.
	table, err := read(sectionOffset, int(sections*40))
	if err != nil {
		return nil, err
	}
	for n := uint64(0); n < sections; n++ {
		section := table[n*40 : n*40+40]
		virtualSize := uint64(binary.LittleEndian.Uint32(section[8:]))
		rva := uint64(binary.LittleEndian.Uint32(section[12:]))
		rawSize := uint64(binary.LittleEndian.Uint32(section[16:]))
		if rva > size || virtualSize > size-rva || rawSize > size {
			return nil, fmt.Errorf("section %d exceeds declared image", n)
		}
		rounded := (virtualSize + align - 1) &^ (align - 1)
		if rounded > 0xffffffff || rounded > size-rva {
			return nil, fmt.Errorf("section %d rounded size exceeds image", n)
		}
		for _, field := range []struct {
			offset uint64
			value  uint64
			reason string
		}{{8, rounded, "VirtualSize rounded to SectionAlignment"}, {16, rounded, "SizeOfRawData follows mapped section size"}, {20, rva, "PointerToRawData follows mapped RVA"}} {
			value := make([]byte, 4)
			binary.LittleEndian.PutUint32(value, uint32(field.value))
			patch(sectionOffset+n*40+field.offset, field.reason, section[field.offset:field.offset+4], value)
		}
	}
	return image, nil
}

// Overlay applies only patches whose source bytes were read successfully. The
// caller's page-granular extraction retains all other failures and padding logs.
func (i *Image) Overlay(source memory.MemoryLayer) memory.MemoryLayer {
	return &overlay{MemoryLayer: source, image: i}
}

type overlay struct {
	memory.MemoryLayer
	image *Image
}

func (o *overlay) ReadAt(ctx context.Context, p []byte, address uint64) (int, error) {
	n, err := o.MemoryLayer.ReadAt(ctx, p, address)
	if n < 0 || n > len(p) {
		return 0, fmt.Errorf("invalid source read count")
	}
	first := sort.Search(len(o.image.Patches), func(index int) bool {
		p := o.image.Patches[index]
		return o.image.Base+p.offset+uint64(len(p.Replacement)) > address
	})
	for _, patch := range o.image.Patches[first:] {
		start := o.image.Base + patch.offset
		if start >= address && start-address >= uint64(n) {
			break
		}
		for x, value := range patch.Replacement {
			a := start + uint64(x)
			if a >= address && a-address < uint64(n) {
				p[a-address] = value
			}
		}
	}
	return n, err
}
