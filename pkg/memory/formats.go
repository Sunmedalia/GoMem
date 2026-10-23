package memory

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

type sourceReader struct {
	ctx context.Context
	s   MemorySource
}

func (r sourceReader) ReadAt(p []byte, o int64) (int, error) {
	if o < 0 {
		return 0, io.EOF
	}
	return r.s.ReadAt(r.ctx, p, uint64(o))
}

// Detect refuses recognizable unsupported containers instead of treating their headers as RAM.
func Detect(ctx context.Context, s MemorySource) (MemoryLayer, string, error) {
	if source, ok := s.(*VMwareSource); ok {
		layer, err := vmwareImage(ctx, source)
		return layer, "vmware", err
	}
	switch sourceExtension(s.Name()) {
	case ".vmem", ".vmss", ".vmsn":
		return nil, "vmware", fmt.Errorf("%w: VMware pair requires OpenImageSource", ErrUnsupported)
	}
	h := make([]byte, min(s.Size(), 4096))
	n, e := s.ReadAt(ctx, h, 0)
	if e != nil && e != io.EOF && n == 0 {
		return nil, "", e
	}
	h = h[:n]
	switch {
	case bytes.HasPrefix(h, []byte("QEVM")):
		layer, err := qemuImage(ctx, s)
		return layer, "qemu", err
	case len(h) >= 4 && binary.LittleEndian.Uint32(h) == 0x4c694d45:
		return lime(ctx, s)
	case bytes.HasPrefix(h, []byte("\x7fELF")):
		return elfImage(ctx, s)
	case bytes.HasPrefix(h, []byte("PAGE")):
		return crash(ctx, s)
	case bytes.HasPrefix(h, []byte("AVML")):
		l, err := openAVML(ctx, s)
		if err != nil {
			return nil, "avml", err
		}
		return l, "avml", err
	case bytes.HasPrefix(h, []byte{0xd2, 0xbe, 0xd2, 0xbe}), bytes.HasPrefix(h, []byte{0xd0, 0xbe, 0xd2, 0xbe}), bytes.HasPrefix(h, []byte{0xd1, 0xba, 0xd1, 0xba}), bytes.HasPrefix(h, []byte{0xd3, 0xbe, 0xd3, 0xbe}):
		return nil, "virtual-machine", fmt.Errorf("%w: QEMU/VMware saved state", ErrUnsupported)
	case bytes.HasPrefix(h, []byte{0x1f, 0x8b}), bytes.HasPrefix(h, []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0}), bytes.HasPrefix(h, []byte("PK\x03\x04")):
		return nil, "compressed", fmt.Errorf("%w: compressed image; decompress into the case directory first", ErrUnsupported)
	default:
		m, e := NewMapped(s, "physical:raw", []Range{{Start: 0, Length: s.Size(), FileOffset: 0}})
		return m, "raw", e
	}
}
func lime(ctx context.Context, s MemorySource) (MemoryLayer, string, error) {
	var runs []Range
	var off uint64
	for off < s.Size() {
		h := make([]byte, 32)
		if _, e := s.ReadAt(ctx, h, off); e != nil {
			return nil, "lime", fmt.Errorf("LiME header: %w", e)
		}
		if binary.LittleEndian.Uint32(h) != 0x4c694d45 || binary.LittleEndian.Uint32(h[4:]) != 1 {
			return nil, "lime", fmt.Errorf("invalid LiME magic/version at %#x", off)
		}
		start, end := binary.LittleEndian.Uint64(h[8:]), binary.LittleEndian.Uint64(h[16:])
		if end < start || end == math.MaxUint64 {
			return nil, "lime", fmt.Errorf("invalid LiME range")
		}
		n := end - start + 1
		data, e := Add(off, 32)
		if e != nil {
			return nil, "lime", e
		}
		next, e := Add(data, n)
		if e != nil || next > s.Size() {
			return nil, "lime", fmt.Errorf("truncated LiME segment")
		}
		runs = append(runs, Range{Start: start, Length: n, FileOffset: data})
		if len(runs) > 1<<20 {
			return nil, "lime", fmt.Errorf("too many LiME segments")
		}
		off = next
	}
	m, e := NewMapped(s, "physical:lime", runs)
	return m, "lime", e
}
func elfImage(ctx context.Context, s MemorySource) (MemoryLayer, string, error) {
	if err := boundELF(ctx, s); err != nil {
		return nil, "elf", err
	}
	f, e := elf.NewFile(sourceReader{ctx, s})
	if e != nil {
		return nil, "elf", e
	}
	if f.Type != elf.ET_CORE {
		return nil, "elf", fmt.Errorf("ELF is not a memory core")
	}
	if layer, matched, err := xenImage(ctx, s, f); matched {
		return layer, "xen", err
	}
	var runs []Range
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Filesz == 0 {
			continue
		}
		if p.Filesz > p.Memsz {
			return nil, "elf", fmt.Errorf("ELF filesz exceeds memsz")
		}
		runs = append(runs, Range{Start: p.Paddr, Length: p.Filesz, FileOffset: p.Off})
	}
	m, e := NewMapped(s, "physical:elf", runs)
	return m, "elf", e
}
