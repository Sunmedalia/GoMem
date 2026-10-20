package memory

import (
	"context"
	"encoding/binary"
	"fmt"
)

// Windows complete and bitmap dumps use physical page runs. Other dump types
// have different addressing semantics and are rejected before a layer is built.
func crash(ctx context.Context, s MemorySource) (MemoryLayer, string, error) {
	first := make([]byte, 8)
	if _, e := s.ReadAt(ctx, first, 0); e != nil {
		return nil, "crash", e
	}
	size, descriptor, stride, dumpAt := 4096, 100, 8, 3976
	switch string(first) {
	case "PAGEDUMP":
	case "PAGEDU64":
		size, descriptor, stride, dumpAt = 8192, 136, 16, 3992
	default:
		return nil, "crash", fmt.Errorf("invalid Windows dump signature")
	}
	h := make([]byte, size)
	if _, e := s.ReadAt(ctx, h, 0); e != nil {
		return nil, "crash", e
	}
	kind := binary.LittleEndian.Uint32(h[dumpAt:])
	var runs []Range
	switch kind {
	case 1:
		count := int(binary.LittleEndian.Uint32(h[descriptor:]))
		start := descriptor + 8
		if stride == 16 {
			start = descriptor + 16
		}
		if count == 0 || count > (size-start)/stride {
			return nil, "crash", fmt.Errorf("invalid Windows physical run count")
		}
		off := uint64(size)
		for j := 0; j < count; j++ {
			b := h[start+j*stride:]
			base, n := uint64(binary.LittleEndian.Uint32(b)), uint64(binary.LittleEndian.Uint32(b[4:]))
			if stride == 16 {
				base, n = binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint64(b[8:])
			}
			if base > ^uint64(0)/4096 || n > ^uint64(0)/4096 {
				return nil, "crash", fmt.Errorf("Windows physical run overflow")
			}
			runs = append(runs, Range{base * 4096, n * 4096, off})
			var e error
			off, e = Add(off, n*4096)
			if e != nil {
				return nil, "crash", e
			}
		}
	case 5:
		summary := make([]byte, 56)
		if _, e := s.ReadAt(ctx, summary, uint64(size)); e != nil {
			return nil, "crash", e
		}
		if string(summary[:8]) != "SDMPDUMP" && string(summary[:8]) != "FDMPDUMP" {
			return nil, "crash", fmt.Errorf("invalid Windows bitmap summary signature")
		}
		off := binary.LittleEndian.Uint64(summary[32:])
		pages := binary.LittleEndian.Uint64(summary[40:])
		bits := binary.LittleEndian.Uint64(summary[48:])
		bitmapBytes := (bits + 7) / 8
		if bits == 0 || bits > 1<<30 || off < uint64(size)+56+bitmapBytes || off > s.Size() {
			return nil, "crash", fmt.Errorf("invalid Windows bitmap bounds")
		}
		buffer := make([]byte, 4096)
		var mapped uint64
		var current *Range
		for pos := uint64(0); pos < bitmapBytes; {
			n := int(min(uint64(len(buffer)), bitmapBytes-pos))
			if _, e := s.ReadAt(ctx, buffer[:n], uint64(size)+56+pos); e != nil {
				return nil, "crash", e
			}
			for j, v := range buffer[:n] {
				for b := uint(0); b < 8; b++ {
					page := (pos+uint64(j))*8 + uint64(b)
					if page >= bits {
						break
					}
					if v&(1<<b) == 0 {
						current = nil
						continue
					}
					if current == nil {
						if len(runs) >= 1000000 {
							return nil, "crash", fmt.Errorf("too many bitmap segments")
						}
						runs = append(runs, Range{page * 4096, 0, off})
						current = &runs[len(runs)-1]
					}
					current.Length += 4096
					var e error
					off, e = Add(off, 4096)
					if e != nil || off > s.Size() {
						return nil, "crash", fmt.Errorf("truncated Windows bitmap data")
					}
					mapped++
				}
			}
			pos += uint64(n)
		}
		if mapped != pages {
			return nil, "crash", fmt.Errorf("Windows bitmap page count mismatch")
		}
	default:
		return nil, "crash", fmt.Errorf("%w: Windows dump type %#x", ErrUnsupported, kind)
	}
	m, e := NewMapped(s, "physical:crash", runs)
	return m, "crash", e
}
