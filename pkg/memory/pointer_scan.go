package memory

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// ScanPointers finds every unaligned little-endian pointer in a bounded set in
// one physical pass. Adjacent ranges share the width-1 carry; holes break it.
// Values must be unique and fit the declared 4/8 byte width. The callback gets
// the physical address and matched value, not a container file offset.
func ScanPointers(ctx context.Context, layer MemoryLayer, values []uint64, width int, emit func(uint64, uint64) error) error {
	if width != 4 && width != 8 || len(values) == 0 || len(values) > 4096 || emit == nil {
		return fmt.Errorf("pointer scan requires 1..4096 unique pointers, 4/8 byte width and emitter")
	}
	set := make(map[uint64]bool, len(values))
	var first [256]bool
	for _, v := range values {
		if set[v] || width == 4 && v > 0xffffffff {
			return fmt.Errorf("duplicate or out-of-width scan pointer")
		}
		set[v], first[byte(v)] = true, true
	}
	ranges := layer.Ranges()
	if len(ranges) == 0 {
		return fmt.Errorf("pointer scan requires explicitly enumerated physical ranges")
	}
	const chunk = 1 << 20
	window := make([]byte, chunk+width-1)
	tail := 0
	var previousEnd uint64
	for index, r := range ranges {
		end, err := Add(r.Start, r.Length)
		if err != nil || r.Length == 0 || index > 0 && r.Start < previousEnd {
			return fmt.Errorf("invalid pointer scan ranges")
		}
		if index == 0 || r.Start != previousEnd {
			tail = 0
		}
		for off := uint64(0); off < r.Length; {
			if err := ctx.Err(); err != nil {
				return err
			}
			length := int(min(uint64(chunk), r.Length-off))
			got, err := layer.ReadAt(ctx, window[tail:tail+length], r.Start+off)
			if err != nil {
				return err
			}
			if got != length {
				return &ReadError{Address: r.Start + off, Length: length, Layer: layer.Name(), Cause: io.ErrUnexpectedEOF}
			}
			data := window[:tail+length]
			base := r.Start + off - uint64(tail)
			for n := 0; n+width <= len(data); n++ {
				if n&4095 == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				if !first[data[n]] {
					continue
				}
				var value uint64
				if width == 4 {
					value = uint64(binary.LittleEndian.Uint32(data[n:]))
				} else {
					value = binary.LittleEndian.Uint64(data[n:])
				}
				if set[value] {
					if err := ctx.Err(); err != nil {
						return err
					}
					if err := emit(base+uint64(n), value); err != nil {
						return err
					}
				}
			}
			tail = min(width-1, len(data))
			copy(window, data[len(data)-tail:])
			off += uint64(length)
		}
		previousEnd = end
	}
	return ctx.Err()
}
