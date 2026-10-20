package memory

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

// Scan streams overlapping literal matches over enumerated physical ranges.
// Adjacent ranges retain their overlap even when container file offsets differ;
// holes never join. Reads and scratch space are bounded independently of size.
func Scan(ctx context.Context, layer MemoryLayer, needle []byte, emit func(uint64) error) error {
	if len(needle) == 0 || len(needle) > 8192 || emit == nil {
		return fmt.Errorf("literal scan requires a 1..8192 byte needle and an emitter")
	}
	ranges := layer.Ranges()
	if len(ranges) == 0 {
		return fmt.Errorf("literal scan needs explicitly enumerated memory ranges")
	}
	const chunk = 1 << 20
	window := make([]byte, chunk+len(needle)-1)
	tail := 0
	var previousEnd uint64
	for n, r := range ranges {
		end, err := Add(r.Start, r.Length)
		if err != nil || r.Length == 0 || n > 0 && r.Start < previousEnd {
			return fmt.Errorf("invalid or overlapping scan ranges")
		}
		if n == 0 || r.Start != previousEnd {
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
			for from := 0; from <= len(data)-len(needle); {
				index := bytes.Index(data[from:], needle)
				if index < 0 {
					break
				}
				index += from
				address := base + uint64(index)
				if address+uint64(len(needle)) > r.Start+off {
					if err := ctx.Err(); err != nil {
						return err
					}
					if err := emit(address); err != nil {
						return err
					}
				}
				from = index + 1
			}
			tail = min(len(needle)-1, len(data))
			copy(window, data[len(data)-tail:])
			off += uint64(length)
		}
		previousEnd = end
	}
	return ctx.Err()
}
