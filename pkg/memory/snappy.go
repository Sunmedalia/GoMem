package memory

import (
	"context"
	"fmt"
)

const snappyFrameSize = 65536

// snappyLength parses the raw block's uint32 varint, before any allocation.
func snappyLength(raw []byte) (int, int, error) {
	var n uint32
	for i := 0; i < 5 && i < len(raw); i++ {
		b := raw[i]
		if i == 4 && b > 15 {
			return 0, 0, fmt.Errorf("Snappy length varint overflows uint32")
		}
		n |= uint32(b&127) << (7 * i)
		if b < 128 {
			if n > snappyFrameSize {
				return 0, 0, fmt.Errorf("Snappy frame output exceeds 64KiB")
			}
			return int(n), i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("unterminated Snappy length varint")
}

func decodeSnappy(ctx context.Context, raw []byte) ([]byte, error) {
	size, prefix, err := snappyLength(raw)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	raw = raw[prefix:]
	for len(raw) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tag := raw[0]
		raw = raw[1:]
		length, distance := int(tag>>2)+1, uint64(0)
		if tag&3 == 0 {
			if length > 60 {
				width := length - 60
				if len(raw) < width {
					return nil, fmt.Errorf("truncated Snappy literal length")
				}
				var count uint64
				for i := 0; i < width; i++ {
					count |= uint64(raw[i]) << (8 * i)
				}
				raw = raw[width:]
				if count >= uint64(size-len(out)) {
					return nil, fmt.Errorf("Snappy literal exceeds declared output")
				}
				length = int(count) + 1
			}
			if length > len(raw) || length > size-len(out) {
				return nil, fmt.Errorf("truncated or oversized Snappy literal")
			}
			out = append(out, raw[:length]...)
			raw = raw[length:]
			continue
		}
		width := 1
		switch tag & 3 {
		case 1:
			length = 4 + int((tag>>2)&7)
			distance = uint64(tag&0xe0) << 3
		case 2:
			width = 2
		case 3:
			width = 4
		}
		if len(raw) < width {
			return nil, fmt.Errorf("truncated Snappy copy offset")
		}
		for i := 0; i < width; i++ {
			distance |= uint64(raw[i]) << (8 * i)
		}
		raw = raw[width:]
		if distance == 0 || distance > uint64(len(out)) || length > size-len(out) {
			return nil, fmt.Errorf("invalid Snappy copy distance/length")
		}
		// Overlapping backreferences intentionally read the newly appended bytes.
		for i := 0; i < length; i++ {
			out = append(out, out[len(out)-int(distance)])
		}
	}
	if len(out) != size {
		return nil, fmt.Errorf("Snappy output differs from declared length")
	}
	return out, ctx.Err()
}
