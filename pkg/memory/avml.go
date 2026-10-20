package memory

import (
	"container/list"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"sync"
)

const (
	maxAVMLFrames = 1 << 20
	maxAVMLChunks = 4 << 20
	avmlCacheSize = 128 // At most 8MiB of decoded frames.
)

var snappyCRC = crc32.MakeTable(crc32.Castagnoli)

type avmlFrame struct {
	start, length, offset uint64
	size, checksum        uint32
	compressed            bool
}

type avmlCacheEntry struct {
	index int
	data  []byte
}

type avmlLayer struct {
	source MemorySource
	ranges []Range
	frames []avmlFrame
	mu     sync.Mutex
	lru    *list.List
	cache  map[int]*list.Element
}

func (l *avmlLayer) Name() string    { return "physical:avml-v2" }
func (l *avmlLayer) Ranges() []Range { return append([]Range(nil), l.ranges...) }

func avmlRead(ctx context.Context, source MemorySource, offset uint64, size int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if size < 0 || size > MaxRead || offset > source.Size() || uint64(size) > source.Size()-offset {
		return nil, fmt.Errorf("AVML stored range is truncated or exceeds bounds at %#x", offset)
	}
	data := make([]byte, size)
	n, err := source.ReadAt(ctx, data, offset)
	if err != nil {
		return nil, err
	}
	if n != size {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func openAVML(ctx context.Context, source MemorySource) (*avmlLayer, error) {
	l := &avmlLayer{source: source, lru: list.New(), cache: map[int]*list.Element{}}
	var offset uint64
	chunks := 0
	for offset < source.Size() {
		if len(l.ranges) >= maxAVMLFrames {
			return nil, fmt.Errorf("AVML region index limit exceeded")
		}
		header, err := avmlRead(ctx, source, offset, 32)
		if err != nil {
			return nil, err
		}
		if string(header[:4]) != "AVML" || binary.LittleEndian.Uint32(header[4:]) != 2 || binary.LittleEndian.Uint64(header[24:]) != 0 {
			return nil, fmt.Errorf("invalid AVML magic/version/reserved header at %#x", offset)
		}
		start, end := binary.LittleEndian.Uint64(header[8:]), binary.LittleEndian.Uint64(header[16:])
		if end < start || end == ^uint64(0) {
			return nil, fmt.Errorf("invalid AVML inclusive physical range")
		}
		length := end - start + 1
		offset += 32
		stream := offset
		var decoded uint64
		identified := false
		for decoded < length {
			chunks++
			if chunks > maxAVMLChunks {
				return nil, fmt.Errorf("AVML chunk index limit exceeded")
			}
			h, err := avmlRead(ctx, source, offset, 4)
			if err != nil {
				return nil, err
			}
			kind := h[0]
			size := uint64(binary.LittleEndian.Uint32(h) >> 8)
			body := offset + 4
			if body > source.Size() || size > source.Size()-body {
				return nil, fmt.Errorf("truncated AVML Snappy chunk at %#x", offset)
			}
			if !identified && kind != 255 {
				return nil, fmt.Errorf("AVML Snappy stream identifier must precede data")
			}
			switch {
			case kind == 255:
				if size != 6 {
					return nil, fmt.Errorf("invalid AVML Snappy identifier length")
				}
				id, err := avmlRead(ctx, source, body, 6)
				if err != nil {
					return nil, err
				}
				if string(id) != "sNaPpY" {
					return nil, fmt.Errorf("invalid AVML Snappy identifier")
				}
				identified = true
			case kind == 0 || kind == 1:
				if size < 4 {
					return nil, fmt.Errorf("AVML data chunk has no complete CRC")
				}
				crc, err := avmlRead(ctx, source, body, 4)
				if err != nil {
					return nil, err
				}
				dataSize := int(size - 4)
				output := dataSize
				if kind == 0 {
					prefix, err := avmlRead(ctx, source, body+4, min(dataSize, 5))
					if err != nil {
						return nil, err
					}
					output, _, err = snappyLength(prefix)
					if err != nil {
						return nil, err
					}
				}
				if output > snappyFrameSize || uint64(output) > length-decoded {
					return nil, fmt.Errorf("AVML frame output exceeds its 64KiB/physical region bounds")
				}
				frame := avmlFrame{start: start + decoded, length: uint64(output), offset: body + 4, size: uint32(dataSize), checksum: binary.LittleEndian.Uint32(crc), compressed: kind == 0}
				if output == 0 {
					// Empty frames have no physical address to trigger a later read.
					if _, err := l.decode(ctx, frame); err != nil {
						return nil, err
					}
				} else {
					if len(l.frames) >= maxAVMLFrames {
						return nil, fmt.Errorf("AVML frame index limit exceeded")
					}
					l.frames = append(l.frames, frame)
				}
				decoded += uint64(output)
			case kind < 128:
				return nil, fmt.Errorf("unskippable AVML Snappy chunk type %#x", kind)
			default:
				// Reserved skippable chunks and padding are skipped without
				// interpreting their bytes, as required by Snappy framing.
			}
			offset = body + size
		}
		trailer, err := avmlRead(ctx, source, offset, 8)
		if err != nil {
			return nil, err
		}
		stored := offset - stream
		if binary.LittleEndian.Uint64(trailer) != stored {
			return nil, fmt.Errorf("AVML compressed-length trailer differs at %#x", offset)
		}
		l.ranges = append(l.ranges, Range{Start: start, Length: length, FileOffset: stream, StoredLength: stored, Encoding: "snappy-framed"})
		offset += 8
	}
	if len(l.frames) == 0 {
		return nil, fmt.Errorf("AVML contains no physical data")
	}
	sort.Slice(l.ranges, func(i, j int) bool { return l.ranges[i].Start < l.ranges[j].Start })
	for i, region := range l.ranges {
		if i > 0 && region.Start < l.ranges[i-1].Start+l.ranges[i-1].Length {
			return nil, fmt.Errorf("overlapping AVML physical regions")
		}
	}
	sort.Slice(l.frames, func(i, j int) bool { return l.frames[i].start < l.frames[j].start })
	return l, nil
}

func (l *avmlLayer) decode(ctx context.Context, frame avmlFrame) ([]byte, error) {
	raw, err := avmlRead(ctx, l.source, frame.offset, int(frame.size))
	if err != nil {
		return nil, err
	}
	data := raw
	if frame.compressed {
		data, err = decodeSnappy(ctx, raw)
		if err != nil {
			return nil, err
		}
	}
	if uint64(len(data)) != frame.length {
		return nil, fmt.Errorf("AVML decoded frame length changed")
	}
	crc := crc32.Checksum(data, snappyCRC)
	masked := ((crc >> 15) | (crc << 17)) + uint32(0xa282ead8)
	if masked != frame.checksum {
		return nil, fmt.Errorf("AVML frame CRC32C mismatch at stored offset %#x", frame.offset)
	}
	return data, ctx.Err()
}

func (l *avmlLayer) frame(ctx context.Context, index int) ([]byte, error) {
	// Serializing cache misses bounds scratch allocation even if tasks share
	// this layer. Returned frame bytes are immutable.
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if element := l.cache[index]; element != nil {
		l.lru.MoveToFront(element)
		return element.Value.(avmlCacheEntry).data, nil
	}
	data, err := l.decode(ctx, l.frames[index])
	if err != nil {
		return nil, err
	}
	l.cache[index] = l.lru.PushFront(avmlCacheEntry{index, data})
	if l.lru.Len() > avmlCacheSize {
		last := l.lru.Back()
		delete(l.cache, last.Value.(avmlCacheEntry).index)
		l.lru.Remove(last)
	}
	return data, nil
}

func (l *avmlLayer) ReadAt(ctx context.Context, p []byte, address uint64) (int, error) {
	if len(p) > MaxRead {
		return 0, fmt.Errorf("AVML read exceeds limit")
	}
	if _, err := Add(address, uint64(len(p))); err != nil {
		return 0, err
	}
	n := 0
	for n < len(p) {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		a := address + uint64(n)
		i := sort.Search(len(l.frames), func(i int) bool { return l.frames[i].start > a }) - 1
		if i < 0 || a-l.frames[i].start >= l.frames[i].length {
			return n, &ReadError{a, len(p) - n, l.Name(), ErrUnmapped}
		}
		data, err := l.frame(ctx, i)
		if err != nil {
			return n, &ReadError{a, len(p) - n, l.Name(), err}
		}
		inside := a - l.frames[i].start
		count := copy(p[n:], data[inside:])
		n += count
	}
	return n, ctx.Err()
}
