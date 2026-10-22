// Package memoryscan acquires bounded scan buffers while keeping the original
// virtual/physical source correspondence distinct from scanner coordinates.
package memoryscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// Acquisition records a whole planned read. A failed part's captured prefix is
// hashed but excluded from Data, matching the locked scanner's part semantics.
// BufferOffset is meaningful only when Complete is true.
type Acquisition struct {
	Part         memory.ScanPart
	Captured     uint64
	SHA256       string
	Complete     bool
	BufferOffset uint64
	Error        error
}
type Buffer struct {
	Data  []byte
	Parts []Acquisition
	// Base follows the baseline's end-minus-successful-length calculation. On
	// failed parts it can differ from the actual source virtual address. Parts
	// are authoritative for attribution; Base is only a reported scan coordinate.
	Base     uint64
	Complete bool
}

// Acquire reads physical scan parts, never requesting more than memory.MaxRead
// in one call. It validates the whole plan before I/O and returns incomplete
// coverage together with an error. It never pads or searches failed prefixes.
func Acquire(ctx context.Context, physical memory.MemoryLayer, chunk memory.ScanChunk) (Buffer, error) {
	result := Buffer{Complete: true, Parts: []Acquisition{}}
	if ctx == nil || physical == nil {
		return Buffer{}, fmt.Errorf("scan acquisition requires context and physical layer")
	}
	if err := ctx.Err(); err != nil {
		return Buffer{}, err
	}
	if len(chunk.Parts) > 4096 {
		return Buffer{}, fmt.Errorf("scan part count exceeds 4096")
	}
	var total uint64
	for _, p := range chunk.Parts {
		if p.Length == 0 || p.Length > memory.MaxScanChunk-total {
			return Buffer{}, fmt.Errorf("invalid scan part size or buffer bound")
		}
		end, err := memory.Add(p.Virtual, p.Length)
		if err != nil || end > chunk.End {
			return Buffer{}, fmt.Errorf("scan part outside chunk virtual end")
		}
		if _, err = memory.Add(p.Physical, p.Length); err != nil {
			return Buffer{}, err
		}
		total += p.Length
	}
	if total > chunk.End {
		return Buffer{}, fmt.Errorf("scan coordinate underflow")
	}
	result.Data = make([]byte, 0, int(total))
	var failures []error
	for _, part := range chunk.Parts {
		if err := ctx.Err(); err != nil {
			result.Complete = false
			failures = append(failures, err)
			break
		}
		start := len(result.Data)
		result.Data = result.Data[:start+int(part.Length)]
		var captured uint64
		var fault error
		for captured < part.Length {
			if fault = ctx.Err(); fault != nil {
				break
			}
			length := min(part.Length-captured, uint64(memory.MaxRead))
			n, err := physical.ReadAt(ctx, result.Data[start+int(captured):start+int(captured+length)], part.Physical+captured)
			if n < 0 || uint64(n) > length {
				fault = fmt.Errorf("invalid reader byte count %d for %d", n, length)
				break
			}
			captured += uint64(n)
			if err != nil {
				fault = err
				break
			}
			if uint64(n) != length {
				fault = io.ErrUnexpectedEOF
				break
			}
		}
		if fault == nil {
			fault = ctx.Err()
		}
		digest := sha256.Sum256(result.Data[start : start+int(captured)])
		a := Acquisition{Part: part, Captured: captured, SHA256: hex.EncodeToString(digest[:]), Complete: fault == nil, BufferOffset: uint64(start), Error: fault}
		result.Parts = append(result.Parts, a)
		if fault != nil {
			result.Complete = false
			result.Data = result.Data[:start]
			failures = append(failures, fmt.Errorf("physical scan read %#x+%#x (%d bytes captured): %w", part.Physical, part.Length, captured, fault))
			if ctx.Err() != nil {
				break
			}
		}
	}
	result.Base = chunk.End - uint64(len(result.Data))
	return result, errors.Join(failures...)
}

// Source identifies the bytes behind a slice of the successful scan buffer.
// Offset is relative to that slice, not to Base or an inferred virtual read.
type Source struct {
	Offset   uint64
	Virtual  uint64
	Physical uint64
	Length   uint64
}

// Sources attributes a nonempty matched span to actual acquisitions. Empty
// matches have no source bytes and return an explicit empty list.
func (b Buffer) Sources(start, end int) ([]Source, error) {
	if start < 0 || end < start || end > len(b.Data) {
		return nil, fmt.Errorf("match span outside acquired data")
	}
	sources := []Source{}
	if start == end {
		return sources, nil
	}
	lo, hi := uint64(start), uint64(end)
	var covered uint64
	for _, a := range b.Parts {
		if !a.Complete {
			continue
		}
		if a.BufferOffset > uint64(len(b.Data)) || a.Part.Length > uint64(len(b.Data))-a.BufferOffset {
			return nil, fmt.Errorf("invalid acquisition buffer interval")
		}
		first, last := max(lo, a.BufferOffset), min(hi, a.BufferOffset+a.Part.Length)
		if first >= last {
			continue
		}
		if first-lo != covered {
			return nil, fmt.Errorf("match source coverage has a gap or overlap")
		}
		relative := first - a.BufferOffset
		virtual, err := memory.Add(a.Part.Virtual, relative)
		if err != nil {
			return nil, err
		}
		physical, err := memory.Add(a.Part.Physical, relative)
		if err != nil {
			return nil, err
		}
		sources = append(sources, Source{Offset: first - lo, Virtual: virtual, Physical: physical, Length: last - first})
		covered += last - first
	}
	if covered != hi-lo {
		return nil, fmt.Errorf("match source coverage inconsistent")
	}
	return sources, nil
}
