package memoryscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// BackingChunk is virtually contiguous but can contain several backing sources.
// Matches starting in PrimaryLength belong to this chunk; the remaining bytes
// are overlap for those matches. This avoids duplicate hits at chunk boundaries.
type BackingChunk struct {
	Start, Length, PrimaryLength uint64
	Parts                        []memory.BackingMapping
}

func (c BackingChunk) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Start         string                  `json:"start"`
		Length        uint64                  `json:"length"`
		PrimaryLength uint64                  `json:"primary_length"`
		Parts         []memory.BackingMapping `json:"parts"`
	}{fmt.Sprintf("0x%016x", c.Start), c.Length, c.PrimaryLength, c.Parts})
}

type BackingScanOptions struct {
	Mappings                      memory.BackingMapOptions
	ChunkSize, Overlap, MaxChunks uint64
}
type BackingScanStats struct {
	Mappings             memory.PageMapStats
	Chunks, PrimaryBytes uint64
}
type backingPlanner struct {
	ctx            context.Context
	options        BackingScanOptions
	stats          *BackingScanStats
	out            func(BackingChunk) error
	parts          []memory.BackingMapping
	total, lastEnd uint64
	started        bool
}

// VisitBackingChunks preserves overlap across adjacent RAM/pagefile mappings,
// but never across a virtual gap. Faults retained by mapping callbacks still
// return incomplete-coverage errors after all available chunks are emitted.
func VisitBackingChunks(ctx context.Context, tr *memory.Intel, options BackingScanOptions, out func(BackingChunk) error) (BackingScanStats, error) {
	var stats BackingScanStats
	if ctx == nil || tr == nil || out == nil || options.ChunkSize == 0 || options.Overlap > options.ChunkSize || options.ChunkSize > memory.MaxScanChunk || options.Overlap > memory.MaxScanChunk-options.ChunkSize || options.MaxChunks == 0 || options.MaxChunks > 1000000 {
		return stats, fmt.Errorf("invalid backing scan context, chunk shape or budget")
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	p := &backingPlanner{ctx: ctx, options: options, stats: &stats, out: out}
	var err error
	stats.Mappings, err = tr.VisitBackingMappings(ctx, options.Mappings, p.push)
	if err != nil {
		return stats, err
	}
	if err = p.finish(); err != nil {
		return stats, err
	}
	if stats.Mappings.Unavailable != 0 {
		return stats, fmt.Errorf("%w: backing scan has %d unavailable tables or intervals", memory.ErrUnmapped, stats.Mappings.Unavailable)
	}
	return stats, nil
}
func cloneBacking(m memory.BackingMapping) memory.BackingMapping {
	if m.Pagefile != nil {
		number := *m.Pagefile
		m.Pagefile = &number
	}
	return m
}
func (p *backingPlanner) push(m memory.BackingMapping) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	end, err := memory.Add(m.Virtual, m.Length)
	if err != nil || m.Length == 0 || m.Layer == nil {
		return fmt.Errorf("invalid backing scan mapping")
	}
	if _, err := memory.Add(m.Offset, m.Length); err != nil {
		return err
	}
	if p.started && m.Virtual < p.lastEnd {
		return fmt.Errorf("overlapping backing scan mappings")
	}
	if p.started && m.Virtual != p.lastEnd {
		if err := p.finish(); err != nil {
			return err
		}
	}
	p.started = true
	p.lastEnd = end
	for m.Length != 0 {
		if err := p.ctx.Err(); err != nil {
			return err
		}
		if len(p.parts) >= 4096 {
			return fmt.Errorf("backing scan part count exceeds 4096")
		}
		n := min(m.Length, p.options.ChunkSize+p.options.Overlap-p.total)
		part := cloneBacking(m)
		part.Length = n
		p.parts = append(p.parts, part)
		p.total += n
		m.Virtual += n
		m.Offset += n
		m.Length -= n
		if p.total == p.options.ChunkSize+p.options.Overlap {
			if err := p.emit(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (p *backingPlanner) emit() error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if p.stats.Chunks >= p.options.MaxChunks {
		return fmt.Errorf("backing scan chunk budget exhausted")
	}
	parts := make([]memory.BackingMapping, len(p.parts))
	for n, m := range p.parts {
		parts[n] = cloneBacking(m)
	}
	primary := min(p.options.ChunkSize, p.total)
	if err := p.out(BackingChunk{Start: parts[0].Virtual, Length: p.total, PrimaryLength: primary, Parts: parts}); err != nil {
		return err
	}
	p.stats.Chunks++
	p.stats.PrimaryBytes += primary
	remove := primary
	for remove != 0 {
		if p.parts[0].Length <= remove {
			remove -= p.parts[0].Length
			p.parts = p.parts[1:]
		} else {
			p.parts[0].Virtual += remove
			p.parts[0].Offset += remove
			p.parts[0].Length -= remove
			remove = 0
		}
	}
	p.total -= primary
	return p.ctx.Err()
}
func (p *backingPlanner) finish() error {
	for p.total != 0 {
		if err := p.emit(); err != nil {
			return err
		}
	}
	p.parts = nil
	return nil
}

type BackingCapture struct {
	Mapping  memory.BackingMapping
	Captured uint64
	SHA256   string
	Bytes    []byte
	Complete bool
	Error    error
}

func (c BackingCapture) MarshalJSON() ([]byte, error) {
	message := ""
	if c.Error != nil {
		message = c.Error.Error()
	}
	return json.Marshal(struct {
		Mapping  memory.BackingMapping `json:"mapping"`
		Captured uint64                `json:"captured"`
		SHA256   string                `json:"sha256"`
		Bytes    []byte                `json:"bytes"`
		Complete bool                  `json:"complete"`
		Error    string                `json:"error,omitempty"`
	}{c.Mapping, c.Captured, c.SHA256, c.Bytes, c.Complete, message})
}

type BackingBuffer struct {
	Chunk    BackingChunk
	Data     []byte
	Captures []BackingCapture
	Complete bool
}

// AcquireBacking validates the whole plan before I/O. A failed part makes the
// entire chunk unsearchable (Data nil), retaining original captured prefixes
// and their hashes without joining bytes across failed reads.
func AcquireBacking(ctx context.Context, chunk BackingChunk) (BackingBuffer, error) {
	result := BackingBuffer{Chunk: chunk}
	if ctx == nil {
		return result, fmt.Errorf("backing acquisition requires context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if chunk.Length == 0 || chunk.Length > memory.MaxScanChunk || chunk.PrimaryLength == 0 || chunk.PrimaryLength > chunk.Length || len(chunk.Parts) == 0 || len(chunk.Parts) > 4096 {
		return result, fmt.Errorf("invalid backing acquisition shape")
	}
	parts := make([]memory.BackingMapping, len(chunk.Parts))
	for n, m := range chunk.Parts {
		parts[n] = cloneBacking(m)
	}
	chunk.Parts = parts
	result.Chunk = chunk
	var total uint64
	for _, m := range chunk.Parts {
		start, err := memory.Add(chunk.Start, total)
		if err != nil || m.Virtual != start || m.Layer == nil || m.Unresolved || m.Length == 0 || m.Length > chunk.Length-total || m.Pagefile != nil && *m.Pagefile > 15 {
			return result, fmt.Errorf("invalid backing acquisition part")
		}
		if _, err := memory.Add(m.Offset, m.Length); err != nil {
			return result, err
		}
		total += m.Length
	}
	if total != chunk.Length {
		return result, fmt.Errorf("backing acquisition length mismatch")
	}
	if _, err := memory.Add(chunk.Start, chunk.Length); err != nil {
		return result, err
	}
	raw := make([]byte, int(total))
	result.Complete = true
	var offset uint64
	var failures []error
	for _, m := range chunk.Parts {
		var captured uint64
		var fault error
		for captured < m.Length {
			if fault = ctx.Err(); fault != nil {
				break
			}
			length := min(m.Length-captured, uint64(memory.MaxRead))
			n, err := m.Layer.ReadAt(ctx, raw[offset+captured:offset+captured+length], m.Offset+captured)
			if n < 0 || uint64(n) > length {
				fault = fmt.Errorf("invalid backing reader byte count %d", n)
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
		data := raw[offset : offset+captured]
		sum := sha256.Sum256(data)
		result.Captures = append(result.Captures, BackingCapture{Mapping: cloneBacking(m), Captured: captured, SHA256: hex.EncodeToString(sum[:]), Bytes: data, Complete: fault == nil, Error: fault})
		if fault != nil {
			result.Complete = false
			failures = append(failures, fmt.Errorf("backing read for virtual %#x at source offset %#x: %w", m.Virtual, m.Offset, fault))
		}
		offset += m.Length
		if ctx.Err() != nil {
			break
		}
	}
	if result.Complete {
		result.Data = raw
	}
	return result, errors.Join(failures...)
}

func (b BackingBuffer) Accepts(start, length uint64) bool {
	return b.Complete && length != 0 && start < b.Chunk.PrimaryLength && start <= uint64(len(b.Data)) && length <= uint64(len(b.Data))-start
}

// Sources attributes a successful buffer slice to its original backing bytes.
func (b BackingBuffer) Sources(start, length uint64) ([]memory.BackingMapping, error) {
	if !b.Complete || length == 0 || start > uint64(len(b.Data)) || length > uint64(len(b.Data))-start {
		return nil, fmt.Errorf("slice outside complete backing buffer")
	}
	var sources []memory.BackingMapping
	var offset uint64
	end := start + length
	for _, m := range b.Chunk.Parts {
		lo, hi := max(start, offset), min(end, offset+m.Length)
		if hi > lo {
			part := cloneBacking(m)
			part.Virtual += lo - offset
			part.Offset += lo - offset
			part.Length = hi - lo
			sources = append(sources, part)
		}
		offset += m.Length
	}
	return sources, nil
}
