package memory

import (
	"context"
	"fmt"
)

// ScanPart binds a planned layer read to its coalesced physical mapping.
// Virtual uses the caller's scan coordinates (48-bit coordinates for the
// pinned x64 iterator); callers canonicalize individual virtual acquisitions.
type ScanPart struct {
	Virtual  uint64 `json:"virtual"`
	Physical uint64 `json:"physical"`
	Length   uint64 `json:"length"`
}
type ScanChunk struct {
	End   uint64     `json:"end"`
	Parts []ScanPart `json:"parts"`
}

// MaxScanChunk bounds planned buffers independently of individual MaxRead reads.
// Acquisition must split a larger part into bounded reads without changing its
// all-or-nothing part success semantics.
const MaxScanChunk = 32 << 20

type ScanPlanOptions struct {
	ChunkSize, Overlap, MaxChunks uint64
}

// ScanPlanner streams the locked Intel translation-layer chunk order for one
// coalesced section. Separate physical mapping runs stay separate even when
// their virtual addresses touch. A first mapping above zero produces the
// baseline's initial empty chunk ending at zero. Finish must be called before
// planning another section with a new planner. This type performs no reads.
type ScanPlanner struct {
	ctx                         context.Context
	options                     ScanPlanOptions
	out                         func(ScanChunk) error
	pending                     ScanChunk
	hasPending, started, closed bool
	lastEnd, chunks             uint64
	stop                        error
}

func NewScanPlanner(ctx context.Context, options ScanPlanOptions, out func(ScanChunk) error) (*ScanPlanner, error) {
	if ctx == nil || out == nil || options.ChunkSize == 0 || options.Overlap > options.ChunkSize || options.ChunkSize > MaxScanChunk || options.Overlap > MaxScanChunk-options.ChunkSize || options.MaxChunks == 0 || options.MaxChunks > 1000000 {
		return nil, fmt.Errorf("invalid scan plan context, shape or chunk bound")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &ScanPlanner{ctx: ctx, options: options, out: out}, nil
}
func (p *ScanPlanner) check() error {
	if p.stop != nil {
		return p.stop
	}
	if err := p.ctx.Err(); err != nil {
		p.stop = err
		return err
	}
	if p.closed {
		return fmt.Errorf("scan planner is closed")
	}
	return nil
}
func (p *ScanPlanner) emit(chunk ScanChunk) error {
	if err := p.check(); err != nil {
		return err
	}
	if p.chunks >= p.options.MaxChunks {
		p.stop = fmt.Errorf("scan plan chunk bound exhausted")
		return p.stop
	}
	p.chunks++
	p.stop = p.out(chunk)
	if p.stop == nil {
		p.stop = p.ctx.Err()
	}
	return p.stop
}

func (p *ScanPlanner) Push(mapping PageMapping) error {
	if err := p.check(); err != nil {
		return err
	}
	end, err := Add(mapping.Virtual, mapping.Length)
	if err != nil || mapping.Length == 0 {
		p.stop = fmt.Errorf("invalid scan virtual interval")
		return p.stop
	}
	if _, err := Add(mapping.Physical, mapping.Length); err != nil {
		p.stop = err
		return err
	}
	if p.started && mapping.Virtual < p.lastEnd {
		p.stop = fmt.Errorf("scan mappings overlap or are unordered")
		return p.stop
	}
	if p.hasPending {
		if err := p.emit(p.pending); err != nil {
			return err
		}
		p.hasPending = false
	} else if !p.started && mapping.Virtual > 0 {
		if err := p.emit(ScanChunk{End: 0, Parts: []ScanPart{}}); err != nil {
			return err
		}
	}
	p.started = true
	p.lastEnd = end
	for offset := uint64(0); offset < mapping.Length; {
		if err := p.check(); err != nil {
			return err
		}
		if p.hasPending {
			if err := p.emit(p.pending); err != nil {
				return err
			}
		}
		length := min(mapping.Length-offset, p.options.ChunkSize+p.options.Overlap)
		virtual := mapping.Virtual + offset
		p.pending = ScanChunk{End: virtual + length, Parts: []ScanPart{{Virtual: virtual, Physical: mapping.Physical + offset, Length: length}}}
		p.hasPending = true
		if mapping.Length-offset <= p.options.ChunkSize {
			break
		}
		offset += p.options.ChunkSize
	}
	return nil
}
func (p *ScanPlanner) Finish() error {
	if err := p.check(); err != nil {
		return err
	}
	if p.hasPending {
		if err := p.emit(p.pending); err != nil {
			return err
		}
		p.hasPending = false
	}
	p.closed = true
	return nil
}
