package memory

import (
	"context"
	"fmt"
	"sort"
)

// PageMapping is one virtually and physically contiguous run. Virtual is the
// canonical start. Length may cross the x64 canonical boundary when the run
// starts in the low 48-bit half; comparison masks that start to 48 bits.
type PageMapping struct {
	Virtual  uint64
	Physical uint64
	Length   uint64
}

type pageSpan struct {
	virt   uint64
	phys   uint64
	length uint64
}

// PageMapOptions bounds the table walk independently of the number of merged
// output runs. Fault callbacks may retain source errors or stop the walk.
type PageMapOptions struct {
	MaxTables  uint64
	MaxEntries uint64
	// Sections restricts traversal to virtual byte intervals. Nil selects the
	// baseline's default whole-space range (which excludes its final byte).
	// A non-nil empty slice selects nothing. Explicit intervals can include the
	// final byte and are clipped before physical availability is checked.
	Sections []Range
	// OnProgress observes table/entry counters before the corresponding work.
	// It can enforce a shared budget across nested walks and stop immediately.
	OnProgress           func(PageMapStats) error
	OnReadError          func(uint64, error) error
	OnUnavailableMapping func(PageMapping) error
}

type PageMapStats struct {
	Tables      uint64
	Entries     uint64
	Mappings    uint64
	Unavailable uint64
}

// PageMappings preserves the original collecting API. Streaming consumers
// should use VisitPageMappings with explicit task limits.
func (i *Intel) PageMappings(ctx context.Context) ([]PageMapping, error) {
	var out []PageMapping
	_, err := i.VisitPageMappings(ctx, PageMapOptions{MaxTables: ^uint64(0), MaxEntries: ^uint64(0)}, func(m PageMapping) error {
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, err
}

type pageMapWalk struct {
	intel    *Intel
	ctx      context.Context
	options  PageMapOptions
	stats    PageMapStats
	ranges   []Range
	limit    uint64
	levels   []mappedLevel
	width    int
	pending  *pageSpan
	out      func(PageMapping) error
	sections []flatSection
}
type flatSection struct{ start, end uint64 }

func pageMapSections(mode string, domain uint64, ranges []Range) ([]flatSection, error) {
	if ranges == nil {
		return nil, nil
	}
	if len(ranges) > 1000000 {
		return nil, fmt.Errorf("page map section limit exceeds 1000000")
	}
	sections := make([]flatSection, 0, len(ranges))
	for _, r := range ranges {
		start := r.Start
		if mode == "x64" && start>>48 != 0 {
			if start>>48 != 0xffff || start&(uint64(1)<<47) == 0 {
				return nil, fmt.Errorf("invalid x64 section address %#x", start)
			}
			start &= (uint64(1) << 48) - 1
		}
		if start >= domain || r.Length == 0 || r.Length > domain-start {
			return nil, fmt.Errorf("invalid page map section %#x+%#x", r.Start, r.Length)
		}
		sections = append(sections, flatSection{start, start + r.Length})
	}
	sort.Slice(sections, func(a, b int) bool { return sections[a].start < sections[b].start })
	merged := sections[:0]
	for _, s := range sections {
		if len(merged) > 0 && s.start <= merged[len(merged)-1].end {
			merged[len(merged)-1].end = max(merged[len(merged)-1].end, s.end)
		} else {
			merged = append(merged, s)
		}
	}
	return merged, nil
}

func (w *pageMapWalk) firstSection(virtual uint64) int {
	return sort.Search(len(w.sections), func(n int) bool { return w.sections[n].end > virtual })
}
func (w *pageMapWalk) selected(virtual, length uint64) bool {
	if w.sections == nil {
		return true
	}
	n := w.firstSection(virtual)
	return n < len(w.sections) && w.sections[n].start < virtual+length
}

// VisitPageMappings yields coalesced runs in the pinned Windows layer order,
// retaining only one pending run and the bounded page-table recursion stack.
// Uniform tables, final-byte clipping, physical masks and whole-large-page
// availability follow PageMappings. Cancellation or any callback error stops
// acquisition. An aborted walk can leave its final pending run unreported.
func (i *Intel) VisitPageMappings(ctx context.Context, options PageMapOptions, out func(PageMapping) error) (PageMapStats, error) {
	if i == nil || i.physical == nil {
		return PageMapStats{}, fmt.Errorf("page table is not initialized")
	}
	if options.MaxTables == 0 || options.MaxEntries == 0 || out == nil {
		return PageMapStats{}, fmt.Errorf("page map walk needs positive table/entry bounds and an emitter")
	}
	levels, width, limit, err := i.mapShape()
	if err != nil {
		return PageMapStats{}, err
	}
	if err := ctx.Err(); err != nil {
		return PageMapStats{}, err
	}
	sections, err := pageMapSections(i.mode, limit+1, options.Sections)
	if err != nil {
		return PageMapStats{}, err
	}
	if sections != nil && len(sections) == 0 {
		return PageMapStats{}, nil
	}
	if sections != nil {
		limit++
	}
	ranges := append([]Range(nil), i.physical.Ranges()...)
	sort.Slice(ranges, func(a, b int) bool { return ranges[a].Start < ranges[b].Start })
	w := pageMapWalk{intel: i, ctx: ctx, options: options, ranges: ranges, limit: limit, levels: levels, width: width, out: out, sections: sections}
	root, err := w.read(i.root)
	if err == nil && root != nil && !uniformEntries(root, width) {
		err = w.walk(0, root, 0)
	}
	if err == nil {
		err = w.flush()
	}
	return w.stats, err
}

func (w *pageMapWalk) read(at uint64) ([]byte, error) {
	if err := w.ctx.Err(); err != nil {
		return nil, err
	}
	if w.stats.Tables >= w.options.MaxTables {
		return nil, fmt.Errorf("page map table limit exhausted")
	}
	w.stats.Tables++
	if w.options.OnProgress != nil {
		if err := w.options.OnProgress(w.stats); err != nil {
			return nil, err
		}
	}
	raw, err := Read(w.ctx, w.intel.physical, at, 4096)
	if err == nil {
		return raw, nil
	}
	if w.ctx.Err() != nil {
		return nil, w.ctx.Err()
	}
	if w.options.OnReadError != nil {
		return nil, w.options.OnReadError(at, err)
	}
	return nil, nil
}

func (w *pageMapWalk) flush() error {
	if w.pending == nil {
		return nil
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	p := w.pending
	virtual := p.virt
	if w.intel.mode == "x64" && virtual&(uint64(1)<<47) != 0 {
		virtual |= 0xffff000000000000
	}
	if err := w.out(PageMapping{Virtual: virtual, Physical: p.phys, Length: p.length}); err != nil {
		return err
	}
	w.stats.Mappings++
	w.pending = nil
	return nil
}

func (w *pageMapWalk) span(virt, phys, length uint64) error {
	if _, err := Add(virt, length); err != nil {
		return err
	}
	if _, err := Add(phys, length); err != nil {
		return err
	}
	if p := w.pending; p != nil {
		if virt == p.virt+p.length && phys == p.phys+p.length {
			if _, err := Add(p.length, length); err != nil {
				return err
			}
			p.length += length
			return nil
		}
		if virt < p.virt+p.length {
			return fmt.Errorf("mapped virtual ranges are not ordered at %#x", virt)
		}
		if err := w.flush(); err != nil {
			return err
		}
	}
	w.pending = &pageSpan{virt: virt, phys: phys, length: length}
	return nil
}

func (i *Intel) mapShape() ([]mappedLevel, int, uint64, error) {
	switch i.mode {
	case "x64":
		return []mappedLevel{{39, 512, false}, {30, 512, true}, {21, 512, true}, {12, 512, false}}, 8, uint64(1)<<48 - 1, nil
	case "pae":
		return []mappedLevel{{30, 4, false}, {21, 512, true}, {12, 512, false}}, 8, uint64(1)<<32 - 1, nil
	case "x86":
		return []mappedLevel{{22, 1024, true}, {12, 1024, false}}, 4, uint64(1)<<32 - 1, nil
	default:
		return nil, 0, 0, fmt.Errorf("unsupported architecture %q", i.mode)
	}
}

func (w *pageMapWalk) walk(depth int, table []byte, base uint64) error {
	level := w.levels[depth]
	last := depth+1 == len(w.levels)
	for index := 0; index < level.entries; index++ {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		virtual := base | uint64(index)<<level.shift
		if virtual >= w.limit {
			continue
		}
		full := uint64(1) << level.shift
		if !w.selected(virtual, min(full, w.limit-virtual)) {
			continue
		}
		if w.stats.Entries >= w.options.MaxEntries {
			return fmt.Errorf("page map entry limit exhausted")
		}
		w.stats.Entries++
		if w.options.OnProgress != nil {
			if err := w.options.OnProgress(w.stats); err != nil {
				return err
			}
		}
		entry := tableEntry(table, index, w.width)
		if _, ok := w.intel.entryMapped(entry); !ok {
			continue
		}
		large := level.large && entry&128 != 0
		if !large && !last {
			child, err := w.read(w.intel.mapFrame(entry, false, full))
			if err != nil {
				return err
			}
			if child == nil || uniformEntries(child, w.width) {
				continue
			}
			if err = w.walk(depth+1, child, virtual); err != nil {
				return err
			}
			continue
		}
		span := full
		if remain := w.limit - virtual; span > remain {
			span = remain
		}
		phys := w.intel.mapFrame(entry, large, full)
		if w.sections == nil {
			if err := w.leaf(virtual, phys, span); err != nil {
				return err
			}
		} else {
			end := virtual + span
			for n := w.firstSection(virtual); n < len(w.sections) && w.sections[n].start < end; n++ {
				lo, hi := max(virtual, w.sections[n].start), min(end, w.sections[n].end)
				at, err := Add(phys, lo-virtual)
				if err != nil {
					return err
				}
				if err := w.leaf(lo, at, hi-lo); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (w *pageMapWalk) leaf(virtual, phys, span uint64) error {
	if !rangeCovers(w.ranges, phys, span) {
		w.stats.Unavailable++
		if w.options.OnUnavailableMapping != nil {
			if w.intel.mode == "x64" && virtual&(uint64(1)<<47) != 0 {
				virtual |= 0xffff000000000000
			}
			if err := w.options.OnUnavailableMapping(PageMapping{Virtual: virtual, Physical: phys, Length: span}); err != nil {
				return err
			}
		}
		return nil
	}
	return w.span(virtual, phys, span)
}

// mapFrame matches the pinned WindowsIntel32e mask: bits 12..44, including
// present entries. Other modes keep the architecture physical mask. Large-page
// offsets replace the low frame bits, so the PAT bit does not survive.
func (i *Intel) mapFrame(entry uint64, large bool, page uint64) uint64 {
	var frame uint64
	switch i.mode {
	case "x86":
		if large {
			frame = entry & 0xffc00000
		} else {
			frame = entry & 0xfffff000
		}
	case "pae":
		frame = entry & 0xfffffffff000
		if large {
			frame &^= page - 1
		}
	default:
		frame = entry & 0x000ffffffffff000
		if i.windows {
			frame = entry & 0x1ffffffff000
		}
		if large {
			frame &^= page - 1
		}
	}
	return frame
}

func rangeCovers(ranges []Range, phys, size uint64) bool {
	end, err := Add(phys, size)
	if err != nil || size == 0 {
		return false
	}
	cur := phys
	for _, r := range ranges {
		if r.Length == 0 {
			continue
		}
		rEnd, err := Add(r.Start, r.Length)
		if err != nil {
			return false
		}
		if rEnd <= cur {
			continue
		}
		if r.Start > cur {
			return false
		}
		if rEnd >= end {
			return true
		}
		cur = rEnd
	}
	return false
}
