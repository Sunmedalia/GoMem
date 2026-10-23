package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// BackingMapping is contiguous in virtual space and in one backing source.
// Pagefile nil means RAM. Layer is a runtime handle, owned by the acquisition;
// it must not outlive that acquisition. Offset is never implicitly physical.
type BackingMapping struct {
	Virtual, Offset, Length uint64
	Pagefile                *uint8
	Layer                   MemoryLayer
	// Unresolved is used only by fault callbacks, never by the valid emitter.
	Unresolved bool
}

func (m BackingMapping) MarshalJSON() ([]byte, error) {
	source := "physical"
	if m.Pagefile != nil {
		source = "pagefile"
	}
	var offset *string
	if m.Unresolved {
		source = "unresolved"
	} else {
		value := fmt.Sprintf("0x%016x", m.Offset)
		offset = &value
	}
	return json.Marshal(struct {
		Virtual  string  `json:"virtual"`
		Offset   *string `json:"offset,omitempty"`
		Length   uint64  `json:"length"`
		Source   string  `json:"source"`
		Pagefile *uint8  `json:"pagefile,omitempty"`
	}{fmt.Sprintf("0x%016x", m.Virtual), offset, m.Length, source, m.Pagefile})
}

// BackingMapOptions has the same section coordinates and budgets as page maps.
// Unlike the legacy physical-only walker, missing tables or backing bytes fail
// by default. A callback may retain a fault and continue; Unavailable counts
// both missing tables and missing mapped intervals even when it continues.
type BackingMapOptions struct {
	MaxTables, MaxEntries uint64
	Sections              []Range
	OnProgress            func(PageMapStats) error
	OnReadError           func(uint64, error) error
	OnUnavailableMapping  func(BackingMapping, error) error
}

type backingWalk struct {
	i        *Intel
	ctx      context.Context
	options  BackingMapOptions
	stats    PageMapStats
	levels   []mappedLevel
	width    int
	limit    uint64
	sections []flatSection
	pending  *BackingMapping
	out      func(BackingMapping) error
	ranges   map[int][]Range
}

// VisitBackingMappings streams RAM and configured Windows pagefiles without
// merging across source identities or the x64 canonical-address gap. It keeps
// the pinned default final-byte exclusion. Unlike the legacy walker, uniform
// tables are inspected, and nonzero unresolved Windows entries retain faults.
func (i *Intel) VisitBackingMappings(ctx context.Context, options BackingMapOptions, out func(BackingMapping) error) (PageMapStats, error) {
	if ctx == nil || i == nil || i.physical == nil || out == nil || options.MaxTables == 0 || options.MaxEntries == 0 {
		return PageMapStats{}, fmt.Errorf("backing map walk requires context, initialized tables, positive budgets and an emitter")
	}
	if err := ctx.Err(); err != nil {
		return PageMapStats{}, err
	}
	levels, width, limit, err := i.mapShape()
	if err != nil {
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
	w := &backingWalk{i: i, ctx: ctx, options: options, levels: levels, width: width, limit: limit, sections: sections, out: out, ranges: make(map[int][]Range)}
	root, err := w.read(i.root)
	if err == nil && root != nil {
		err = w.walk(0, root, 0, i.root)
	}
	if err == nil {
		err = w.flush()
	}
	return w.stats, err
}

func (w *backingWalk) progress() error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.options.OnProgress != nil {
		return w.options.OnProgress(w.stats)
	}
	return nil
}
func (w *backingWalk) read(at uint64) ([]byte, error) {
	if err := w.ctx.Err(); err != nil {
		return nil, err
	}
	if w.stats.Tables >= w.options.MaxTables {
		return nil, fmt.Errorf("backing map table limit exhausted")
	}
	w.stats.Tables++
	if err := w.progress(); err != nil {
		return nil, err
	}
	data, err := Read(w.ctx, w.i.physical, at, 4096)
	if err == nil {
		return data, nil
	}
	if w.ctx.Err() != nil {
		return nil, w.ctx.Err()
	}
	w.stats.Unavailable++
	if flushErr := w.flush(); flushErr != nil {
		return nil, flushErr
	}
	if w.options.OnReadError != nil {
		return nil, w.options.OnReadError(at, err)
	}
	return nil, fmt.Errorf("backing map table %#x: %w", at, err)
}
func (w *backingWalk) canonical(address uint64) uint64 {
	if w.i.mode == "x64" && address&(uint64(1)<<47) != 0 {
		return address | 0xffff000000000000
	}
	return address
}
func (w *backingWalk) walk(depth int, table []byte, base, at uint64) error {
	level := w.levels[depth]
	for index := 0; index < level.entries; index++ {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		virtual := base | uint64(index)<<level.shift
		if virtual >= w.limit {
			continue
		}
		span := min(uint64(1)<<level.shift, w.limit-virtual)
		if w.sections != nil {
			n := sort.Search(len(w.sections), func(n int) bool { return w.sections[n].end > virtual })
			if n == len(w.sections) || w.sections[n].start >= virtual+span {
				continue
			}
		}
		if w.stats.Entries >= w.options.MaxEntries {
			return fmt.Errorf("backing map entry limit exhausted")
		}
		w.stats.Entries++
		if err := w.progress(); err != nil {
			return err
		}
		entry := tableEntry(table, index, w.width)
		software, resident := w.i.entryMapped(entry)
		swap, err := w.i.swapEntry(w.canonical(virtual), at+uint64(index*w.width), entry, level.shift, w.width)
		if err != nil {
			return err
		}
		if !resident && swap == nil {
			if w.i.windows && entry != 0 {
				fault := fmt.Errorf("%w: Windows software entry %#x at %#x (%d-byte entry) is unresolved", ErrUnsupported, entry, at+uint64(index*w.width), w.width)
				if w.sections == nil {
					if err := w.unresolved(virtual, span, fault); err != nil {
						return err
					}
				} else {
					end := virtual + span
					for n := sort.Search(len(w.sections), func(n int) bool { return w.sections[n].end > virtual }); n < len(w.sections) && w.sections[n].start < end; n++ {
						lo, hi := max(virtual, w.sections[n].start), min(end, w.sections[n].end)
						if err := w.unresolved(lo, hi-lo, fault); err != nil {
							return err
						}
					}
				}
			}
			continue
		}
		large := resident && !software && entry&128 != 0 && level.shift > 12
		if large && !level.large {
			return fmt.Errorf("reserved large-page bit at %#x", at+uint64(index*w.width))
		}
		if resident && !large && depth+1 < len(w.levels) {
			childAt := w.i.frameAddress(entry, software, false, 4096)
			child, err := w.read(childAt)
			if err != nil {
				return err
			}
			if child != nil {
				if err := w.walk(depth+1, child, virtual, childAt); err != nil {
					return err
				}
			}
			continue
		}
		if w.sections == nil {
			if err := w.leaf(virtual, virtual, span, swap); err != nil {
				return err
			}
		} else {
			end := virtual + span
			for n := sort.Search(len(w.sections), func(n int) bool { return w.sections[n].end > virtual }); n < len(w.sections) && w.sections[n].start < end; n++ {
				lo, hi := max(virtual, w.sections[n].start), min(end, w.sections[n].end)
				if err := w.leaf(virtual, lo, hi-lo, swap); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (w *backingWalk) unresolved(virtual, length uint64, fault error) error {
	w.stats.Unavailable++
	if err := w.flush(); err != nil {
		return err
	}
	if w.options.OnUnavailableMapping != nil {
		return w.options.OnUnavailableMapping(BackingMapping{Virtual: w.canonical(virtual), Length: length, Unresolved: true}, fault)
	}
	return fault
}
func (w *backingWalk) leaf(block, virtual, length uint64, swap *SwappedPageError) error {
	m := BackingMapping{Virtual: w.canonical(virtual), Length: length, Layer: w.i.physical}
	key := -1
	if swap != nil {
		number := swap.Number
		m.Pagefile = &number
		m.Layer = w.i.pagefiles[number]
		key = int(number)
		offset, err := Add(swap.Offset, virtual-block)
		if err != nil {
			return err
		}
		m.Offset = offset
	} else {
		t, err := w.i.Translate(w.ctx, m.Virtual)
		if err != nil {
			return err
		}
		m.Offset = t.Physical
	}
	ranges, ok := w.ranges[key]
	if !ok && m.Layer != nil {
		ranges = append([]Range(nil), m.Layer.Ranges()...)
		sort.Slice(ranges, func(a, b int) bool { return ranges[a].Start < ranges[b].Start })
		w.ranges[key] = ranges
	}
	if m.Layer == nil || !rangeCovers(ranges, m.Offset, m.Length) {
		w.stats.Unavailable++
		if err := w.flush(); err != nil {
			return err
		}
		err := fmt.Errorf("%w: backing interval for virtual %#x (%d bytes)", ErrUnmapped, m.Virtual, m.Length)
		if w.options.OnUnavailableMapping != nil {
			return w.options.OnUnavailableMapping(m, err)
		}
		return err
	}
	if p := w.pending; p != nil {
		sameSource := p.Pagefile == nil && m.Pagefile == nil || p.Pagefile != nil && m.Pagefile != nil && *p.Pagefile == *m.Pagefile
		// Canonical addresses are checked directly; adjacent flat coordinates
		// at bit 47 must not turn into a run through the noncanonical gap.
		end, e := Add(p.Virtual, p.Length)
		if sameSource && e == nil && end == m.Virtual && p.Offset+p.Length == m.Offset {
			if _, err := Add(p.Length, m.Length); err != nil {
				return err
			}
			p.Length += m.Length
			return nil
		}
		if err := w.flush(); err != nil {
			return err
		}
	}
	w.pending = &m
	return nil
}
func (w *backingWalk) flush() error {
	if w.pending == nil {
		return nil
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if err := w.out(*w.pending); err != nil {
		return err
	}
	w.stats.Mappings++
	w.pending = nil
	return w.ctx.Err()
}
