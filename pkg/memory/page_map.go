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

// PageMappings walks the Intel page tables the way the pinned Windows layer
// mapping does. A table whose entries are all identical is absent. Windows x64
// physical addresses keep bits 12..44 only. The walk stops one byte before the
// architecture maximum, and a large page with any physical hole is omitted.
func (i *Intel) PageMappings(ctx context.Context) ([]PageMapping, error) {
	if i == nil || i.physical == nil {
		return nil, fmt.Errorf("page table is not initialized")
	}
	levels, width, limit, err := i.mapShape()
	if err != nil {
		return nil, err
	}
	root, err := Read(ctx, i.physical, i.root, 4096)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	if uniformEntries(root, width) {
		return nil, nil
	}
	ranges := append([]Range(nil), i.physical.Ranges()...)
	sort.Slice(ranges, func(a, b int) bool { return ranges[a].Start < ranges[b].Start })
	var spans []pageSpan
	if err = i.walkPageMaps(ctx, 0, root, 0, levels, width, ranges, limit, &spans); err != nil {
		return nil, err
	}
	return finishPageMappings(spans, i.mode == "x64"), nil
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

func (i *Intel) walkPageMaps(ctx context.Context, depth int, table []byte, base uint64, levels []mappedLevel, width int, ranges []Range, limit uint64, out *[]pageSpan) error {
	level := levels[depth]
	last := depth+1 == len(levels)
	for index := 0; index < level.entries; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		shift := level.shift
		virtual := base | uint64(index)<<shift
		if virtual >= limit {
			continue
		}
		entry := tableEntry(table, index, width)
		if _, ok := i.entryMapped(entry); !ok {
			continue
		}
		full := uint64(1) << shift
		large := level.large && entry&128 != 0
		if !large && !last {
			next := i.mapFrame(entry, false, full)
			child, err := Read(ctx, i.physical, next, 4096)
			if err != nil || uniformEntries(child, width) {
				if err = ctx.Err(); err != nil {
					return err
				}
				continue
			}
			if err = i.walkPageMaps(ctx, depth+1, child, virtual, levels, width, ranges, limit, out); err != nil {
				return err
			}
			continue
		}
		span := full
		if remain := limit - virtual; span > remain {
			span = remain
		}
		phys := i.mapFrame(entry, large, full)
		if !rangeCovers(ranges, phys, span) {
			continue
		}
		if err := addPageSpan(out, virtual, phys, span); err != nil {
			return err
		}
	}
	return nil
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

func addPageSpan(out *[]pageSpan, virt, phys, length uint64) error {
	if length == 0 {
		return nil
	}
	if _, err := Add(virt, length); err != nil {
		return err
	}
	if _, err := Add(phys, length); err != nil {
		return err
	}
	if spans := *out; len(spans) > 0 {
		last := &spans[len(spans)-1]
		vend, err := Add(last.virt, last.length)
		if err != nil {
			return err
		}
		pend, err := Add(last.phys, last.length)
		if err != nil {
			return err
		}
		if virt == vend && phys == pend {
			if _, err = Add(last.length, length); err != nil {
				return err
			}
			last.length += length
			return nil
		}
		if virt < vend {
			return fmt.Errorf("mapped virtual ranges are not ordered at %#x", virt)
		}
	}
	*out = append(*out, pageSpan{virt: virt, phys: phys, length: length})
	return nil
}

func finishPageMappings(spans []pageSpan, canonical bool) []PageMapping {
	out := make([]PageMapping, len(spans))
	for n, span := range spans {
		virtual := span.virt
		if canonical && virtual&(uint64(1)<<47) != 0 {
			virtual |= 0xffff000000000000
		}
		out[n] = PageMapping{Virtual: virtual, Physical: span.phys, Length: span.length}
	}
	return out
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
