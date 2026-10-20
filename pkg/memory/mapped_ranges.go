package memory

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
)

type mappedLevel struct {
	shift   uint
	entries int
	large   bool
}

// MappedRanges lists readable virtual runs in increasing address order.
// A page-table page whose entries are all identical is omitted, matching the
// Intel layer the pinned pool scanner uses. Windows transition pages are
// included only for a translator created with the Windows software-entry rule.
func (i *Intel) MappedRanges(ctx context.Context) ([]Range, error) {
	if i == nil || i.physical == nil {
		return nil, fmt.Errorf("page table is not initialized")
	}
	var levels []mappedLevel
	width := 8
	switch i.mode {
	case "x64":
		levels = []mappedLevel{{39, 512, false}, {30, 512, true}, {21, 512, true}, {12, 512, false}}
	case "pae":
		levels = []mappedLevel{{30, 4, false}, {21, 512, true}, {12, 512, false}}
	case "x86":
		width = 4
		levels = []mappedLevel{{22, 1024, true}, {12, 1024, false}}
	default:
		return nil, fmt.Errorf("unsupported architecture %q", i.mode)
	}
	ranges := append([]Range(nil), i.physical.Ranges()...)
	sort.Slice(ranges, func(a, b int) bool { return ranges[a].Start < ranges[b].Start })
	root, err := Read(ctx, i.physical, i.root, 4096)
	if err != nil {
		return nil, fmt.Errorf("page table root: %w", err)
	}
	if uniformEntries(root, width) {
		return nil, nil
	}
	var out []Range
	var walk func(depth int, table []byte, base uint64) error
	walk = func(depth int, table []byte, base uint64) error {
		level := levels[depth]
		last := depth+1 == len(levels)
		for index := 0; index < level.entries; index++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			entry := tableEntry(table, index, width)
			software, ok := i.entryMapped(entry)
			if !ok {
				continue
			}
			huge := !software && entry&128 != 0 && level.shift > 12
			if huge && !level.large {
				continue
			}
			size := uint64(1) << level.shift
			virtual := base | uint64(index)<<level.shift
			if huge || last {
				if huge && width == 8 && entry&((size-1)&^8191) != 0 {
					continue
				}
				phys := i.frameAddress(entry, software, huge, size)
				for _, span := range residentSpans(ranges, phys, size) {
					if err := i.appendMapped(&out, virtual+span[0], span[1]); err != nil {
						return err
					}
				}
				continue
			}
			child, err := Read(ctx, i.physical, i.frameAddress(entry, software, false, 4096), 4096)
			if err != nil || uniformEntries(child, width) {
				continue
			}
			if err := walk(depth+1, child, virtual); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(0, root, 0); err != nil {
		return nil, err
	}
	return out, nil
}

func (i *Intel) entryMapped(entry uint64) (software, ok bool) {
	if entry&1 != 0 {
		return false, true
	}
	if i.windows && entry&2048 != 0 && entry&1024 == 0 {
		return true, true
	}
	return false, false
}

func (i *Intel) frameAddress(entry uint64, software, large bool, size uint64) uint64 {
	var frame uint64
	if i.mode == "x86" {
		frame = entry & 0xfffff000
		if large {
			frame = (entry & 0xffc00000) | ((entry & 0x001fe000) << 19)
		}
	} else {
		frame = entry & 0x000ffffffffff000
		if software && i.mode == "x64" {
			frame &= 0x00001ffffffff000
		}
	}
	if large {
		frame &^= size - 1
	}
	return frame
}

func (i *Intel) appendMapped(out *[]Range, virtual, length uint64) error {
	if length == 0 {
		return nil
	}
	if i.mode == "x64" && virtual&(1<<47) != 0 {
		virtual |= 0xffff000000000000
	}
	if _, err := Add(virtual, length); err != nil {
		return err
	}
	if ranges := *out; len(ranges) > 0 {
		last := &ranges[len(ranges)-1]
		end, err := Add(last.Start, last.Length)
		if err != nil {
			return err
		}
		if virtual == end {
			if _, err := Add(last.Length, length); err != nil {
				return err
			}
			last.Length += length
			return nil
		}
		if virtual < end {
			return fmt.Errorf("mapped virtual ranges are not ordered at %#x", virtual)
		}
	}
	*out = append(*out, Range{Start: virtual, Length: length})
	return nil
}

func tableEntry(table []byte, index, width int) uint64 {
	off := index * width
	if off < 0 || off+width > len(table) {
		return 0
	}
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(table[off:]))
	}
	return binary.LittleEndian.Uint64(table[off:])
}

func uniformEntries(table []byte, width int) bool {
	if width <= 0 || len(table) < width || len(table)%width != 0 {
		return false
	}
	first := table[:width]
	for off := width; off < len(table); off += width {
		if !bytes.Equal(table[off:off+width], first) {
			return false
		}
	}
	return true
}

func residentSpans(ranges []Range, phys, size uint64) [][2]uint64 {
	end, err := Add(phys, size)
	if err != nil || size == 0 {
		return nil
	}
	var spans [][2]uint64
	for _, r := range ranges {
		rEnd, err := Add(r.Start, r.Length)
		if err != nil || r.Length == 0 || rEnd <= phys || r.Start >= end {
			continue
		}
		lo, hi := phys, end
		if r.Start > lo {
			lo = r.Start
		}
		if rEnd < hi {
			hi = rEnd
		}
		spans = append(spans, [2]uint64{lo - phys, hi - lo})
	}
	return spans
}
