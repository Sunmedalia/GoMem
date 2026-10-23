package memory

import (
	"container/list"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
)

type page struct {
	address uint64
	data    []byte
}

// Intel is a bounded, synchronized page-table cache. Software page-table
// encodings are interpreted only when an operating system is explicitly selected.
type Intel struct {
	physical  MemoryLayer
	root      uint64
	mode      string
	mu        sync.Mutex
	pages     map[uint64]*list.Element
	lru       *list.List
	capacity  int
	windows   bool
	pagefiles map[uint8]MemoryLayer
}

func (i *Intel) Root() uint64 { return i.root }

// NewIntelForOS enables resident Windows transition entries (Transition=1,
// Prototype=0). Prototype entries remain explicit errors. Translate reports
// swapped entries as SwappedPageError; Resolve can read attached pagefiles.
// The pinned Windows x64 baseline reserves PFN bits above bit 44; this policy
// is confined to Windows software entries, never generic hardware mappings.
func NewIntelForOS(p MemoryLayer, root uint64, mode, os string, capacity int) (*Intel, error) {
	i, err := NewIntel(p, root, mode, capacity)
	if err == nil {
		i.windows = os == "windows"
		if backing, ok := p.(*pagefilePhysical); ok && i.windows {
			i.pagefiles = backing.files
		}
	}
	return i, err
}

func NewIntel(p MemoryLayer, root uint64, mode string, capacity int) (*Intel, error) {
	if mode != "x64" && mode != "x86" && mode != "pae" {
		return nil, fmt.Errorf("unsupported architecture %q", mode)
	}
	if capacity <= 0 || capacity > 65536 {
		return nil, fmt.Errorf("page cache capacity must be 1..65536")
	}
	if mode == "pae" {
		root &= ^uint64(31)
	} else {
		root &= ^uint64(4095)
	}
	return &Intel{physical: p, root: root, mode: mode, pages: make(map[uint64]*list.Element), lru: list.New(), capacity: capacity}, nil
}
func (i *Intel) entry(ctx context.Context, a uint64, width int) (uint64, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	base := a &^ uint64(4095)
	off := int(a - base)
	i.mu.Lock()
	defer i.mu.Unlock()
	e := i.pages[base]
	if e == nil {
		b, err := Read(ctx, i.physical, base, 4096)
		if err != nil {
			return 0, err
		}
		e = i.lru.PushFront(page{base, b})
		i.pages[base] = e
		if i.lru.Len() > i.capacity {
			last := i.lru.Back()
			delete(i.pages, last.Value.(page).address)
			i.lru.Remove(last)
		}
	} else {
		i.lru.MoveToFront(e)
	}
	p := e.Value.(page).data
	if off+width > 4096 {
		return 0, fmt.Errorf("unaligned page table entry")
	}
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(p[off:])), nil
	}
	return binary.LittleEndian.Uint64(p[off:]), nil
}
func (i *Intel) Translate(ctx context.Context, a uint64) (Translation, error) {
	if e := ctx.Err(); e != nil {
		return Translation{}, e
	}
	shifts := []uint{39, 30, 21, 12}
	width := 8
	table := i.root
	w, x := true, true
	transition := false
	if i.mode == "x64" {
		upper := a >> 48
		if (a>>47)&1 == 0 && upper != 0 || (a>>47)&1 == 1 && upper != 0xffff {
			return Translation{}, fmt.Errorf("noncanonical x64 address %#x", a)
		}
	} else {
		if a>>32 != 0 {
			return Translation{}, fmt.Errorf("32-bit address out of range")
		}
		if i.mode == "x86" {
			shifts = []uint{22, 12}
			width = 4
		} else {
			shifts = []uint{30, 21, 12}
		}
	}
	for level, shift := range shifts {
		mask := uint64(511)
		if width == 4 {
			mask = 1023
		}
		if i.mode == "pae" && level == 0 {
			mask = 3
		}
		index := (a >> shift) & mask
		entry, e := i.entry(ctx, table+index*uint64(width), width)
		if e != nil {
			return Translation{}, e
		}
		software := entry&1 == 0
		if software && (!i.windows || entry&2048 == 0 || entry&1024 != 0) {
			bitOffset := uint(32)
			if i.mode == "x86" {
				bitOffset = 12
			}
			if i.windows && entry&(1|1024|2048) == 0 && entry&128 != 0 && entry>>bitOffset != 0 {
				if entry>>bitOffset > ^uint64(0)>>shift {
					return Translation{}, fmt.Errorf("%w: pagefile offset overflows", ErrUnmapped)
				}
				return Translation{}, &SwappedPageError{Virtual: a, EntryAddress: table + index*uint64(width), Entry: entry, EntryWidth: uint8(width), Number: uint8((entry >> 1) & 15), Offset: (entry >> bitOffset) << shift, PageSize: uint64(1) << shift}
			}
			return Translation{}, fmt.Errorf("%w: nonpresent page-table entry %#x at %#x (prototype/swap or unsupported software encoding)", ErrUnmapped, entry, table+index*uint64(width))
		}
		transition = transition || software
		if !software && !(i.mode == "pae" && level == 0) {
			w = w && entry&2 != 0
			x = x && (width == 4 || entry>>63 == 0)
		}
		// Bit 7 is software protection metadata in a transition entry.
		large := !software && entry&128 != 0 && shift > 12
		if large {
			allowed := (i.mode == "x64" && (shift == 30 || shift == 21)) || (i.mode == "pae" && shift == 21) || (i.mode == "x86" && shift == 22)
			if !allowed {
				return Translation{}, fmt.Errorf("reserved large-page bit")
			}
		}
		if shift == 12 || large {
			size := uint64(1) << shift
			if large && width == 8 && entry&((size-1)&^uint64(8191)) != 0 {
				return Translation{}, fmt.Errorf("reserved physical-address bits in large page")
			}
			frame := entry & 0x000ffffffffff000
			if software && i.mode == "x64" {
				frame &= 0x00001ffffffff000
			}
			if width == 4 {
				frame = entry & 0xfffff000
				if large {
					frame = (entry & 0xffc00000) | ((entry & 0x001fe000) << 19)
				}
			}
			if large {
				frame &= ^(size - 1)
			}
			return Translation{PageSize: size, EntryAddress: table + index*uint64(width), Entry: entry, EntryWidth: uint8(width), Dirty: !transition && entry&64 != 0, DirtyKnown: !transition, Physical: frame + (a & (size - 1)), Available: size - (a & (size - 1)), Writable: w && !transition, Executable: x && !transition, PermissionsKnown: !transition, Transition: transition}, nil
		}
		table = entry & 0x000ffffffffff000
		if software && i.mode == "x64" {
			table &= 0x00001ffffffff000
		}
	}
	return Translation{}, fmt.Errorf("incomplete page walk")
}
