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

// Intel is a bounded, synchronized page-table cache. Nonpresent entries, including
// transition/prototype/swap entries, are errors until a matching swap resolver exists.
type Intel struct {
	physical MemoryLayer
	root     uint64
	mode     string
	mu       sync.Mutex
	pages    map[uint64]*list.Element
	lru      *list.List
	capacity int
}

func (i *Intel) Root() uint64 { return i.root }

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
		if entry&1 == 0 {
			return Translation{}, fmt.Errorf("%w: nonpresent page-table entry at %#x (swap/transition pages unresolved)", ErrUnmapped, table+index*uint64(width))
		}
		if !(i.mode == "pae" && level == 0) {
			w = w && entry&2 != 0
			x = x && (width == 4 || entry>>63 == 0)
		}
		large := entry&128 != 0 && shift > 12
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
			if width == 4 {
				frame = entry & 0xfffff000
				if large {
					frame = (entry & 0xffc00000) | ((entry & 0x001fe000) << 19)
				}
			}
			if large {
				frame &= ^(size - 1)
			}
			return Translation{frame + (a & (size - 1)), size - (a & (size - 1)), w, x}, nil
		}
		table = entry & 0x000ffffffffff000
	}
	return Translation{}, fmt.Errorf("incomplete page walk")
}
