package kallsyms

import (
	"context"
	"fmt"
	"sort"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// Lookup resolves an interior core address to its first aliased symbol. Core
// text/init section membership gates lookup; a nearby data symbol does not
// make an arbitrary address resolvable. Names are located through resident
// markers, not the external ISF's symbol names or enumeration-side offsets.
// Lookup and Stream share the fixed name cursor and must not run concurrently.
func (c *Core) Lookup(ctx context.Context, address uint64) (*Symbol, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.config.HasText {
		return nil, fmt.Errorf("core lookup lacks _stext metadata")
	}
	address &= c.config.AddressMask
	inText := c.config.TextStart <= address && address < c.config.TextEnd
	inInit := c.config.HasInit && c.config.InitStart <= address && address < c.config.InitEnd
	if !inText && !inInit {
		return nil, nil
	}
	if len(c.addresses) == 0 {
		return nil, fmt.Errorf("core lookup cannot resolve an empty address index")
	}
	i := sort.Search(len(c.addresses), func(i int) bool { return c.addresses[i] > address }) - 1
	if i < 0 {
		i = 0
	}
	alias := c.addresses[i]
	i = sort.Search(len(c.addresses), func(i int) bool { return c.addresses[i] >= alias })
	offset, err := c.nameOffset(ctx, uint64(i))
	if err != nil {
		return nil, err
	}
	name, typ, length, header, err := c.Expand(ctx, offset)
	if err != nil {
		return nil, err
	}
	start, end := c.interval(address)
	next, err := memory.Add(offset, length+1)
	if err != nil {
		return nil, err
	}
	result := &Symbol{Index: uint64(i), Address: c.addresses[i], Name: name, Type: typ, NameOffset: offset, NextOffset: next, CompressedLength: length, HeaderBytes: header, SizeStart: start, SizeEnd: end}
	if end > start {
		result.Size = end - start
		result.SizeAvailable = true
	}
	if typ != "" {
		v := typ >= "A" && typ <= "Z" || typ == "u" || typ == "v" || typ == "w"
		result.Exported = &v
	}
	return result, nil
}

func (c *Core) nameOffset(ctx context.Context, index uint64) (uint64, error) {
	if element, ok := c.nameOffsets[index]; ok {
		c.nameLRU.MoveToFront(element)
		return element.Value.(coreNameOffset).offset, nil
	}
	if c.config.Markers == 0 {
		return 0, fmt.Errorf("core lookup lacks kallsyms_markers")
	}
	if c.config.MarkerSize != 4 && c.config.MarkerSize != 8 {
		return 0, fmt.Errorf("invalid kallsyms marker width")
	}
	at, err := memory.Add(c.config.Markers, (index>>8)*uint64(c.config.MarkerSize))
	if err != nil {
		return 0, err
	}
	offset, err := c.uint(ctx, at, c.config.MarkerSize)
	if err != nil {
		return 0, err
	}
	for step := uint64(0); step < index&0xff; step++ {
		at, err := memory.Add(c.config.Names, offset)
		if err != nil {
			return 0, err
		}
		length, err := c.uint(ctx, at, 1)
		if err != nil {
			return 0, err
		}
		if length&0x80 != 0 {
			// Pinned _get_symbol_offset takes the high byte from the shared names
			// cursor, not at+1. Retain this order-sensitive behavior explicitly.
			cursor, err := memory.Add(c.config.Names, c.namesCursor)
			if err != nil {
				return 0, err
			}
			upper, err := c.uint(ctx, cursor, 1)
			if err != nil {
				return 0, err
			}
			c.namesCursor++
			length = upper<<7 | length&0x7f
		}
		offset, err = memory.Add(offset, length+1)
		if err != nil {
			return 0, err
		}
	}
	// Fixed functools.lru_cache() keeps 128 entries. Eviction matters because
	// an extended length can consume the shared decoder cursor on a cache miss.
	c.nameOffsets[index] = c.nameLRU.PushFront(coreNameOffset{index, offset})
	if c.nameLRU.Len() > 128 {
		old := c.nameLRU.Back()
		delete(c.nameOffsets, old.Value.(coreNameOffset).index)
		c.nameLRU.Remove(old)
	}
	return offset, nil
}

type coreNameOffset struct{ index, offset uint64 }
