// Package linuxcache reads Linux page-cache indices using declared kernel types.
// Tagged values are evidence, never speculative pointers to struct page.
package linuxcache

import (
	"context"
	"errors"
	"fmt"
	"math/bits"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

type Entry struct {
	Index, Span, Value, Slot uint64
	Kind                     string
}
type Limits struct{ Nodes, Entries uint64 }
type Stats struct {
	Kind           string
	Nodes, Entries uint64
}

// Walk streams ascending indices. Any structural/read error means that the
// emitted prefix cannot establish absence in the rest of the cache.
func Walk(ctx context.Context, r *object.Reader, mapping uint64, limits Limits, emit func(Entry) error) (Stats, error) {
	var stats Stats
	if limits.Nodes == 0 || limits.Nodes > 1000000 || limits.Entries == 0 || limits.Entries > 1000000 {
		return stats, fmt.Errorf("tree limits must be 1..1000000")
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	width := uint64(r.Symbols.PointerSize())
	if width != 4 && width != 8 {
		return stats, fmt.Errorf("unsupported pointer width")
	}
	field, err := r.Field("address_space", "i_pages")
	if errors.Is(err, object.ErrFieldAbsent) {
		field, err = r.Field("address_space", "page_tree")
	}
	if err != nil {
		return stats, err
	}
	if field.Type.Kind != "struct" {
		return stats, fmt.Errorf("page-cache root is not an embedded structure")
	}
	root, err := memory.Add(mapping, field.Offset)
	if err != nil {
		return stats, err
	}
	rootType := field.Type.Name
	_, xaErr := r.Field(rootType, "xa_head")
	xa := xaErr == nil
	if xaErr != nil && !errors.Is(xaErr, object.ErrFieldAbsent) {
		return stats, xaErr
	}
	nodeType, headField := "radix_tree_node", "rnode"
	stats.Kind = "radix"
	if xa {
		nodeType, headField, stats.Kind = "xa_node", "xa_head", "xarray"
	}
	headLayout, err := r.Field(rootType, headField)
	if err != nil {
		return stats, err
	}
	if headLayout.Type.Kind != "pointer" {
		return stats, fmt.Errorf("cache head is not a pointer")
	}
	head, err := r.Uint(ctx, root, rootType, headField)
	if err != nil {
		return stats, err
	}
	slots, err := r.Field(nodeType, "slots")
	if err != nil {
		return stats, err
	}
	count := slots.Type.Count
	if slots.Type.Kind != "array" || slots.Type.Subtype == nil || slots.Type.Subtype.Kind != "pointer" || count < 2 || count > 256 || count&(count-1) != 0 {
		return stats, fmt.Errorf("invalid page-cache slots array")
	}
	size, err := r.Size(*slots.Type.Subtype)
	if err != nil || size != width {
		return stats, fmt.Errorf("slot width does not match kernel pointers")
	}
	chunk := uint64(bits.TrailingZeros64(count))
	maxHeight := (width*8 + chunk - 1) / chunk
	seen := map[uint64]bool{}
	publish := func(index, shift, value, slot uint64, kind string) error {
		if stats.Entries >= limits.Entries {
			return fmt.Errorf("cache entry limit exceeded")
		}
		stats.Entries++
		return emit(Entry{index, uint64(1) << shift, value, slot, kind})
	}
	heightAt := func(node uint64) (uint64, error) {
		for _, name := range []string{"shift", "path", "height"} {
			_, er := r.Field(nodeType, name)
			if errors.Is(er, object.ErrFieldAbsent) {
				continue
			}
			if er != nil {
				return 0, er
			}
			v, er := r.Uint(ctx, node, nodeType, name)
			if er != nil {
				return 0, er
			}
			if name == "shift" {
				if v%chunk != 0 || v >= width*8 {
					return 0, fmt.Errorf("invalid node shift %d", v)
				}
				v = v/chunk + 1
			}
			if name == "path" {
				v &= (uint64(1) << (maxHeight + 1)) - 1
			}
			if v == 0 || v > maxHeight {
				return 0, fmt.Errorf("invalid node height %d", v)
			}
			return v, nil
		}
		return 0, fmt.Errorf("missing node height")
	}
	var walkNode func(uint64, uint64, uint64) error
	var walkValue func(uint64, uint64, uint64, uint64, uint64) error
	walkValue = func(value, index, shift, slot, childHeight uint64) error {
		if value == 0 {
			return nil
		}
		if xa {
			if value&1 != 0 {
				return publish(index, shift, value, slot, "value")
			}
			if value&3 == 2 {
				if value < 4096 {
					kind := "internal_value"
					if value>>2 < count {
						kind = "sibling"
					}
					return publish(index, shift, value, slot, kind)
				}
				if childHeight == 0 {
					return fmt.Errorf("xarray node below leaf level")
				}
				return walkNode(value&^3, index, childHeight)
			}
		} else {
			if value&3 == 2 {
				return publish(index, shift, value, slot, "exceptional")
			}
			if value&3 == 3 {
				return fmt.Errorf("invalid radix entry tag")
			}
			if childHeight > 0 {
				return walkNode(value&^3, index, childHeight)
			}
			if value&1 != 0 {
				return fmt.Errorf("radix node below leaf level")
			}
		}
		if value%width != 0 {
			return fmt.Errorf("unaligned page pointer")
		}
		return publish(index, shift, value, slot, "page")
	}
	walkNode = func(node, index, height uint64) error {
		if er := ctx.Err(); er != nil {
			return er
		}
		if node == 0 || node%width != 0 {
			return fmt.Errorf("invalid cache node pointer")
		}
		if seen[node] {
			return fmt.Errorf("repeated cache node %#x", node)
		}
		if stats.Nodes >= limits.Nodes {
			return fmt.Errorf("cache node limit exceeded")
		}
		seen[node] = true
		stats.Nodes++
		actual, er := heightAt(node)
		if er != nil {
			return er
		}
		if actual != height {
			return fmt.Errorf("cache node height %d differs from expected %d", actual, height)
		}
		shift := (height - 1) * chunk
		base, er := memory.Add(node, slots.Offset)
		if er != nil {
			return er
		}
		for i := uint64(0); i < count; i++ {
			if er := ctx.Err(); er != nil {
				return er
			}
			slot, er := memory.Add(base, i*width)
			if er != nil {
				return er
			}
			v, er := r.Scalar(ctx, slot, *slots.Type.Subtype)
			if er != nil {
				return fmt.Errorf("cache slot %#x: %w", slot, er)
			}
			if v == 0 {
				continue
			}
			if i > (^uint64(0)-index)>>shift {
				return fmt.Errorf("cache index overflow")
			}
			if er = walkValue(v, index+(i<<shift), shift, slot, height-1); er != nil {
				return er
			}
		}
		return nil
	}
	slot, err := r.Field(rootType, headField)
	if err != nil {
		return stats, err
	}
	slotAddr, err := memory.Add(root, slot.Offset)
	if err != nil {
		return stats, err
	}
	if head == 0 {
		return stats, nil
	}
	var height uint64
	if !xa {
		if _, er := r.Field(rootType, "height"); er == nil {
			height, err = r.Uint(ctx, root, rootType, "height")
			if err != nil {
				return stats, err
			}
		} else if !errors.Is(er, object.ErrFieldAbsent) {
			return stats, er
		}
		if height > maxHeight {
			return stats, fmt.Errorf("invalid root height")
		}
	}
	taggedNode := xa && head&3 == 2 && head >= 4096 || !xa && head&3 == 1
	if taggedNode || height > 0 {
		node := head &^ 3
		if xa || taggedNode {
			actual, er := heightAt(node)
			if er != nil {
				return stats, er
			}
			if height != 0 && height != actual {
				return stats, fmt.Errorf("root/node height mismatch")
			}
			height = actual
		}
		if head&3 != 0 && !taggedNode {
			return stats, fmt.Errorf("invalid root node tag")
		}
		err = walkNode(node, 0, height)
	} else {
		err = walkValue(head, 0, 0, slotAddr, 0)
	}
	return stats, err
}
