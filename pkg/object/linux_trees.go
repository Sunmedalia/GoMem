package object

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// WalkHList follows hlist_head.first and verifies each hlist_node.pprev points
// to the slot that actually contained it. It does not accept tagged bl_hlists.
func (r *Reader) WalkHList(ctx context.Context, head, offset uint64, max int, emit func(uint64) error) error {
	if max < 1 || max > 1000000 {
		return fmt.Errorf("invalid hlist limit")
	}
	first, err := r.Field("hlist_head", "first")
	if err != nil {
		return err
	}
	slot, err := memory.Add(head, first.Offset)
	if err != nil {
		return err
	}
	next, err := r.Uint(ctx, head, "hlist_head", "first")
	if err != nil {
		return err
	}
	seen := map[uint64]bool{}
	width := uint64(r.Symbols.PointerSize())
	if width != 4 && width != 8 {
		return fmt.Errorf("unsupported hlist pointer width")
	}
	for next != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if next < offset || next%width != 0 || seen[next] {
			return fmt.Errorf("invalid/cyclic hlist node %#x", next)
		}
		if len(seen) >= max {
			return fmt.Errorf("hlist exceeds %d nodes", max)
		}
		seen[next] = true
		previous, err := r.Uint(ctx, next, "hlist_node", "pprev")
		if err != nil {
			return err
		}
		if previous != slot {
			return fmt.Errorf("hlist pprev mismatch at %#x", next)
		}
		if err = emit(next - offset); err != nil {
			return err
		}
		field, err := r.Field("hlist_node", "next")
		if err != nil {
			return err
		}
		slot, err = memory.Add(next, field.Offset)
		if err != nil {
			return err
		}
		next, err = r.Uint(ctx, next, "hlist_node", "next")
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

// WalkRBTree emits containers in order and verifies unique, aligned nodes and
// parent pointers. This checks captured structure, not red/black balancing.
func (r *Reader) WalkRBTree(ctx context.Context, root, offset uint64, max int, emit func(uint64) error) error {
	if max < 1 || max > 1000000 {
		return fmt.Errorf("invalid rb-tree limit")
	}
	next, err := r.Uint(ctx, root, "rb_root", "rb_node")
	if err != nil {
		return err
	}
	width := uint64(r.Symbols.PointerSize())
	if width != 4 && width != 8 {
		return fmt.Errorf("unsupported rb-tree pointer width")
	}
	type frame struct {
		node, parent uint64
		emit         bool
	}
	stack := []frame{{node: next}}
	seen := map[uint64]bool{}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.node == 0 {
			continue
		}
		if f.emit {
			if err := emit(f.node - offset); err != nil {
				return err
			}
			continue
		}
		if f.node < offset || f.node%width != 0 || seen[f.node] {
			return fmt.Errorf("invalid/cyclic rb-tree node %#x", f.node)
		}
		if len(seen) >= max {
			return fmt.Errorf("rb-tree exceeds %d nodes", max)
		}
		seen[f.node] = true
		parent, err := r.Uint(ctx, f.node, "rb_node", "__rb_parent_color")
		if err != nil {
			return err
		}
		if parent&^3 != f.parent {
			return fmt.Errorf("rb-tree parent mismatch at %#x", f.node)
		}
		left, err := r.Uint(ctx, f.node, "rb_node", "rb_left")
		if err != nil {
			return err
		}
		right, err := r.Uint(ctx, f.node, "rb_node", "rb_right")
		if err != nil {
			return err
		}
		stack = append(stack, frame{node: right, parent: f.node}, frame{node: f.node, emit: true}, frame{node: left, parent: f.node})
	}
	return ctx.Err()
}
