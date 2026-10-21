package object

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// LatchMatch describes the selected captured tree and the search path length.
// Found is independent of Node, since a container address may be zero.
type LatchMatch struct {
	Found                                  bool
	Node, RBNode, Sequence, Index, Visited uint64
}

// FindLatchTree searches the sequence-selected copy of a Linux latch tree.
// compare returns negative/zero/positive for key before/inside/after a node.
// Node coordinates follow the locked Volatility 2.28.2 extension's pointer-size
// subtraction for node[index], including its difference from the rb_node stride.
// The caller supplies source-specific interval semantics and records acquisitions
// through Layer. Invalid layouts, unreadable nodes, cycles, bounds and callback
// errors are explicit failures, not evidence that the key is absent.
func (r *Reader) FindLatchTree(ctx context.Context, root, key uint64, max int, compare func(context.Context, uint64, uint64) (int, error)) (LatchMatch, error) {
	var result LatchMatch
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if r == nil || r.Layer == nil || r.Symbols == nil || compare == nil || max < 1 || max > 1000000 {
		return result, fmt.Errorf("invalid latch-tree reader, comparator or bound")
	}
	width := uint64(r.Symbols.PointerSize())
	if width != 4 && width != 8 {
		return result, fmt.Errorf("unsupported latch-tree pointer width")
	}
	seq, err := r.Field("latch_tree_root", "seq")
	if err != nil {
		return result, err
	}
	if seq.Type.Kind != "struct" {
		return result, fmt.Errorf("latch-tree sequence is not embedded")
	}
	path := "seq.sequence"
	_, err = r.Field(seq.Type.Name, "seqcount")
	if err == nil {
		path = "seq.seqcount.sequence"
	} else if !errors.Is(err, ErrFieldAbsent) {
		return result, err
	}
	result.Sequence, err = r.Uint(ctx, root, "latch_tree_root", path)
	if err != nil {
		return result, err
	}
	result.Index = result.Sequence & 1
	tree, err := r.Field("latch_tree_root", "tree")
	if err != nil {
		return result, err
	}
	if tree.Type.Kind != "array" || tree.Type.Count < 2 || tree.Type.Subtype == nil || tree.Type.Subtype.Kind != "struct" || tree.Type.Subtype.Name != "rb_root" {
		return result, fmt.Errorf("invalid latch-tree root array")
	}
	rootSize, err := r.Size(*tree.Type.Subtype)
	if err != nil {
		return result, err
	}
	at, err := memory.Add(root, tree.Offset)
	if err != nil {
		return result, err
	}
	at, err = memory.Add(at, result.Index*rootSize)
	if err != nil {
		return result, err
	}
	nodes, err := r.Field("latch_tree_node", "node")
	if err != nil {
		return result, err
	}
	if nodes.Type.Kind != "array" || nodes.Type.Count < 2 || nodes.Type.Subtype == nil || nodes.Type.Subtype.Kind != "struct" || nodes.Type.Subtype.Name != "rb_node" {
		return result, fmt.Errorf("invalid latch-tree node array")
	}
	displacement, err := memory.Add(nodes.Offset, result.Index*width)
	if err != nil {
		return result, err
	}
	for _, field := range []struct{ typ, name string }{{"rb_root", "rb_node"}, {"rb_node", "rb_left"}, {"rb_node", "rb_right"}} {
		f, err := r.Field(field.typ, field.name)
		if err != nil {
			return result, err
		}
		if f.Type.Kind != "pointer" {
			return result, fmt.Errorf("%s.%s is not a pointer", field.typ, field.name)
		}
		size, err := r.Size(f.Type)
		if err != nil {
			return result, err
		}
		if size != width {
			return result, fmt.Errorf("%s.%s pointer width differs from kernel", field.typ, field.name)
		}
	}
	rbType, err := r.Symbols.Type("rb_node")
	if err != nil {
		return result, err
	}
	if rbType.Size == 0 || rbType.Size > memory.MaxRead {
		return result, fmt.Errorf("invalid rb_node size")
	}
	next, err := r.Uint(ctx, at, "rb_root", "rb_node")
	if err != nil {
		return result, err
	}
	seen := map[uint64]bool{}
	for next != 0 {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if next%width != 0 || next < displacement || seen[next] {
			return result, fmt.Errorf("invalid/cyclic latch-tree node %#x", next)
		}
		if len(seen) >= max {
			return result, fmt.Errorf("latch-tree exceeds %d nodes", max)
		}
		seen[next] = true
		result.Visited++
		// Match the extension's full pointed rb_node readability gate. Parent/color
		// is captured but not used to assert balancing or whole-tree integrity.
		if _, err := memory.Read(ctx, r.Layer, next, int(rbType.Size)); err != nil {
			return result, err
		}
		node := next - displacement
		order, err := compare(ctx, key, node)
		if err != nil {
			return result, err
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if order == 0 {
			result.Found = true
			result.Node = node
			result.RBNode = next
			return result, nil
		}
		field := "rb_right"
		if order < 0 {
			field = "rb_left"
		}
		next, err = r.Uint(ctx, next, "rb_node", field)
		if err != nil {
			return result, err
		}
	}
	return result, ctx.Err()
}
