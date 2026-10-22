package wingui

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// WindowRef separates the original displayed offset (which can be a pointer
// field) from the address at which the window's members are actually read.
type WindowRef struct {
	Offset, Address uint64
	Name            Name
	NameError       error
}

type WindowWalkOptions struct {
	MaxWindows, MaxSteps, MaxDepth uint64
}

type windowWalkNode struct {
	offset, address   uint64
	pointer           bool
	body, next, child *windowWalkNode
}

// Windows follows the pinned generator's mixed pointer/object semantics. The
// initial spwnd and child links remain pointer objects, whereas adjacent links
// are dereferenced. Python's object-set child order is not stable across runs;
// this reader visits those parents in discovery order. Every other offset and
// duplicate decision is explicit. Limits and faults preserve the emitted prefix.
func (r Reader) Windows(ctx context.Context, desktop uint64, opts WindowWalkOptions, emit func(WindowRef) error) error {
	if emit == nil || opts.MaxWindows == 0 || opts.MaxWindows > 1000000 || opts.MaxSteps == 0 || opts.MaxSteps > 10000000 || opts.MaxDepth == 0 || opts.MaxDepth > 256 {
		return fmt.Errorf("invalid GUI window traversal emitter or bounds")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	o, err := r.objects()
	if err != nil {
		return err
	}
	info, err := o.Uint(ctx, desktop, "tagDESKTOP", "pDeskInfo")
	if err != nil {
		return err
	}
	f, err := o.Field("tagDESKTOPINFO", "spwnd")
	if err != nil {
		return err
	}
	rootOffset, err := memory.Add(info, f.Offset)
	if err != nil {
		return err
	}
	rootAddress, err := o.Uint(ctx, info, "tagDESKTOPINFO", "spwnd")
	if err != nil {
		return err
	}
	root := &windowWalkNode{offset: rootOffset, address: rootAddress, pointer: true}
	seen := map[uint64]bool{}
	active := map[[2]uint64]bool{}
	var steps, failures uint64
	var first error
	fail := func(err error) {
		if err != nil {
			failures++
			if first == nil {
				first = err
			}
		}
	}
	budget := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if steps >= opts.MaxSteps {
			return fmt.Errorf("GUI window step bound exhausted")
		}
		steps++
		return nil
	}
	stop := errors.New("GUI window output bound exhausted")
	var deref func(*windowWalkNode) *windowWalkNode
	deref = func(n *windowWalkNode) *windowWalkNode {
		if !n.pointer {
			return n
		}
		if n.body == nil {
			n.body = &windowWalkNode{offset: n.address, address: n.address}
		}
		return n.body
	}
	link := func(n *windowWalkNode, member string) (*windowWalkNode, error) {
		if err := budget(); err != nil {
			return nil, err
		}
		body := deref(n)
		cached := &body.next
		if member == "spwndChild" {
			cached = &body.child
		}
		if *cached != nil {
			return *cached, nil
		}
		f, err := o.Field("tagWND", member)
		if err != nil {
			return nil, err
		}
		at, err := memory.Add(body.address, f.Offset)
		if err != nil {
			return nil, err
		}
		value, err := o.Uint(ctx, body.address, "tagWND", member)
		if err != nil {
			return nil, err
		}
		*cached = &windowWalkNode{offset: at, address: value, pointer: true}
		return *cached, nil
	}
	yield := func(n *windowWalkNode) error {
		if err := budget(); err != nil {
			return err
		}
		name, nameErr := r.WindowName(ctx, n.address)
		fail(nameErr)
		if err := ctx.Err(); err != nil {
			return err
		}
		if seen[n.offset] {
			return nil
		}
		seen[n.offset] = true
		if err := emit(WindowRef{Offset: n.offset, Address: n.address, Name: name, NameError: nameErr}); err != nil {
			return err
		}
		if uint64(len(seen)) == opts.MaxWindows {
			return stop
		}
		return nil
	}
	var walk func(*windowWalkNode, uint64) error
	walk = func(root *windowWalkNode, depth uint64) error {
		if err := budget(); err != nil {
			return err
		}
		if root.offset == 0 {
			return nil
		}
		if depth >= opts.MaxDepth {
			fail(fmt.Errorf("GUI window depth bound exhausted"))
			return nil
		}
		key := [2]uint64{root.offset, root.address}
		if active[key] {
			fail(fmt.Errorf("GUI window child cycle at 0x%x (target 0x%x)", root.offset, root.address))
			return nil
		}
		active[key] = true
		defer delete(active, key)
		if err := yield(root); err != nil {
			return err
		}
		parents := []*windowWalkNode{root}
		current := root
		for uint64(len(parents)) < opts.MaxWindows {
			next, err := link(current, "spwndNext")
			if err != nil {
				if ctx.Err() != nil || steps >= opts.MaxSteps {
					return err
				}
				fail(err)
				break
			}
			current = deref(next)
			if current.offset == 0 {
				break
			}
			// Struct instances use identity hashes in the original. Only the
			// initial pointer can compare equal to an integer address here.
			if root.pointer && current.offset == root.address {
				break
			}
			if err := yield(current); err != nil {
				return err
			}
			parents = append(parents, current)
		}
		if uint64(len(parents)) == opts.MaxWindows {
			fail(fmt.Errorf("GUI adjacent-window bound exhausted"))
		}
		children := map[uint64]bool{}
		for _, parent := range parents {
			child := parent
			for uint64(len(parents)+len(children)) < opts.MaxWindows {
				next, err := link(child, "spwndChild")
				if err != nil {
					if ctx.Err() != nil || steps >= opts.MaxSteps {
						return err
					}
					fail(err)
					break
				}
				child = next
				if child.offset == 0 || children[child.address] {
					break
				}
				children[child.address] = true
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		if uint64(len(parents)+len(children)) == opts.MaxWindows {
			fail(fmt.Errorf("GUI child-window bound exhausted"))
		}
		return nil
	}
	err = walk(root, 0)
	if first != nil {
		return errors.Join(fmt.Errorf("GUI window traversal: %d failures; first: %w", failures, first), err)
	}
	return err
}
