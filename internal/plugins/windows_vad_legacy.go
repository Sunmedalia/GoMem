package plugins

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Legacy roots can be a direct VAD pointer or an inline AVL sentinel. Later
// roots can point to MM_AVL_NODE rather than RTL_BALANCED_NODE. Link fields are
// resolved from the actual node type; ranges use the pool-tag-selected VAD type.
func windowsLegacyVADRegions(ctx context.Context, e plugin.Environment, process uint64, max int) ([]windowsVADPath, error) {
	rootField, err := e.Objects.Field("_EPROCESS", "VadRoot")
	if err != nil {
		return nil, err
	}
	rootType := "_MMVAD"
	sentinel := false
	var root uint64
	if rootField.Type.Kind == "pointer" {
		root, err = e.Objects.Uint(ctx, process, "_EPROCESS", "VadRoot")
	} else if f, fieldErr := e.Objects.Field("_EPROCESS", "VadRoot.BalancedRoot"); fieldErr == nil {
		root, err = memory.Add(process, f.Offset)
		rootType = f.Type.Name
		sentinel = true
	} else if errors.Is(fieldErr, object.ErrFieldAbsent) {
		var f symbols.Field
		f, err = e.Objects.Field("_EPROCESS", "VadRoot.Root")
		if err == nil {
			if f.Type.Kind != "pointer" || f.Type.Subtype == nil {
				return nil, fmt.Errorf("VAD Root is not a typed pointer")
			}
			rootType = f.Type.Subtype.Name
			root, err = e.Objects.Uint(ctx, process, "_EPROCESS", "VadRoot.Root")
		}
	} else {
		return nil, fieldErr
	}
	if err != nil {
		return nil, err
	}
	if root == 0 {
		return nil, nil
	}
	type frame struct {
		node, parent uint64
		typ          string
		depth        int
	}
	stack := []frame{{node: root, typ: rootType}}
	seen := map[uint64]bool{}
	var regions []windowsVADPath
	bias := uint64(12)
	if e.Symbols.PointerSize() == 4 {
		bias = 4
	}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.node == 0 {
			continue
		}
		if item.depth > 128 || len(seen) >= max || seen[item.node] {
			return nil, fmt.Errorf("VAD tree cycle, depth or node limit at %#x", item.node)
		}
		seen[item.node] = true
		isSentinel := sentinel && item.depth == 0
		tag := ""
		if !isSentinel {
			if item.node < bias {
				return nil, fmt.Errorf("VAD pool tag underflow")
			}
			raw, err := memory.Read(ctx, e.Kernel, item.node-bias, 4)
			if err != nil {
				return nil, err
			}
			tag = string(raw)
			if !strings.HasPrefix(tag, "Vad") {
				return nil, fmt.Errorf("unrecognized VAD pool tag %q at %#x", tag, item.node)
			}
		}
		leftPath, leftField, err := windowsVADField(e, item.typ, []string{"LeftChild", "Left", "VadNode.LeftChild", "VadNode.Left", "Core.VadNode.LeftChild", "Core.VadNode.Left"})
		if err != nil {
			return nil, err
		}
		rightPath, rightField, err := windowsVADField(e, item.typ, []string{"RightChild", "Right", "VadNode.RightChild", "VadNode.Right", "Core.VadNode.RightChild", "Core.VadNode.Right"})
		if err != nil {
			return nil, err
		}
		left, err := e.Objects.Uint(ctx, item.node, item.typ, leftPath)
		if err != nil {
			return nil, err
		}
		right, err := e.Objects.Uint(ctx, item.node, item.typ, rightPath)
		if err != nil {
			return nil, err
		}
		if !isSentinel {
			parentPath, _, err := windowsVADField(e, item.typ, []string{"Parent", "u1.Parent", "ParentValue", "VadNode.u1.Parent", "VadNode.ParentValue", "Core.VadNode.u1.Parent", "Core.VadNode.ParentValue"})
			if err != nil {
				return nil, err
			}
			parent, err := e.Objects.Uint(ctx, item.node, item.typ, parentPath)
			if err != nil {
				return nil, err
			}
			if parentPath != "Parent" {
				parent &^= 3
			}
			if parent != item.parent {
				return nil, fmt.Errorf("VAD parent mismatch at %#x", item.node)
			}
			typ := "_MMVAD"
			if tag == "VadS" || tag == "VadF" {
				typ = "_MMVAD_SHORT"
			}
			start, end, err := windowsVADRange(ctx, e, item.node, typ)
			if err != nil {
				return nil, err
			}
			path := evidence.Missing("not_file_backed", nil)
			if typ == "_MMVAD" {
				path = windowsVADFile(ctx, e, item.node)
			}
			regions = append(regions, windowsVADPath{start: start, end: end, address: item.node, parent: item.parent, left: left, right: right, tag: tag, file: path})
		}
		childType := func(f symbols.Field) (string, error) {
			if f.Type.Kind != "pointer" || f.Type.Subtype == nil || f.Type.Subtype.Name == "" {
				return "", fmt.Errorf("VAD child is not a typed pointer")
			}
			return f.Type.Subtype.Name, nil
		}
		leftType, err := childType(leftField)
		if err != nil {
			return nil, err
		}
		rightType, err := childType(rightField)
		if err != nil {
			return nil, err
		}
		stack = append(stack, frame{right, item.node, rightType, item.depth + 1}, frame{left, item.node, leftType, item.depth + 1})
	}
	return regions, nil
}

func windowsVADField(e plugin.Environment, typ string, paths []string) (string, symbols.Field, error) {
	for _, path := range paths {
		f, err := e.Objects.Field(typ, path)
		if err == nil {
			return path, f, nil
		}
		if !errors.Is(err, object.ErrFieldAbsent) {
			return "", symbols.Field{}, err
		}
	}
	return "", symbols.Field{}, fmt.Errorf("no supported VAD field in %s for %v", typ, paths)
}

func windowsVADRange(ctx context.Context, e plugin.Environment, address uint64, typ string) (uint64, uint64, error) {
	read := func(name string) (uint64, uint64, error) {
		path, _, err := windowsVADField(e, typ, []string{name, "Core." + name})
		if err != nil {
			return 0, 0, err
		}
		low, err := e.Objects.Uint(ctx, address, typ, path)
		if err != nil {
			return 0, 0, err
		}
		var high uint64
		if _, err := e.Objects.Field(typ, path+"High"); err == nil {
			high, err = e.Objects.Uint(ctx, address, typ, path+"High")
			if err != nil {
				return 0, 0, err
			}
			if low > 0xffffffff || high > 0xff {
				return 0, 0, fmt.Errorf("invalid VAD VPN width")
			}
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return 0, 0, err
		}
		if low >= uint64(1)<<52 {
			return 0, 0, fmt.Errorf("invalid VAD VPN width")
		}
		return low, high, nil
	}
	first, firstHigh, err := read("StartingVpn")
	if err != nil {
		return 0, 0, err
	}
	last, lastHigh, err := read("EndingVpn")
	if err != nil {
		return 0, 0, err
	}
	start := (first << 12) | (firstHigh << 44)
	// Preserve the pinned OR-before-subtraction arithmetic at a low-word rollover.
	end := (((last + 1) << 12) | (lastHigh << 44)) - 1
	if start > end {
		return 0, 0, fmt.Errorf("invalid VAD address range")
	}
	return start, end, nil
}
