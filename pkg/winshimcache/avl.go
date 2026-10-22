// Package winshimcache parses native Windows Shimcache memory structures.
package winshimcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Layout struct {
	Types  *symbols.ISF
	SHA256 string
}

// ParseAVLLayout projects only the self-contained AVL validation fields. Entry,
// handle and external kernel types require separate validation before use.
func ParseAVLLayout(raw []byte) (*Layout, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fmt.Errorf("invalid Shimcache layout size")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var source map[string]symbols.Type
	if err := json.Unmarshal(doc["user_types"], &source); err != nil {
		return nil, err
	}
	required := map[string][]string{"_RTL_AVL_TABLE": {"BalancedRoot", "AllocateRoutine", "CompareRoutine", "FreeRoutine"}, "_RTL_BALANCED_LINKS": {"Parent"}}
	projected := map[string]symbols.Type{}
	for name, members := range required {
		src, ok := source[name]
		if !ok || src.Kind != "struct" || src.Size < 4 || src.Size > 1<<20 {
			return nil, fmt.Errorf("invalid Shimcache type %s", name)
		}
		dst := symbols.Type{Kind: src.Kind, Size: src.Size, Fields: map[string]symbols.Field{}}
		for _, member := range members {
			f, ok := src.Fields[member]
			if !ok {
				return nil, fmt.Errorf("missing Shimcache field %s.%s", name, member)
			}
			dst.Fields[member] = f
		}
		projected[name] = dst
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, err
	}
	doc["user_types"] = encoded
	doc["enums"] = json.RawMessage(`{}`)
	doc["symbols"] = json.RawMessage(`{}`)
	encoded, err = json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	table, err := symbols.Parse(encoded)
	if err != nil {
		return nil, err
	}
	if width := table.PointerSize(); width != 4 && width != 8 {
		return nil, fmt.Errorf("unsupported Shimcache pointer width %d", width)
	}
	if p := table.Bases["pointer"]; p.Endian != "little" || p.Signed {
		return nil, fmt.Errorf("invalid Shimcache pointer representation")
	}
	o := &object.Reader{Symbols: table}
	for name, members := range required {
		for _, member := range members {
			f, err := o.Field(name, member)
			if err != nil {
				return nil, err
			}
			if member == "BalancedRoot" {
				if f.Type.Kind != "struct" || f.Type.Name != "_RTL_BALANCED_LINKS" {
					return nil, fmt.Errorf("invalid Shimcache BalancedRoot")
				}
				continue
			}
			if f.Type.Kind != "pointer" || f.Type.Subtype == nil {
				return nil, fmt.Errorf("invalid Shimcache pointer %s.%s", name, member)
			}
			if member == "Parent" && (f.Type.Subtype.Kind != "struct" || f.Type.Subtype.Name != "_RTL_BALANCED_LINKS") {
				return nil, fmt.Errorf("invalid Shimcache parent target")
			}
		}
	}
	digest := sha256.Sum256(raw)
	return &Layout{Types: table, SHA256: hex.EncodeToString(digest[:])}, nil
}

type Reader struct {
	Layer  memory.MemoryLayer
	Layout *Layout
}

// AVLValid mirrors the pinned RTL_AVL_TABLE.is_valid predicate. The PAGE end is
// inclusive. Routine storage addresses, not pointer values, must be distinct;
// FreeRoutine is read but its target is not range checked. A read error remains
// distinct from a readable but rejected candidate.
func (r Reader) AVLValid(ctx context.Context, at, pageStart, pageEnd uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if r.Layer == nil || r.Layout == nil || r.Layout.Types == nil {
		return false, fmt.Errorf("Shimcache AVL requires layer and layout")
	}
	o := &object.Reader{Layer: r.Layer, Symbols: r.Layout.Types}
	root, err := o.Field("_RTL_AVL_TABLE", "BalancedRoot")
	if err != nil {
		return false, err
	}
	rootAt, err := memory.Add(at, root.Offset)
	if err != nil {
		return false, err
	}
	parent, err := o.Uint(ctx, at, "_RTL_AVL_TABLE", "BalancedRoot.Parent")
	if err != nil {
		return false, err
	}
	if parent != rootAt {
		return false, nil
	}
	var storage [3]uint64
	for i, member := range []string{"AllocateRoutine", "CompareRoutine", "FreeRoutine"} {
		f, err := o.Field("_RTL_AVL_TABLE", member)
		if err != nil {
			return false, err
		}
		storage[i], err = memory.Add(at, f.Offset)
		if err != nil {
			return false, err
		}
		value, err := o.Uint(ctx, at, "_RTL_AVL_TABLE", member)
		if err != nil {
			return false, err
		}
		if i < 2 && (value < pageStart || value > pageEnd) {
			return false, nil
		}
		if i == 1 && storage[0] == storage[1] {
			return false, nil
		}
	}
	return storage[0] != storage[1] && storage[0] != storage[2] && storage[1] != storage[2], nil
}
