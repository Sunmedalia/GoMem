package winshimcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// LinkedEntryReader validates the non-XP entry heuristic, not the complete
// doubly linked list. The original compares separately instantiated structures
// by identity, so equal Flink/Blink values do not by themselves reject an entry.
type LinkedEntryReader struct {
	reader       object.Reader
	listOffset   uint64
	mask         uint64
	LayoutSHA256 string
}

// NewLinkedEntryReader requires explicit kernel types and the native layer's
// pointer address mask. XP entries have a different predicate and are rejected.
func NewLinkedEntryReader(layer memory.MemoryLayer, raw []byte, kernel *symbols.ISF, mask uint64) (*LinkedEntryReader, error) {
	if layer == nil || kernel == nil || len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fmt.Errorf("linked Shimcache entry requires bounded layout, layer and kernel symbols")
	}
	width := kernel.PointerSize()
	if width != 4 && width != 8 {
		return nil, fmt.Errorf("unsupported entry pointer width")
	}
	maximum := uint64(math.MaxUint64)
	if width == 4 {
		maximum = math.MaxUint32
	}
	if mask == 0 || mask > maximum || mask&(mask+1) != 0 {
		return nil, fmt.Errorf("invalid entry native address mask")
	}
	p := kernel.Bases["pointer"]
	if p.Endian != "little" || p.Signed {
		return nil, fmt.Errorf("invalid kernel entry pointer representation")
	}
	var doc struct {
		Bases map[string]symbols.Type `json:"base_types"`
		Types map[string]symbols.Type `json:"user_types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	p = doc.Bases["pointer"]
	if p.Size != uint64(width) || p.Endian != "little" || p.Signed {
		return nil, fmt.Errorf("entry/kernel pointer representation mismatch")
	}
	entry, ok := doc.Types["SHIM_CACHE_ENTRY"]
	if !ok || entry.Kind != "struct" || entry.Size == 0 || entry.Size > 1<<20 {
		return nil, fmt.Errorf("invalid Shimcache entry type")
	}
	f, ok := entry.Fields["ListEntry"]
	if !ok || f.Type.Kind != "struct" || f.Type.Name != "nt_symbols!_LIST_ENTRY" {
		return nil, fmt.Errorf("missing or invalid Shimcache entry ListEntry")
	}
	list, err := kernel.Type("_LIST_ENTRY")
	if err != nil || list.Kind != "struct" || list.Size == 0 || list.Size > 1<<20 || f.Offset > entry.Size || list.Size > entry.Size-f.Offset {
		return nil, fmt.Errorf("invalid Shimcache embedded list extent")
	}
	r := &LinkedEntryReader{reader: object.Reader{Layer: layer, Symbols: kernel}, listOffset: f.Offset, mask: mask}
	for _, name := range []string{"Flink", "Blink"} {
		field, err := r.reader.Field("_LIST_ENTRY", name)
		if err != nil {
			return nil, err
		}
		if field.Type.Kind != "pointer" || field.Type.Subtype == nil || field.Type.Subtype.Kind != "struct" || field.Type.Subtype.Name != "_LIST_ENTRY" || field.Type.Base != "" && field.Type.Base != "pointer" {
			return nil, fmt.Errorf("invalid Shimcache entry link %s", name)
		}
	}
	digest := sha256.Sum256(raw)
	r.LayoutSHA256 = hex.EncodeToString(digest[:])
	return r, nil
}

// Valid performs at most three scalar reads, preserving the original's weak
// predicate and short circuiting. Blink's target is never read. The forward
// link's Blink pointer is masked when constructed by the original and compared
// with its own dereference address, not this entry. This last check is always
// true if that pointer can be read. Faults remain errors for evidence retention.
func (r *LinkedEntryReader) Valid(ctx context.Context, at uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if r == nil || r.reader.Layer == nil || r.reader.Symbols == nil {
		return false, fmt.Errorf("missing linked entry reader")
	}
	listAt, err := memory.Add(at, r.listOffset)
	if err != nil {
		return false, err
	}
	flink, err := r.reader.Uint(ctx, listAt, "_LIST_ENTRY", "Flink")
	flink &= r.mask
	if err != nil || flink == 0 {
		return false, err
	}
	if _, err = r.reader.Uint(ctx, listAt, "_LIST_ENTRY", "Blink"); err != nil {
		return false, err
	}
	_, err = r.reader.Uint(ctx, flink, "_LIST_ENTRY", "Blink")
	return err == nil, err
}
