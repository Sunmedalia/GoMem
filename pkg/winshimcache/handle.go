package winshimcache

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// HandleReader composes the original resource, AVL and linked-entry predicates.
// It requires a selected non-XP layout and the image's own kernel types.
type HandleReader struct {
	layer                                  memory.MemoryLayer
	avl                                    Reader
	resource                               *ResourceReader
	entry                                  *LinkedEntryReader
	mask                                   uint64
	width                                  int
	resourceOffset, tableOffset, tableSize uint64
	LayoutSHA256                           string
	// LayoutAnomalies must accompany discovery evidence. Some shipped layouts
	// declare a handle smaller than its fields; original objects still read them.
	LayoutAnomalies []string
}

func NewHandleReader(layer memory.MemoryLayer, raw []byte, kernel *symbols.ISF, mask uint64) (*HandleReader, error) {
	entry, err := NewLinkedEntryReader(layer, raw, kernel, mask)
	if err != nil {
		return nil, err
	}
	avl, err := ParseAVLLayout(raw)
	if err != nil {
		return nil, err
	}
	resource, err := NewResourceReader(layer, kernel)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Types map[string]symbols.Type `json:"user_types"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	handle, ok := doc.Types["SHIM_CACHE_HANDLE"]
	if !ok || handle.Kind != "struct" || handle.Size == 0 || handle.Size > 1<<20 {
		return nil, fmt.Errorf("invalid Shimcache handle type")
	}
	r := &HandleReader{layer: layer, avl: Reader{Layer: layer, Layout: avl}, resource: resource, entry: entry, mask: mask, width: kernel.PointerSize(), tableSize: avl.Types.Types["_RTL_AVL_TABLE"].Size, LayoutSHA256: entry.LayoutSHA256}
	for _, name := range []string{"eresource", "rtl_avl_table"} {
		f, ok := handle.Fields[name]
		if !ok || f.Offset > 1<<20 || f.Type.Kind != "pointer" || f.Type.Subtype == nil || f.Type.Subtype.Kind != "struct" || f.Type.Base != "" && f.Type.Base != "pointer" {
			return nil, fmt.Errorf("invalid Shimcache handle field %s", name)
		}
		want := "_RTL_AVL_TABLE"
		if name == "eresource" {
			want = "nt_symbols!_ERESOURCE"
		}
		if f.Type.Subtype.Name != want {
			return nil, fmt.Errorf("invalid Shimcache handle target %s", name)
		}
		if f.Offset > handle.Size || uint64(r.width) > handle.Size-f.Offset {
			r.LayoutAnomalies = append(r.LayoutAnomalies, fmt.Sprintf("SHIM_CACHE_HANDLE.%s at %#x (%d bytes) exceeds declared size %#x; retained original field offset", name, f.Offset, r.width, handle.Size))
		}
		if name == "eresource" {
			r.resourceOffset = f.Offset
		} else {
			r.tableOffset = f.Offset
		}
	}
	return r, nil
}

func (r *HandleReader) pointer(ctx context.Context, at, offset uint64) (uint64, error) {
	storage, err := memory.Add(at, offset)
	if err != nil {
		return 0, err
	}
	raw, err := memory.Read(ctx, r.layer, storage, r.width)
	if err != nil {
		return 0, err
	}
	if r.width == 4 {
		return uint64(binary.LittleEndian.Uint32(raw)) & r.mask, nil
	}
	return binary.LittleEndian.Uint64(raw) & r.mask, nil
}

// Head mirrors the original property: it validates the resource, probes the AVL
// pointer's STORAGE byte, and validates an entry after the target table's SIZE.
// It does not validate the AVL itself, or require the table target to be mapped.
func (r *HandleReader) Head(ctx context.Context, at uint64) (head uint64, valid bool, err error) {
	if err = ctx.Err(); err != nil {
		return 0, false, err
	}
	if r == nil || r.layer == nil {
		return 0, false, fmt.Errorf("missing Shimcache handle reader")
	}
	resource, err := r.pointer(ctx, at, r.resourceOffset)
	if err != nil {
		return 0, false, err
	}
	valid, err = r.resource.validMasked(ctx, resource, r.mask)
	if err != nil || !valid {
		return 0, false, err
	}
	table, err := r.pointer(ctx, at, r.tableOffset)
	if err != nil {
		return 0, false, err
	}
	storage, err := memory.Add(at, r.tableOffset)
	if err != nil {
		return 0, false, err
	}
	if _, err = memory.Read(ctx, r.layer, storage, 1); err != nil {
		return 0, false, err
	}
	head, err = memory.Add(table, r.tableSize)
	if err != nil {
		return 0, false, err
	}
	valid, err = r.entry.Valid(ctx, head)
	if err != nil || !valid {
		return 0, false, err
	}
	return head, true, nil
}

// Valid follows SHIM_CACHE_HANDLE.is_valid, including its zero-handle guard and
// repeated head properties. Read probes are explicit evidence reads, and native
// subreaders revalidate fields rather than hiding repeated reads behind Python
// object caches. On a static image these yield the same predicate result.
func (r *HandleReader) Valid(ctx context.Context, at, pageStart, pageEnd uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if r == nil || r.layer == nil {
		return false, fmt.Errorf("missing Shimcache handle reader")
	}
	if at == 0 {
		return false, nil
	}
	if _, err := memory.Read(ctx, r.layer, at, 1); err != nil {
		return false, err
	}
	resource, err := r.pointer(ctx, at, r.resourceOffset)
	if err != nil {
		return false, err
	}
	valid, err := r.resource.validMasked(ctx, resource, r.mask)
	if err != nil || !valid {
		return false, err
	}
	table, err := r.pointer(ctx, at, r.tableOffset)
	if err != nil {
		return false, err
	}
	valid, err = r.avl.avlValidMasked(ctx, table, pageStart, pageEnd, r.mask)
	if err != nil || !valid {
		return false, err
	}
	if _, valid, err = r.Head(ctx, at); err != nil || !valid {
		return false, err
	}
	_, valid, err = r.Head(ctx, at)
	return valid, err
}
