package winshimcache

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// TemporalField retains the evidence for one original Shimcache property.
// Complete describes whether the attempted memory read completed; semantic
// absence and unparsable values still count as a completed operation.
type TemporalField struct {
	Value     evidence.Value
	Address   uint64
	Requested uint64
	Raw       []byte
	Complete  bool
}

type temporalExecKind uint8

const (
	temporalExecNone temporalExecKind = iota
	temporalExecDetailInsert
	temporalExecDirectInsert
	temporalExecDetailBlob
)

// TemporalReader implements the pinned Shimcache last_modified, last_update
// and exec_flag properties. It consumes only an explicitly selected layout and
// kernel symbol table; it does not select a layout or discover cache entries.
type TemporalReader struct {
	reader       object.Reader
	layer        memory.MemoryLayer
	mask         uint64
	width        int
	hasDetail    bool
	detailOffset uint64

	modifiedDetail bool
	modifiedOffset uint64
	hasUpdate      bool
	updateOffset   uint64

	execKind         temporalExecKind
	insertOffset     uint64
	insertWidth      int
	blobBufferOffset uint64
	blobBufferWidth  int
	blobSizeOffset   uint64
	blobSizeWidth    int
	LayoutSHA256     string
	KernelSHA256     string
}

// NewTemporalReader validates the subset of a Shimcache layout needed by the
// three properties. All field extents come from the selected data-only layout;
// scalar and _LARGE_INTEGER definitions come from the image kernel symbols.
func NewTemporalReader(layer memory.MemoryLayer, raw []byte, kernel *symbols.ISF, mask uint64) (*TemporalReader, error) {
	if layer == nil || kernel == nil || len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fmt.Errorf("Shimcache temporal fields require bounded layout, layer and kernel symbols")
	}
	width := kernel.PointerSize()
	maximum := uint64(math.MaxUint64)
	if width == 4 {
		maximum = math.MaxUint32
	}
	if width != 4 && width != 8 || mask == 0 || mask > maximum || mask&(mask+1) != 0 {
		return nil, fmt.Errorf("invalid Shimcache temporal pointer width/mask")
	}
	if p := kernel.Bases["pointer"]; p.Size != uint64(width) || p.Endian != "little" || p.Signed {
		return nil, fmt.Errorf("invalid kernel Shimcache temporal pointer representation")
	}

	var doc struct {
		Bases map[string]symbols.Type `json:"base_types"`
		Types map[string]symbols.Type `json:"user_types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if p := doc.Bases["pointer"]; p.Size != uint64(width) || p.Endian != "little" || p.Signed {
		return nil, fmt.Errorf("Shimcache temporal layout pointer mismatch")
	}
	entry, ok := doc.Types["SHIM_CACHE_ENTRY"]
	if !ok || entry.Kind != "struct" || entry.Size == 0 || entry.Size > 1<<20 {
		return nil, fmt.Errorf("invalid Shimcache temporal entry type")
	}
	large, ok := doc.Types["_LARGE_INTEGER"]
	if !ok || large.Kind != "struct" && large.Kind != "union" || large.Size != 8 {
		return nil, fmt.Errorf("invalid Shimcache _LARGE_INTEGER")
	}
	quad, ok := large.Fields["QuadPart"]
	if !ok {
		return nil, fmt.Errorf("missing Shimcache _LARGE_INTEGER.QuadPart")
	}
	largeProjection := symbols.Type{
		Kind:   large.Kind,
		Size:   large.Size,
		Fields: map[string]symbols.Field{"QuadPart": quad},
	}

	entryProjection := symbols.Type{Kind: "struct", Size: entry.Size, Fields: map[string]symbols.Field{}}
	projections := map[string]symbols.Type{"_LARGE_INTEGER": largeProjection}
	r := &TemporalReader{layer: layer, mask: mask, width: width, KernelSHA256: kernel.Digest()}

	detail, hasDetailType := doc.Types["SHIM_CACHE_ENTRY_DETAIL"]
	if field, ok := entry.Fields["ListEntryDetail"]; ok {
		if field.Type.Kind != "pointer" || field.Type.Subtype == nil || field.Type.Subtype.Kind != "struct" {
			return nil, fmt.Errorf("invalid Shimcache ListEntryDetail pointer")
		}
		if field.Type.Base != "" && field.Type.Base != "pointer" {
			return nil, fmt.Errorf("invalid Shimcache ListEntryDetail pointer base")
		}
		if normalizedTypeName(field.Type.Subtype.Name) != "SHIM_CACHE_ENTRY_DETAIL" {
			return nil, fmt.Errorf("invalid Shimcache ListEntryDetail target")
		}
		if !hasDetailType || detail.Kind != "struct" || detail.Size == 0 || detail.Size > 1<<20 {
			return nil, fmt.Errorf("missing Shimcache entry detail type")
		}
		field.Type.Subtype.Name = "SHIM_CACHE_ENTRY_DETAIL"
		entryProjection.Fields["ListEntryDetail"] = field
		r.hasDetail = true
		r.detailOffset = field.Offset
	}

	var directModified, directUpdate, directInsert *symbols.Field
	if field, ok := entry.Fields["LastModified"]; ok {
		normalized, err := normalizeLargeIntegerField(field)
		if err != nil {
			return nil, fmt.Errorf("LastModified: %w", err)
		}
		entryProjection.Fields["LastModified"] = normalized
		copy := normalized
		directModified = &copy
	}
	if field, ok := entry.Fields["LastUpdate"]; ok {
		normalized, err := normalizeLargeIntegerField(field)
		if err != nil {
			return nil, fmt.Errorf("LastUpdate: %w", err)
		}
		entryProjection.Fields["LastUpdate"] = normalized
		copy := normalized
		directUpdate = &copy
	}
	if field, ok := entry.Fields["InsertFlags"]; ok {
		if err := validateTemporalScalar(kernel, field.Type); err != nil {
			return nil, fmt.Errorf("InsertFlags: %w", err)
		}
		entryProjection.Fields["InsertFlags"] = field
		copy := field
		directInsert = &copy
	}

	var detailProjection symbols.Type
	var detailModified, detailInsert, detailBlobBuffer, detailBlobSize *symbols.Field
	if r.hasDetail {
		detailProjection = symbols.Type{Kind: "struct", Size: detail.Size, Fields: map[string]symbols.Field{}}
		if field, ok := detail.Fields["LastModified"]; ok {
			normalized, err := normalizeLargeIntegerField(field)
			if err != nil {
				return nil, fmt.Errorf("detail LastModified: %w", err)
			}
			detailProjection.Fields["LastModified"] = normalized
			copy := normalized
			detailModified = &copy
		}
		if field, ok := detail.Fields["InsertFlags"]; ok {
			if err := validateTemporalScalar(kernel, field.Type); err != nil {
				return nil, fmt.Errorf("detail InsertFlags: %w", err)
			}
			detailProjection.Fields["InsertFlags"] = field
			copy := field
			detailInsert = &copy
		}
		if field, ok := detail.Fields["BlobBuffer"]; ok {
			if err := validateTemporalScalar(kernel, field.Type); err != nil {
				return nil, fmt.Errorf("detail BlobBuffer: %w", err)
			}
			detailProjection.Fields["BlobBuffer"] = field
			copy := field
			detailBlobBuffer = &copy
		}
		if field, ok := detail.Fields["BlobSize"]; ok {
			if err := validateTemporalScalar(kernel, field.Type); err != nil {
				return nil, fmt.Errorf("detail BlobSize: %w", err)
			}
			detailProjection.Fields["BlobSize"] = field
			copy := field
			detailBlobSize = &copy
		}
		if detailBlobBuffer != nil && detailBlobSize == nil {
			return nil, fmt.Errorf("Shimcache detail BlobBuffer lacks BlobSize")
		}
	}

	switch {
	case detailModified != nil:
		r.modifiedDetail = true
		r.modifiedOffset = detailModified.Offset
	case directModified != nil:
		r.modifiedOffset = directModified.Offset
	default:
		return nil, fmt.Errorf("Shimcache entry has no LastModified field")
	}
	if directUpdate != nil {
		r.hasUpdate = true
		r.updateOffset = directUpdate.Offset
	}
	switch {
	case detailInsert != nil:
		r.execKind = temporalExecDetailInsert
		r.insertOffset = detailInsert.Offset
		r.insertWidth = scalarWidth(kernel, detailInsert.Type)
	case directInsert != nil:
		r.execKind = temporalExecDirectInsert
		r.insertOffset = directInsert.Offset
		r.insertWidth = scalarWidth(kernel, directInsert.Type)
	case detailBlobBuffer != nil:
		r.execKind = temporalExecDetailBlob
		r.blobBufferOffset = detailBlobBuffer.Offset
		r.blobBufferWidth = scalarWidth(kernel, detailBlobBuffer.Type)
		r.blobSizeOffset = detailBlobSize.Offset
		r.blobSizeWidth = scalarWidth(kernel, detailBlobSize.Type)
	}
	projections["SHIM_CACHE_ENTRY"] = entryProjection
	if r.hasDetail {
		projections["SHIM_CACHE_ENTRY_DETAIL"] = detailProjection
	}

	encoded, err := json.Marshal(map[string]any{
		"metadata":   map[string]string{"format": "6.2.0"},
		"base_types": kernel.Bases,
		"user_types": projections,
		"symbols":    map[string]any{},
		"enums":      map[string]any{},
	})
	if err != nil {
		return nil, err
	}
	table, err := symbols.Parse(encoded)
	if err != nil {
		return nil, err
	}
	r.reader = object.Reader{Layer: layer, Symbols: table}
	for typ, projection := range projections {
		for name := range projection.Fields {
			if _, err := r.reader.Field(typ, name); err != nil {
				return nil, err
			}
		}
	}
	quadField, err := r.reader.Field("_LARGE_INTEGER", "QuadPart")
	if err != nil {
		return nil, err
	}
	scalar, err := r.reader.ScalarType(quadField.Type)
	if err != nil || scalar.Kind != "int" || scalar.Size != 8 || !scalar.Signed || scalar.Endian != "little" {
		return nil, fmt.Errorf("invalid _LARGE_INTEGER.QuadPart scalar")
	}
	if r.hasDetail {
		if _, err := r.reader.Field("SHIM_CACHE_ENTRY", "ListEntryDetail"); err != nil {
			return nil, err
		}
	}
	r.modifiedOffset, err = memory.Add(r.modifiedOffset, quadField.Offset)
	if err != nil {
		return nil, err
	}
	if r.hasUpdate {
		r.updateOffset, err = memory.Add(r.updateOffset, quadField.Offset)
		if err != nil {
			return nil, err
		}
	}
	digest := sha256.Sum256(raw)
	r.LayoutSHA256 = hex.EncodeToString(digest[:])
	return r, nil
}

func normalizedTypeName(name string) string {
	if i := len("nt_symbols!"); len(name) >= i && name[:i] == "nt_symbols!" {
		return name[i:]
	}
	return name
}

func normalizeLargeIntegerField(field symbols.Field) (symbols.Field, error) {
	if field.Type.Kind != "struct" && field.Type.Kind != "union" {
		return field, fmt.Errorf("field is not an embedded _LARGE_INTEGER")
	}
	if normalizedTypeName(field.Type.Name) != "_LARGE_INTEGER" {
		return field, fmt.Errorf("field target is %s", field.Type.Name)
	}
	field.Type.Name = "_LARGE_INTEGER"
	return field, nil
}

func validateTemporalScalar(kernel *symbols.ISF, ref symbols.TypeRef) error {
	if ref.Kind != "base" && ref.Kind != "enum" && ref.Kind != "bitfield" {
		return fmt.Errorf("field is not a scalar")
	}
	base, ok := kernel.Bases[ref.Name]
	if ref.Kind == "bitfield" && ref.Underlying() != nil {
		base, ok = kernel.Bases[ref.Underlying().Name]
	}
	if !ok || base.Kind != "int" && base.Kind != "char" || base.Endian != "little" || base.Size < 1 || base.Size > 8 {
		return fmt.Errorf("invalid scalar definition")
	}
	return nil
}

func scalarWidth(kernel *symbols.ISF, ref symbols.TypeRef) int {
	if ref.Kind == "bitfield" && ref.Underlying() != nil {
		ref = *ref.Underlying()
	}
	return int(kernel.Bases[ref.Name].Size)
}

// LastModified follows the original detail-first property. A present detail
// field is dereferenced before deciding whether its nested field exists.
func (r *TemporalReader) LastModified(ctx context.Context, at uint64) (result TemporalField, err error) {
	defer temporalFailure(&result, &err)
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if r == nil || r.layer == nil {
		return result, fmt.Errorf("missing Shimcache temporal reader")
	}
	base := at
	if r.hasDetail {
		base, result, err = r.detail(ctx, at)
		if err != nil {
			return result, err
		}
	}
	return r.readTime(ctx, base, r.modifiedOffset)
}

// LastUpdate reads only the direct LastUpdate field. It is absent on layouts
// that do not declare it and unreadable, rather than absent, when a read fails.
func (r *TemporalReader) LastUpdate(ctx context.Context, at uint64) (result TemporalField, err error) {
	defer temporalFailure(&result, &err)
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if r == nil || r.layer == nil {
		return result, fmt.Errorf("missing Shimcache temporal reader")
	}
	if !r.hasUpdate {
		result.Value = evidence.Missing("not_applicable", nil)
		result.Complete = true
		return result, nil
	}
	return r.readTime(ctx, at, r.updateOffset)
}

// ExecFlag preserves the pinned original's control flow, including its
// successful-read else branch that always replaces a bool with NotApplicable.
// Consequently only read failures and an empty blob produce persistent absence.
func (r *TemporalReader) ExecFlag(ctx context.Context, at uint64) (result TemporalField, err error) {
	defer temporalFailure(&result, &err)
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if r == nil || r.layer == nil {
		return result, fmt.Errorf("missing Shimcache temporal reader")
	}
	detail := uint64(0)
	if r.hasDetail {
		detail, result, err = r.detail(ctx, at)
		if err != nil {
			return result, err
		}
	}
	switch r.execKind {
	case temporalExecDetailInsert:
		return r.readSuccessfulFlag(ctx, detail, r.insertOffset, r.insertWidth)
	case temporalExecDirectInsert:
		return r.readSuccessfulFlag(ctx, at, r.insertOffset, r.insertWidth)
	case temporalExecDetailBlob:
		if detail == 0 {
			// The original's native layer rejects a zero address even for a
			// zero-length span, before the empty-blob branch can run.
			return result, &memory.ReadError{Address: 0, Length: 0, Layer: r.layer.Name(), Cause: memory.ErrUnmapped}
		}
		storage, err := memory.Add(detail, r.blobBufferOffset)
		if err != nil {
			return result, err
		}
		rawBuffer, err := r.read(ctx, storage, r.blobBufferWidth)
		result.Address, result.Requested, result.Raw = storage, uint64(r.blobBufferWidth), rawBuffer
		if err != nil {
			return result, err
		}
		// BlobBuffer is a scalar, not a pointer template, so the original does
		// not apply the native layer's address mask to it.
		blobAddress := readUnsigned(rawBuffer)
		storage, err = memory.Add(detail, r.blobSizeOffset)
		if err != nil {
			return result, err
		}
		rawSize, err := r.read(ctx, storage, r.blobSizeWidth)
		result.Address, result.Requested, result.Raw = storage, uint64(r.blobSizeWidth), rawSize
		if err != nil {
			return result, err
		}
		blobSize := readUnsigned(rawSize)
		if blobSize == 0 {
			result.Value = evidence.Missing("unparsable", nil)
			result.Address, result.Requested, result.Raw = blobAddress, 0, nil
			result.Complete = true
			return result, nil
		}
		if blobSize > memory.MaxRead || blobSize > math.MaxInt {
			return result, fmt.Errorf("Shimcache exec blob length %d exceeds native bound", blobSize)
		}
		raw, err := r.read(ctx, blobAddress, int(blobSize))
		result.Address, result.Requested, result.Raw = blobAddress, blobSize, raw
		if err != nil {
			return result, err
		}
		if len(raw) == 0 {
			result.Value = evidence.Missing("unparsable", nil)
		} else {
			result.Value = evidence.Missing("not_applicable", nil)
		}
		result.Complete = true
		return result, nil
	default:
		result.Value = evidence.Missing("not_applicable", nil)
		result.Complete = true
		return result, nil
	}
}

func (r *TemporalReader) readSuccessfulFlag(ctx context.Context, base, offset uint64, width int) (result TemporalField, err error) {
	address, err := memory.Add(base, offset)
	if err != nil {
		return result, err
	}
	raw, err := r.read(ctx, address, width)
	result.Address, result.Requested, result.Raw = address, uint64(width), raw
	if err != nil {
		return result, err
	}
	// The pinned property overwrites every successful branch with this value.
	result.Value = evidence.Missing("not_applicable", nil)
	result.Complete = true
	return result, nil
}

func (r *TemporalReader) detail(ctx context.Context, at uint64) (uint64, TemporalField, error) {
	storage, err := memory.Add(at, r.detailOffset)
	if err != nil {
		return 0, TemporalField{}, err
	}
	raw, err := r.read(ctx, storage, r.width)
	result := TemporalField{Address: storage, Requested: uint64(r.width), Raw: raw}
	if err != nil {
		return 0, result, err
	}
	value := readUnsigned(raw) & r.mask
	if r.mask == 0x0000ffffffffffff {
		value = canonicalizePointer(value, r.width)
	}
	return value, TemporalField{}, nil
}

func (r *TemporalReader) readTime(ctx context.Context, base, offset uint64) (result TemporalField, err error) {
	address, err := memory.Add(base, offset)
	if err != nil {
		return result, err
	}
	raw, err := r.read(ctx, address, 8)
	result.Address, result.Requested, result.Raw = address, 8, raw
	if err != nil {
		return result, err
	}
	result.Value = shimcacheFiletime(int64(binary.LittleEndian.Uint64(raw)))
	result.Complete = true
	return result, nil
}

func (r *TemporalReader) read(ctx context.Context, address uint64, length int) ([]byte, error) {
	if length < 0 || length > memory.MaxRead {
		return nil, fmt.Errorf("invalid Shimcache temporal read length %d", length)
	}
	raw := make([]byte, length)
	n, err := r.layer.ReadAt(ctx, raw, address)
	if n < 0 || n > length {
		return nil, fmt.Errorf("invalid Shimcache temporal read count %d", n)
	}
	raw = append([]byte(nil), raw[:n]...)
	if err == nil && n != length {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return raw, &memory.ReadError{Address: address, Length: length, Layer: r.layer.Name(), Cause: err}
	}
	return raw, nil
}

func temporalFailure(result *TemporalField, err *error) {
	if *err != nil && result.Value.Kind == "" {
		result.Value = evidence.Missing("unreadable", *err)
	}
}

func readUnsigned(raw []byte) uint64 {
	var value uint64
	for i := len(raw) - 1; i >= 0; i-- {
		value = value<<8 | uint64(raw[i])
	}
	return value
}

// shimcacheFiletime reproduces conversion.wintime_to_datetime, including
// Python floor division for signed negative values and second precision.
func shimcacheFiletime(ticks int64) evidence.Value {
	seconds := floorDivInt64Temporal(ticks, 10000000)
	if seconds == 0 {
		return evidence.Missing("not_applicable", nil)
	}
	unix := seconds - 11644473600
	if unix < -62135596800 || unix > 253402300799 {
		return evidence.Missing("unparsable", nil)
	}
	return evidence.Text(time.Unix(unix, 0).UTC().Format("2006-01-02T15:04:05-07:00"))
}

func floorDivInt64Temporal(n, d int64) int64 {
	q := n / d
	if n%d != 0 && (n < 0) != (d < 0) {
		q--
	}
	return q
}
