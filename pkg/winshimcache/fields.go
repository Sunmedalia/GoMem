package winshimcache

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// EntryFieldsReader projects only Path and optional FileSize. Time and execution
// fields require further readers; a successfully decoded path is not validation
// of the entry, its list membership, or the selected kernel/layout pair.
type EntryFieldsReader struct {
	reader       object.Reader
	mask         uint64
	inline       bool
	pathBytes    uint64
	sizeSigned   bool
	hasSize      bool
	LayoutSHA256 string
	KernelSHA256 string
}

type PathField struct {
	Value     evidence.Value
	Address   uint64
	Requested uint64
	Raw       []byte
	Complete  bool
}

func NewEntryFieldsReader(layer memory.MemoryLayer, raw []byte, kernel *symbols.ISF, mask uint64) (*EntryFieldsReader, error) {
	if layer == nil || kernel == nil || len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fmt.Errorf("entry fields require bounded layout, layer and kernel")
	}
	width := kernel.PointerSize()
	if width != 4 && width != 8 || mask == 0 || mask&(mask+1) != 0 || width == 4 && mask > 0xffffffff {
		return nil, fmt.Errorf("invalid entry fields pointer width/mask")
	}
	var doc struct {
		Bases map[string]symbols.Type `json:"base_types"`
		Types map[string]symbols.Type `json:"user_types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	for _, p := range []symbols.Type{doc.Bases["pointer"], kernel.Bases["pointer"]} {
		if p.Size != uint64(width) || p.Endian != "little" || p.Signed {
			return nil, fmt.Errorf("invalid entry fields pointer representation")
		}
	}
	src, ok := doc.Types["SHIM_CACHE_ENTRY"]
	if !ok || src.Kind != "struct" || src.Size == 0 || src.Size > 1<<20 {
		return nil, fmt.Errorf("invalid entry field type")
	}
	path, ok := src.Fields["Path"]
	if !ok {
		return nil, fmt.Errorf("missing Shimcache entry Path")
	}
	entry := symbols.Type{Kind: "struct", Size: src.Size, Fields: map[string]symbols.Field{"Path": path}}
	projected := map[string]symbols.Type{"SHIM_CACHE_ENTRY": entry}
	r := &EntryFieldsReader{mask: mask, KernelSHA256: kernel.Digest()}
	switch path.Type.Kind {
	case "array":
		if path.Type.Subtype == nil || path.Type.Subtype.Kind != "base" || path.Type.Count == 0 || path.Type.Count > 65535 {
			return nil, fmt.Errorf("invalid inline Shimcache path")
		}
		base, ok := kernel.Bases[path.Type.Subtype.Name]
		if !ok || base.Size != 1 || base.Kind != "int" && base.Kind != "char" {
			return nil, fmt.Errorf("invalid inline Shimcache path byte")
		}
		r.inline = true
		r.pathBytes = path.Type.Count
	case "struct":
		if path.Type.Name != "nt_symbols!_UNICODE_STRING" {
			return nil, fmt.Errorf("invalid Shimcache path descriptor target")
		}
		unicodeType, err := kernel.Type("_UNICODE_STRING")
		if err != nil || unicodeType.Kind != "struct" || unicodeType.Size == 0 || unicodeType.Size > 1<<20 {
			return nil, fmt.Errorf("invalid kernel Unicode descriptor")
		}
		fields := map[string]symbols.Field{}
		for _, name := range []string{"Length", "Buffer"} {
			field, ok := unicodeType.Fields[name]
			if !ok {
				return nil, fmt.Errorf("missing Unicode descriptor %s", name)
			}
			if name == "Length" {
				base := kernel.Bases[field.Type.Name]
				if field.Type.Kind != "base" || base.Kind != "int" || base.Size != 2 || base.Signed || base.Endian != "little" {
					return nil, fmt.Errorf("invalid Unicode length")
				}
			} else if field.Type.Kind != "pointer" || field.Type.Subtype == nil || field.Type.Base != "" && field.Type.Base != "pointer" {
				return nil, fmt.Errorf("invalid Unicode buffer pointer")
			}
			fields[name] = field
		}
		projected["_UNICODE_STRING"] = symbols.Type{Kind: "struct", Size: unicodeType.Size, Fields: fields}
		path.Type.Name = "_UNICODE_STRING"
		entry.Fields["Path"] = path
	default:
		return nil, fmt.Errorf("invalid Shimcache path representation")
	}
	if size, ok := src.Fields["FileSize"]; ok {
		base, ok := kernel.Bases[size.Type.Name]
		if !ok || size.Type.Kind != "base" || base.Kind != "int" || base.Endian != "little" || base.Size < 1 || base.Size > 8 {
			return nil, fmt.Errorf("invalid Shimcache FileSize")
		}
		entry.Fields["FileSize"] = size
		r.hasSize = true
		r.sizeSigned = base.Signed
	}
	encoded, err := json.Marshal(map[string]any{"metadata": map[string]string{"format": "6.2.0"}, "base_types": kernel.Bases, "user_types": projected, "symbols": map[string]any{}, "enums": map[string]any{}})
	if err != nil {
		return nil, err
	}
	table, err := symbols.Parse(encoded)
	if err != nil {
		return nil, err
	}
	r.reader = object.Reader{Layer: layer, Symbols: table}
	for typ, t := range projected {
		for name := range t.Fields {
			if _, err := r.reader.Field(typ, name); err != nil {
				return nil, err
			}
		}
	}
	digest := sha256.Sum256(raw)
	r.LayoutSHA256 = hex.EncodeToString(digest[:])
	return r, nil
}

func (r *EntryFieldsReader) FileSize(ctx context.Context, at uint64) (evidence.Value, error) {
	if err := ctx.Err(); err != nil {
		return evidence.Missing("unreadable", err), err
	}
	if r == nil || r.reader.Layer == nil {
		err := fmt.Errorf("missing Shimcache entry field reader")
		return evidence.Missing("unreadable", err), err
	}
	if !r.hasSize {
		return evidence.Missing("not_applicable", nil), nil
	}
	if r.sizeSigned {
		value, err := r.reader.Int(ctx, at, "SHIM_CACHE_ENTRY", "FileSize")
		if err != nil {
			return evidence.Missing("unreadable", err), err
		}
		if value < 0 {
			value = 0
		}
		return evidence.Number(uint64(value)), nil
	}
	value, err := r.reader.Uint(ctx, at, "SHIM_CACHE_ENTRY", "FileSize")
	if err != nil {
		return evidence.Missing("unreadable", err), err
	}
	return evidence.Number(value), nil
}

func (r *EntryFieldsReader) FilePath(ctx context.Context, at uint64) (result PathField, err error) {
	defer func() {
		if err != nil && result.Value.Kind == "" {
			result.Value = evidence.Missing("unreadable", err)
		}
	}()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if r == nil || r.reader.Layer == nil {
		return result, fmt.Errorf("missing Shimcache entry field reader")
	}
	if r.inline {
		field, e := r.reader.Field("SHIM_CACHE_ENTRY", "Path")
		if e != nil {
			return result, e
		}
		result.Address, err = memory.Add(at, field.Offset)
		result.Requested = r.pathBytes
	} else {
		// Preserve the original order: pointer first, Length second. MaximumLength
		// does not constrain the original read and is deliberately not consulted.
		result.Address, err = r.reader.Uint(ctx, at, "SHIM_CACHE_ENTRY", "Path.Buffer")
		result.Address &= r.mask
		if r.mask == 0x0000ffffffffffff {
			result.Address = canonicalizePointer(result.Address, r.reader.Symbols.PointerSize())
		}
		if err != nil {
			return result, err
		}
		result.Requested, err = r.reader.Uint(ctx, at, "SHIM_CACHE_ENTRY", "Path.Length")
	}
	if err != nil {
		return result, err
	}
	if _, err = memory.Add(result.Address, result.Requested); err != nil {
		return result, err
	}
	raw := make([]byte, int(result.Requested))
	n, readErr := r.reader.Layer.ReadAt(ctx, raw, result.Address)
	if n < 0 || n > len(raw) {
		return result, fmt.Errorf("invalid path read count %d", n)
	}
	result.Raw = append([]byte(nil), raw[:n]...)
	if readErr == nil && n != len(raw) {
		readErr = io.ErrUnexpectedEOF
	}
	result.Complete = readErr == nil
	if readErr != nil {
		err = &memory.ReadError{Address: result.Address, Length: len(raw), Layer: r.reader.Layer.Name(), Cause: readErr}
		// XP's translated address_to_string can recover a readable prefix. Keep
		// that text and its raw bytes, but still expose the incomplete native read.
		if r.inline && n > 0 {
			result.Value = evidence.Text(decodeShimPath(result.Raw, false, true))
		}
		return result, err
	}
	result.Value = evidence.Text(decodeShimPath(result.Raw, !r.inline, r.inline))
	return result, nil
}

// Match Python's replacement codec, including a high surrogate followed by one
// odd tail byte (a single replacement). Descriptor UTF-16 detects/strips a BOM;
// XP's explicit UTF-16LE keeps the BOM and truncates NUL/replacement characters.
func decodeShimPath(raw []byte, bom, truncate bool) string {
	var order binary.ByteOrder = binary.LittleEndian
	if bom && len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			raw = raw[2:]
		} else if raw[0] == 0xfe && raw[1] == 0xff {
			raw = raw[2:]
			order = binary.BigEndian
		}
	}
	result := []rune{}
	for i := 0; i < len(raw); {
		if i+1 >= len(raw) {
			result = append(result, utf8.RuneError)
			break
		}
		unit := order.Uint16(raw[i:])
		i += 2
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+1 >= len(raw) {
				result = append(result, utf8.RuneError)
				break
			}
			next := order.Uint16(raw[i:])
			if next >= 0xdc00 && next <= 0xdfff {
				result = append(result, utf16.DecodeRune(rune(unit), rune(next)))
				i += 2
			} else {
				result = append(result, utf8.RuneError)
			}
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			result = append(result, utf8.RuneError)
		} else {
			result = append(result, rune(unit))
		}
	}
	text := string(result)
	if truncate {
		if end := strings.IndexAny(text, "\x00\ufffd"); end >= 0 {
			text = text[:end]
		}
	}
	return text
}
