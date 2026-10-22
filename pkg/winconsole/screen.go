package winconsole

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// ScreenLayout retains the original layout digest. Its signed field offsets
// are local to the console adapter: recent upstream _ROW definitions deliberately
// address metadata before the nominal object. General ISF parsing stays strict.
type ScreenLayout struct {
	SHA256   string
	fields   map[string]int64
	rowSize  uint64
	indirect bool
}

func ParseScreenLayout(raw []byte) (*ScreenLayout, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fmt.Errorf("invalid console screen layout size")
	}
	var doc struct {
		Bases map[string]symbols.Type `json:"base_types"`
		Types map[string]struct {
			Kind   string
			Size   uint64
			Fields map[string]struct {
				Offset int64
				Type   symbols.TypeRef
			}
		} `json:"user_types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if b := doc.Bases["pointer"]; b.Kind != "int" || b.Size != 8 || b.Endian != "little" || b.Signed {
		return nil, fmt.Errorf("screen layout requires unsigned little-endian x64 pointers")
	}
	if t := doc.Types["_CHAR_ROW_CELL"]; t.Kind != "struct" || t.Size != 3 {
		return nil, fmt.Errorf("screen layout requires three-byte character cells")
	}
	hash := sha256.Sum256(raw)
	l := &ScreenLayout{SHA256: hex.EncodeToString(hash[:]), fields: map[string]int64{}}
	for _, required := range []struct{ typ, field, kind, target string }{
		{"_SCREEN_INFORMATION", "TextBufferInfo", "pointer", "_TEXT_BUFFER_INFO"},
		{"_TEXT_BUFFER_INFO", "BufferRows", "pointer", "_ROWS_ARRAY"},
		{"_TEXT_BUFFER_INFO", "BufferCapacity", "short", ""},
		{"_TEXT_BUFFER_INFO", "BufferStart", "short", ""},
		{"_ROW", "CharRow", "pointer", "_CHAR_ROW_CELL_ARRAY"},
		{"_ROW", "RowLength", "short", ""},
		{"_ROW", "RowLength2", "short", ""},
		{"_CHAR_ROW_CELL_ARRAY", "Chars", "array", "_CHAR_ROW_CELL"},
	} {
		t, ok := doc.Types[required.typ]
		f, found := t.Fields[required.field]
		if !ok || !found || t.Kind != "struct" || t.Size == 0 || t.Size > memory.MaxRead || f.Offset < -(1<<20) || f.Offset > 1<<20 {
			return nil, fmt.Errorf("invalid screen field %s.%s", required.typ, required.field)
		}
		valid := f.Type.Kind == required.kind && f.Type.Subtype != nil && f.Type.Subtype.Kind == "struct" && f.Type.Subtype.Name == required.target
		if required.kind == "short" {
			b, ok := doc.Bases[f.Type.Name]
			valid = f.Type.Kind == "base" && ok && b.Kind == "int" && b.Size == 2 && b.Signed && b.Endian == "little"
		}
		if !valid {
			return nil, fmt.Errorf("invalid screen field type %s.%s", required.typ, required.field)
		}
		l.fields[required.typ+"."+required.field] = f.Offset
	}
	rows, ok := doc.Types["_ROWS_ARRAY"]
	f, found := rows.Fields["Rows"]
	if !ok || !found || rows.Kind != "struct" || f.Offset < 0 || f.Offset > 1<<20 || f.Type.Kind != "array" || f.Type.Subtype == nil || f.Type.Subtype.Kind != "struct" {
		return nil, fmt.Errorf("invalid screen row array")
	}
	l.fields["_ROWS_ARRAY.Rows"] = f.Offset
	switch f.Type.Subtype.Name {
	case "_ROW":
		l.rowSize = doc.Types["_ROW"].Size
	case "_ROW_POINTER":
		p := doc.Types["_ROW_POINTER"]
		field, ok := p.Fields["Row"]
		if !ok || p.Kind != "struct" || field.Offset < 0 || field.Offset > 1<<20 || field.Type.Kind != "pointer" || field.Type.Subtype == nil || field.Type.Subtype.Kind != "struct" || field.Type.Subtype.Name != "_ROW" {
			return nil, fmt.Errorf("invalid screen row pointer")
		}
		l.indirect, l.rowSize = true, p.Size
		l.fields["_ROW_POINTER.Row"] = field.Offset
	default:
		return nil, fmt.Errorf("unsupported screen row array element")
	}
	if l.rowSize == 0 || l.rowSize > memory.MaxRead {
		return nil, fmt.Errorf("invalid screen row stride")
	}
	return l, nil
}

type ScreenReader struct {
	Layer  memory.MemoryLayer
	Layout *ScreenLayout
}

// ScreenRow keeps the unfiltered three-byte cells even when the baseline
// rejects their DBCS attributes or nonzero character high bytes.
type ScreenRow struct {
	Address, CellsAddress uint64
	Length                int64
	Text                  string
	Raw                   []byte
}

func screenOffset(at uint64, offset int64) (uint64, error) {
	if offset < 0 {
		// Avoid negating MinInt64, including for malformed programmatic callers.
		n := uint64(-(offset + 1)) + 1
		if n > at {
			return 0, fmt.Errorf("screen field address underflow")
		}
		return at - n, nil
	}
	return memory.Add(at, uint64(offset))
}

func (r ScreenReader) field(ctx context.Context, at uint64, name string, short bool) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r.Layer == nil || r.Layout == nil {
		return 0, fmt.Errorf("screen reader requires memory and layout")
	}
	offset, ok := r.Layout.fields[name]
	if !ok {
		return 0, fmt.Errorf("missing screen field %s", name)
	}
	address, err := screenOffset(at, offset)
	if err != nil {
		return 0, fmt.Errorf("%s at 0x%x: %w", name, at, err)
	}
	n := 8
	if short {
		n = 2
	}
	raw, err := memory.Read(ctx, r.Layer, address, n)
	if err != nil {
		return 0, fmt.Errorf("%s at 0x%x: %w", name, address, err)
	}
	if short {
		return uint64(int64(int16(binary.LittleEndian.Uint16(raw)))), nil
	}
	return binary.LittleEndian.Uint64(raw), nil
}

func screenTrim(s string) string {
	// The accepted cells have high byte zero. Python's str.rstrip includes
	// U+001C..U+001F, which Go's unicode.IsSpace does not include.
	return strings.TrimRightFunc(s, func(c rune) bool { return c >= 9 && c <= 13 || c >= 0x1c && c <= 0x20 || c == 0x85 || c == 0xa0 })
}

func screenDBCS(attr byte) bool {
	switch attr {
	case 0, 1, 2, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0xa8, 0xb8, 0xc0, 0xc8, 0x98, 0xd8, 0xe0, 0xe8, 0xf8, 0xf0, 0xa0:
		return true
	}
	return false
}

func (r ScreenReader) Row(ctx context.Context, at, maxCells uint64, truncate bool) (ScreenRow, error) {
	row := ScreenRow{Address: at}
	if maxCells == 0 || maxCells > 32767 {
		return row, fmt.Errorf("screen cell limit must be 1..32767")
	}
	ptr, err := r.field(ctx, at, "_ROW.CharRow", false)
	if err != nil {
		return row, err
	}
	offset := r.Layout.fields["_CHAR_ROW_CELL_ARRAY.Chars"]
	row.CellsAddress, err = screenOffset(ptr, offset)
	if err != nil {
		return row, err
	}
	n, err := r.field(ctx, at, "_ROW.RowLength", true)
	if err != nil {
		return row, err
	}
	row.Length = int64(n)
	if row.Length < 0 || n > maxCells {
		return row, fmt.Errorf("screen row length %d exceeds 0..%d", row.Length, maxCells)
	}
	row.Raw = make([]byte, int(n*3))
	captured, err := r.Layer.ReadAt(ctx, row.Raw, row.CellsAddress)
	if captured < 0 || captured > len(row.Raw) {
		row.Raw = nil
		return row, fmt.Errorf("invalid screen read count %d", captured)
	}
	requested := len(row.Raw)
	row.Raw = row.Raw[:captured]
	if err == nil && captured != requested {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return row, fmt.Errorf("screen cells at 0x%x: %w", row.CellsAddress, err)
	}
	if err := ctx.Err(); err != nil {
		return row, err
	}
	var text strings.Builder
	for i := 0; i < len(row.Raw); i += 3 {
		if row.Raw[i+1] == 0 && screenDBCS(row.Raw[i+2]) {
			text.WriteRune(rune(row.Raw[i]))
		}
	}
	row.Text = text.String()
	if truncate {
		row.Text = screenTrim(row.Text)
	}
	return row, ctx.Err()
}

func (r ScreenReader) rowAddress(ctx context.Context, rows, index uint64) (uint64, error) {
	if index > ^uint64(0)/r.Layout.rowSize {
		return 0, fmt.Errorf("screen row index overflow")
	}
	at, err := memory.Add(rows, index*r.Layout.rowSize)
	if err != nil || !r.Layout.indirect {
		return at, err
	}
	return r.field(ctx, at, "_ROW_POINTER.Row", false)
}

func (r ScreenReader) rowsAddress(ctx context.Context, buffer uint64) (uint64, error) {
	at, err := r.field(ctx, buffer, "_TEXT_BUFFER_INFO.BufferRows", false)
	if err != nil {
		return 0, err
	}
	return screenOffset(at, r.Layout.fields["_ROWS_ARRAY.Rows"])
}

func (r ScreenReader) Dimensions(ctx context.Context, at uint64) (int64, int64, error) {
	buffer, err := r.field(ctx, at, "_SCREEN_INFORMATION.TextBufferInfo", false)
	if err != nil {
		return 0, 0, err
	}
	rows, err := r.rowsAddress(ctx, buffer)
	if err != nil {
		return 0, 0, err
	}
	row, err := r.rowAddress(ctx, rows, 0)
	if err != nil {
		return 0, 0, err
	}
	x, err := r.field(ctx, row, "_ROW.RowLength2", true)
	if err != nil {
		return 0, 0, err
	}
	y, err := r.field(ctx, buffer, "_TEXT_BUFFER_INFO.BufferCapacity", true)
	return int64(x), int64(y), err
}

type ScreenLimits struct{ MaxRows, MaxCells, MaxTextBytes uint64 }
type ScreenBuffer struct {
	Address         uint64
	Capacity, Start int64
	Rows            []ScreenRow
	AcquiredRows    []ScreenRow // Includes trailing rows removed from the display.
	FailedRow       *ScreenRow  // Retains a partial cell capture when a row read fails.
}

// Buffer follows the baseline's circular ordering and optional trailing-row
// trimming. On a failed row it returns the already recovered rows AND the error;
// the baseline silently stops. Raw bytes count against the total text budget.
func (r ScreenReader) Buffer(ctx context.Context, at uint64, limits ScreenLimits, truncateRows, truncateLines bool) (ScreenBuffer, error) {
	result := ScreenBuffer{Address: at, Rows: []ScreenRow{}}
	if limits.MaxRows == 0 || limits.MaxRows > 32767 || limits.MaxCells == 0 || limits.MaxCells > 32767 || limits.MaxTextBytes == 0 || limits.MaxTextBytes > memory.MaxRead {
		return result, fmt.Errorf("screen limits require rows/cells 1..32767 and text bytes 1..%d", memory.MaxRead)
	}
	buffer, err := r.field(ctx, at, "_SCREEN_INFORMATION.TextBufferInfo", false)
	if err != nil {
		return result, err
	}
	n, err := r.field(ctx, buffer, "_TEXT_BUFFER_INFO.BufferCapacity", true)
	if err != nil {
		return result, err
	}
	result.Capacity = int64(n)
	if result.Capacity < 0 || n > limits.MaxRows {
		return result, fmt.Errorf("screen capacity %d exceeds 0..%d", result.Capacity, limits.MaxRows)
	}
	start, err := r.field(ctx, buffer, "_TEXT_BUFFER_INFO.BufferStart", true)
	if err != nil {
		return result, err
	}
	result.Start = int64(start)
	rows, err := r.rowsAddress(ctx, buffer)
	if err != nil {
		return result, err
	}
	var used uint64
	for i := int64(0); i < result.Capacity; i++ {
		if err = ctx.Err(); err != nil {
			break
		}
		index := (result.Start + i) % result.Capacity
		if index < 0 {
			index += result.Capacity
		} // Python's positive modulo.
		var address uint64
		address, err = r.rowAddress(ctx, rows, uint64(index))
		if err != nil {
			break
		}
		var length uint64
		length, err = r.field(ctx, address, "_ROW.RowLength", true)
		if err != nil {
			break
		}
		if int64(length) < 0 || length > limits.MaxCells {
			err = fmt.Errorf("invalid screen row length %d", int64(length))
			break
		}
		if length*3 > limits.MaxTextBytes-used {
			err = fmt.Errorf("screen text byte budget exhausted")
			break
		}
		var row ScreenRow
		row, err = r.Row(ctx, address, limits.MaxCells, truncateLines)
		if err != nil {
			result.FailedRow = &row
			break
		}
		used += uint64(len(row.Raw))
		result.Rows = append(result.Rows, row)
	}
	result.AcquiredRows = result.Rows
	if truncateRows {
		for len(result.Rows) > 0 && screenTrim(result.Rows[len(result.Rows)-1].Text) == "" {
			result.Rows = result.Rows[:len(result.Rows)-1]
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	return result, err
}
