package winconsole

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// ConsoleField uses signed offsets because the pinned console objects include
// fields before their nominal base and beyond their declared struct size.
type ConsoleField struct {
	Offset int64
	Type   symbols.TypeRef
	Size   uint64
	Signed bool
}
type ConsoleLayout struct {
	SHA256  string
	fields  map[string]ConsoleField
	History *symbols.ISF
}

func ParseConsoleLayout(raw []byte) (*ConsoleLayout, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fmt.Errorf("invalid console object layout size")
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
	if p := doc.Bases["pointer"]; p.Kind != "int" || p.Size != 8 || p.Endian != "little" || p.Signed {
		return nil, fmt.Errorf("console objects require unsigned little-endian x64 pointers")
	}
	history, err := ParseHistoryLayout(raw)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	l := &ConsoleLayout{SHA256: hex.EncodeToString(digest[:]), fields: map[string]ConsoleField{}, History: history}
	for _, name := range []string{"_CONSOLE_INFORMATION", "_CONSOLE_PROCESS_LIST", "_CONSOLE_PROCESS", "_EXE_ALIAS_LIST", "_ALIAS", "_COMMAND_HISTORY"} {
		typ, ok := doc.Types[name]
		if !ok || typ.Kind != "struct" || typ.Size == 0 || typ.Size > memory.MaxRead {
			return nil, fmt.Errorf("invalid console type %s", name)
		}
		for member, f := range typ.Fields {
			if f.Offset < -(1<<20) || f.Offset > 1<<20 {
				return nil, fmt.Errorf("invalid console offset %s.%s", name, member)
			}
			entry := ConsoleField{Offset: f.Offset, Type: f.Type}
			switch f.Type.Kind {
			case "pointer":
				if f.Type.Subtype == nil {
					return nil, fmt.Errorf("missing console pointer target")
				}
				entry.Size = 8
			case "base":
				base, ok := doc.Bases[f.Type.Name]
				if !ok || base.Kind != "int" || base.Endian != "little" || (base.Size != 1 && base.Size != 2 && base.Size != 4 && base.Size != 8) {
					return nil, fmt.Errorf("invalid console scalar %s.%s", name, member)
				}
				entry.Size, entry.Signed = base.Size, base.Signed
			case "struct":
				if f.Type.Name == "" {
					return nil, fmt.Errorf("missing console embedded type")
				}
			default:
				return nil, fmt.Errorf("unsupported console field %s.%s", name, member)
			}
			l.fields[name+"."+member] = entry
		}
	}
	for _, name := range []string{"ScreenX", "ScreenY", "CommandHistorySize", "HistoryBufferCount", "HistoryBufferMax", "ProcessCount", "Title", "OriginalTitle", "HistoryList", "ConsoleProcessList", "ExeAliasList", "CurrentScreenBuffer", "GetScreenBuffer"} {
		if _, ok := l.fields["_CONSOLE_INFORMATION."+name]; !ok {
			return nil, fmt.Errorf("missing console member %s", name)
		}
	}
	for _, name := range []string{"Title", "OriginalTitle"} {
		if l.fields["_CONSOLE_INFORMATION."+name].Type.Kind != "pointer" {
			return nil, fmt.Errorf("invalid console title pointer")
		}
	}
	for _, name := range []string{"ScreenX", "ScreenY", "CommandHistorySize", "HistoryBufferCount", "HistoryBufferMax", "ProcessCount"} {
		f := l.fields["_CONSOLE_INFORMATION."+name]
		if f.Type.Kind != "base" || f.Size != 2 {
			return nil, fmt.Errorf("invalid console count or dimension %s", name)
		}
	}
	return l, nil
}
func (l *ConsoleLayout) Field(name string) (ConsoleField, error) {
	if l == nil {
		return ConsoleField{}, fmt.Errorf("missing console layout")
	}
	f, ok := l.fields[name]
	if !ok {
		return f, fmt.Errorf("missing console field %s", name)
	}
	return f, nil
}
func (l *ConsoleLayout) Address(at uint64, name string) (uint64, error) {
	f, err := l.Field(name)
	if err != nil {
		return 0, err
	}
	address, err := screenOffset(at, f.Offset)
	if err != nil {
		return 0, fmt.Errorf("%s at 0x%x: %w", name, at, err)
	}
	return address, nil
}

type ConsoleReader struct {
	Layer         memory.MemoryLayer
	Layout        *ConsoleLayout
	KernelSymbols *symbols.ISF // Resolves the external nt_symbols!_LIST_ENTRY type.
}

// ConsoleScalar retains the source bytes. Signed values are sign-extended into
// Value; callers can convert to int64 when Signed is true.
type ConsoleScalar struct {
	Address, Value uint64
	Signed         bool
	Raw            []byte
}

func consoleRead(ctx context.Context, layer memory.MemoryLayer, at uint64, n int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if layer == nil || n < 0 || n > memory.MaxRead {
		return nil, fmt.Errorf("invalid console read")
	}
	raw := make([]byte, n)
	count, err := layer.ReadAt(ctx, raw, at)
	if count < 0 || count > len(raw) {
		return nil, fmt.Errorf("invalid console capture count %d", count)
	}
	raw = raw[:count]
	if err == nil && count != n {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return raw, &memory.ReadError{Address: at, Length: n, Layer: layer.Name(), Cause: err}
	}
	return raw, ctx.Err()
}
func (r ConsoleReader) Scalar(ctx context.Context, at uint64, name string) (ConsoleScalar, error) {
	value := ConsoleScalar{}
	f, err := r.Layout.Field(name)
	if err != nil {
		return value, err
	}
	if f.Size != 1 && f.Size != 2 && f.Size != 4 && f.Size != 8 {
		return value, fmt.Errorf("%s is not a console scalar", name)
	}
	value.Address, err = r.Layout.Address(at, name)
	if err != nil {
		return value, err
	}
	value.Signed = f.Signed
	value.Raw, err = consoleRead(ctx, r.Layer, value.Address, int(f.Size))
	if err != nil {
		return value, err
	}
	switch f.Size {
	case 1:
		value.Value = uint64(value.Raw[0])
	case 2:
		value.Value = uint64(binary.LittleEndian.Uint16(value.Raw))
	case 4:
		value.Value = uint64(binary.LittleEndian.Uint32(value.Raw))
	case 8:
		value.Value = binary.LittleEndian.Uint64(value.Raw)
	}
	if value.Signed && f.Size < 8 {
		shift := uint(64 - f.Size*8)
		value.Value = uint64(int64(value.Value<<shift) >> shift)
	}
	return value, nil
}

type ConsoleText struct {
	Pointer ConsoleScalar
	Text    string
	Raw     []byte
}

func decodeConsoleText(raw []byte) string {
	order := binary.ByteOrder(binary.LittleEndian)
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			raw = raw[2:]
		} else if raw[0] == 0xfe && raw[1] == 0xff {
			order = binary.BigEndian
			raw = raw[2:]
		}
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = order.Uint16(raw[i*2:])
	}
	text := string(utf16.Decode(units))
	if len(raw)%2 != 0 {
		text += "\ufffd"
	}
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	return text
}
func (r ConsoleReader) Title(ctx context.Context, at uint64, original bool) (ConsoleText, error) {
	result := ConsoleText{}
	name := "_CONSOLE_INFORMATION.Title"
	if original {
		name = "_CONSOLE_INFORMATION.OriginalTitle"
	}
	var err error
	result.Pointer, err = r.Scalar(ctx, at, name)
	if err != nil {
		return result, err
	}
	// The original string cast requests all 512 bytes, including bytes after NUL.
	result.Raw, err = consoleRead(ctx, r.Layer, result.Pointer.Value, 512)
	if err != nil {
		return result, err
	}
	result.Text = decodeConsoleText(result.Raw)
	return result, nil
}

// Valid retains the original count/title short circuit. Title read errors stay
// visible even if the original-title fallback establishes a valid candidate.
func (r ConsoleReader) Valid(ctx context.Context, at, maxBuffers uint64) (bool, error) {
	count, err := r.Scalar(ctx, at, "_CONSOLE_INFORMATION.HistoryBufferCount")
	if err != nil {
		return false, err
	}
	if count.Value < 1 || count.Value > maxBuffers {
		return false, nil
	}
	title, titleErr := r.Title(ctx, at, false)
	if title.Text != "" {
		return true, titleErr
	}
	old, oldErr := r.Title(ctx, at, true)
	return old.Text != "", errors.Join(titleErr, oldErr)
}

// WalkList follows a declared embedded or pointer list head with the kernel's
// actual LIST_ENTRY layout. It preserves the recovered prefix and returns an
// error for unreadable links, null links and non-sentinel cycles; upstream may
// silently stop in those cases. Backlinks are captured but not used to filter.
func (r ConsoleReader) WalkList(ctx context.Context, at uint64, field, node string, maxNodes uint64, emit func(uint64) error) error {
	if maxNodes == 0 || maxNodes > 1000000 || emit == nil {
		return fmt.Errorf("console list requires emitter and node limit 1..1000000")
	}
	if r.Layer == nil || r.Layout == nil {
		return fmt.Errorf("console list requires memory and layout")
	}
	if r.KernelSymbols == nil || r.KernelSymbols.PointerSize() != 8 {
		return fmt.Errorf("console lists require x64 kernel list symbols")
	}
	f, err := r.Layout.Field(field)
	if err != nil {
		return err
	}
	head, err := r.Layout.Address(at, field)
	if err != nil {
		return err
	}
	ref := f.Type
	if ref.Kind == "pointer" {
		value, err := r.Scalar(ctx, at, field)
		if err != nil {
			return err
		}
		head = value.Value
		if ref.Subtype == nil {
			return fmt.Errorf("missing console list target")
		}
		ref = *ref.Subtype
	}
	if ref.Kind != "struct" || ref.Name != "nt_symbols!_LIST_ENTRY" {
		return fmt.Errorf("%s is not a kernel list head", field)
	}
	member, err := r.Layout.Field(node + ".ListEntry")
	if err != nil {
		return err
	}
	if member.Type.Kind != "struct" || member.Type.Name != "nt_symbols!_LIST_ENTRY" || member.Offset < 0 {
		return fmt.Errorf("invalid console node link")
	}
	reader := &object.Reader{Layer: r.Layer, Symbols: r.KernelSymbols}
	size, err := reader.Size(symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"})
	if err != nil || size == 0 || size > memory.MaxRead {
		return fmt.Errorf("invalid kernel list size %d: %v", size, err)
	}
	seen := map[uint64]bool{}
	var failures []error
	fail := func(err error) error { return errors.Join(append(failures, err)...) }
	current := head
	for count := uint64(0); ; {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		next, err := reader.Uint(ctx, current, "_LIST_ENTRY", "Flink")
		if err != nil {
			return fail(err)
		}
		if next == 0 {
			return fail(fmt.Errorf("null console list link at 0x%x", current))
		}
		if _, err := consoleRead(ctx, r.Layer, next, int(size)); err != nil {
			// A failed optional backlink read must not discard a node whose
			// container and forward link remain readable. Keep the failure.
			failures = append(failures, err)
		}
		if next == head {
			return fail(ctx.Err())
		}
		if seen[next] {
			return fail(fmt.Errorf("console list cycle at 0x%x", next))
		}
		if count >= maxNodes {
			return fail(fmt.Errorf("console list node bound exhausted"))
		}
		if next < uint64(member.Offset) {
			return fail(fmt.Errorf("console list container underflow"))
		}
		owner := next - uint64(member.Offset)
		if _, err := consoleRead(ctx, r.Layer, owner, 1); err != nil {
			return fail(err)
		}
		seen[next] = true
		count++
		if err := emit(owner); err != nil {
			return fail(err)
		}
		current = next
	}
}
