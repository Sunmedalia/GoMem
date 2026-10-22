package wingui

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

// Name preserves the original acquisition separately from its display string.
// Text nil is the original None result, while a non-nil empty text is distinct.
type Name struct {
	Text                 *string
	Raw                  []byte
	Header, Info, Buffer uint64
}
type nameSchemaError struct{ error }

func (e nameSchemaError) Unwrap() error { return e.error }

// ObjectName resolves the executive header using kernel types in this exact
// session layer. Both the info-mask table and the final string are read here,
// rather than switching to the primary kernel address space.
func (r Reader) ObjectName(ctx context.Context, at uint64) (Name, error) {
	result := Name{}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if r.Layer == nil || r.KernelSymbols == nil || r.KernelSymbols.PointerSize() != 8 {
		return result, nameSchemaError{fmt.Errorf("GUI names require session memory and matching x64 kernel symbols")}
	}
	kernel := &object.Reader{Layer: r.Layer, Symbols: r.KernelSymbols}
	body, err := kernel.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return result, nameSchemaError{err}
	}
	if at < body.Offset {
		return result, fmt.Errorf("GUI object header underflow")
	}
	result.Header = at - body.Offset
	var delta uint64
	if _, err := kernel.Field("_OBJECT_HEADER", "NameInfoOffset"); err == nil {
		delta, err = r.nameUint(ctx, kernel, result.Header, "_OBJECT_HEADER", "NameInfoOffset")
		if err != nil {
			return result, err
		}
	} else if errors.Is(err, object.ErrFieldAbsent) {
		mask, err := r.nameUint(ctx, kernel, result.Header, "_OBJECT_HEADER", "InfoMask")
		if err != nil {
			return result, err
		}
		symbol, err := r.KernelSymbols.Lookup("ObpInfoMaskToOffset")
		if err != nil {
			return result, nameSchemaError{err}
		}
		table, err := memory.Add(r.KernelBase, symbol.Address)
		if err != nil {
			return result, err
		}
		slot, err := memory.Add(table, mask&3)
		if err != nil {
			return result, err
		}
		raw, err := memory.Read(ctx, r.Layer, slot, 1)
		if err != nil {
			return result, err
		}
		delta = uint64(raw[0])
	} else {
		return result, nameSchemaError{err}
	}
	if delta == 0 {
		return result, nil
	}
	if delta > 255 || result.Header < delta {
		return result, fmt.Errorf("invalid GUI name-info displacement")
	}
	result.Info = result.Header - delta
	length, err := r.nameUint(ctx, kernel, result.Info, "_OBJECT_HEADER_NAME_INFO", "Name.Length")
	if err != nil {
		return result, err
	}
	if length == 0 {
		return result, nil
	}
	maximum, err := r.nameUint(ctx, kernel, result.Info, "_OBJECT_HEADER_NAME_INFO", "Name.MaximumLength")
	if err != nil {
		return result, err
	}
	if maximum == 0 || length > maximum {
		return result, nil
	}
	if length > 65535 {
		return result, fmt.Errorf("GUI name exceeds unsigned 16-bit length bound")
	}
	result.Buffer, err = r.nameUint(ctx, kernel, result.Info, "_OBJECT_HEADER_NAME_INFO", "Name.Buffer")
	if err != nil {
		return result, err
	}
	result.Raw, err = readName(ctx, r.Layer, result.Buffer, int(length))
	if err != nil {
		return result, err
	}
	text := decodeName(result.Raw)
	result.Text = &text
	return result, nil
}
func (r Reader) nameUint(ctx context.Context, kernel *object.Reader, at uint64, typ, member string) (uint64, error) {
	field, err := kernel.Field(typ, member)
	if err != nil {
		return 0, nameSchemaError{err}
	}
	address, err := memory.Add(at, field.Offset)
	if err != nil {
		return 0, err
	}
	return kernel.Scalar(ctx, address, field.Type)
}
func readName(ctx context.Context, layer memory.MemoryLayer, at uint64, size int) ([]byte, error) {
	if size < 0 || size > 65535 {
		return nil, fmt.Errorf("invalid GUI name read bound")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := memory.Add(at, uint64(size)); err != nil {
		return nil, err
	}
	raw := make([]byte, size)
	n, err := layer.ReadAt(ctx, raw, at)
	if n < 0 || n > len(raw) {
		return nil, fmt.Errorf("GUI name layer returned invalid byte count")
	}
	raw = raw[:n]
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return raw, &memory.ReadError{Address: at, Length: size, Layer: layer.Name(), Cause: err}
	}
	return raw, nil
}

// Python's UTF-16 replacement codec consumes a trailing high surrogate and a
// single remaining byte together as one broken sequence. Decoding uint16s and
// appending another replacement for every odd tail would produce different text.
func decodeName(raw []byte) string {
	var order binary.ByteOrder = binary.LittleEndian
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			raw = raw[2:]
		} else if raw[0] == 0xfe && raw[1] == 0xff {
			order = binary.BigEndian
			raw = raw[2:]
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
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	return text
}

type StationInfo struct {
	Name         *string
	Session      *uint64
	NameEvidence Name
}

func (r Reader) StationInfo(ctx context.Context, at uint64) (StationInfo, error) {
	result := StationInfo{}
	name, nameErr := r.ObjectName(ctx, at)
	result.NameEvidence = name
	var schema nameSchemaError
	if errors.As(nameErr, &schema) || ctx.Err() != nil {
		return result, errors.Join(nameErr, ctx.Err())
	}
	sid, err := r.StationSession(ctx, at)
	if name.Text != nil && utf8.RuneCountInString(*name.Text) > 1 && sid != nil && *sid < 256 {
		result.Name, result.Session = name.Text, sid
	}
	return result, errors.Join(nameErr, err)
}

// Desktops repeats the root's rpdeskList access, as the pinned method does.
// The name is read before the seen check. Names swallowed as None upstream
// still produce a desktop tuple; native read errors accompany that prefix.
func (r Reader) Desktops(ctx context.Context, at, maxNodes uint64, emit func(uint64, Name) error) error {
	if maxNodes > 1000000 || emit == nil {
		return fmt.Errorf("GUI desktops require emitter and bound 0..1000000")
	}
	o, err := r.objects()
	if err != nil {
		return err
	}
	var first error
	var failures uint64
	finish := func(err error) error {
		if first != nil {
			return errors.Join(fmt.Errorf("GUI desktop names: %d failures; first: %w", failures, first), err)
		}
		return err
	}
	seen := map[uint64]bool{}
	for uint64(len(seen)) < maxNodes {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		desktop, err := o.Uint(ctx, at, "tagWINDOWSTATION", "rpdeskList")
		if err != nil {
			return finish(err)
		}
		name, err := r.ObjectName(ctx, desktop)
		var schema nameSchemaError
		if errors.As(err, &schema) || ctx.Err() != nil {
			return finish(errors.Join(err, ctx.Err()))
		}
		if err != nil {
			failures++
			if first == nil {
				first = err
			}
		}
		if seen[desktop] {
			return finish(nil)
		}
		if err := emit(desktop, name); err != nil {
			return finish(err)
		}
		seen[desktop] = true
	}
	return finish(ctx.Err())
}
