package kallsyms

import (
	"context"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

func readPointer(ctx context.Context, r *object.Reader, at uint64, typ, field string) (uint64, error) {
	f, err := r.Field(typ, field)
	if err != nil {
		return 0, err
	}
	size, err := r.Size(f.Type)
	if err != nil {
		return 0, err
	}
	if f.Type.Kind != "pointer" || size != uint64(r.Symbols.PointerSize()) {
		return 0, fmt.Errorf("%s.%s is not a kernel-width pointer", typ, field)
	}
	return r.Uint(ctx, at, typ, field)
}
func readArrayName(ctx context.Context, r *object.Reader, at uint64, typ, field string) (string, uint64, error) {
	f, err := r.Field(typ, field)
	if err != nil {
		return "", 0, err
	}
	if f.Type.Kind != "array" || f.Type.Subtype == nil || f.Type.Count > 1<<20 {
		return "", 0, fmt.Errorf("invalid %s.%s name array", typ, field)
	}
	width, err := r.Size(*f.Type.Subtype)
	if err != nil {
		return "", 0, err
	}
	if width != 1 {
		return "", 0, fmt.Errorf("name array elements must be bytes")
	}
	if f.Type.Count == 0 {
		return "", 0, nil
	}
	start, err := memory.Add(at, f.Offset)
	if err != nil {
		return "", 0, err
	}
	raw, err := memory.Read(ctx, r.Layer, start, int(f.Type.Count))
	if err != nil {
		return "", 0, err
	}
	return namePrefix(raw), f.Type.Count, nil
}

func namePrefix(raw []byte) string {
	text := strings.ToValidUTF8(string(raw), "\ufffd")
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	if i := strings.IndexRune(text, '\ufffd'); i >= 0 {
		text = text[:i]
	}
	return text
}
func readName(ctx context.Context, r *object.Reader, at uint64, count int) (string, error) {
	if count < 1 || count > 1<<20 {
		return "", fmt.Errorf("invalid symbol name extent")
	}
	raw, err := memory.Read(ctx, r.Layer, at, count)
	if err != nil {
		return "", err
	}
	return namePrefix(raw), ctx.Err()
}

func readNonnegativeSize(ctx context.Context, r *object.Reader, at uint64, typ, field string) (uint64, error) {
	layout, err := r.Field(typ, field)
	if err != nil {
		return 0, err
	}
	if layout.Type.Kind == "base" {
		scalar, err := r.Symbols.Type(layout.Type.Name)
		if err != nil {
			return 0, err
		}
		if scalar.Signed {
			value, err := r.Int(ctx, at, typ, field)
			if err != nil {
				return 0, err
			}
			if value < 0 {
				return 0, fmt.Errorf("negative %s.%s", typ, field)
			}
			return uint64(value), nil
		}
	}
	return r.Uint(ctx, at, typ, field)
}
