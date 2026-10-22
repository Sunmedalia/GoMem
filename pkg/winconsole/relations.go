package winconsole

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/object"
)

// ScreenLink distinguishes the pointer field address exposed by the original
// generator from the target object used for screen reads.
type ScreenLink struct{ Address, Target uint64 }

// WalkScreens visits the current screen chain before the alternate chain,
// deduplicating pointer field addresses globally. It checks the same metadata the
// original generator touches before yielding, while retaining malformed lengths,
// read errors and non-terminating chains as errors. The limit covers both roots.
func (r ConsoleReader) WalkScreens(ctx context.Context, at uint64, layout *ScreenLayout, maxScreens uint64, emit func(ScreenLink) error) error {
	if maxScreens == 0 || maxScreens > 1000000 || emit == nil || layout == nil {
		return fmt.Errorf("console screens require layout, emitter and limit 1..1000000")
	}
	if r.Layout == nil || r.Layer == nil || layout.SHA256 != r.Layout.SHA256 {
		return fmt.Errorf("console screen and object layouts must share the same source digest")
	}
	current, err := r.Scalar(ctx, at, "_CONSOLE_INFORMATION.CurrentScreenBuffer")
	if err != nil {
		return err
	}
	alternate, err := r.Scalar(ctx, at, "_CONSOLE_INFORMATION.GetScreenBuffer")
	if err != nil {
		return err
	}
	screens := ScreenReader{Layer: r.Layer, Layout: layout}
	seen := map[uint64]bool{}
	var failures []error
	stop := func(err error) error { return errors.Join(append(failures, err)...) }
	roots := []ScreenLink{{current.Address, current.Value}}
	if alternate.Value != current.Value {
		roots = append(roots, ScreenLink{alternate.Address, alternate.Value})
	}
	for _, root := range roots {
		path := map[uint64]bool{}
		for link := root; link.Target != 0; {
			if err := ctx.Err(); err != nil {
				return stop(err)
			}
			if path[link.Address] {
				failures = append(failures, fmt.Errorf("console screen cycle at pointer 0x%x", link.Address))
				break
			}
			if seen[link.Address] {
				break
			}
			if uint64(len(seen)) >= maxScreens {
				return stop(fmt.Errorf("console screen node bound exhausted"))
			}
			buffer, err := screens.field(ctx, link.Target, "_SCREEN_INFORMATION.TextBufferInfo", false)
			if err != nil {
				return stop(err)
			}
			capacity, err := screens.field(ctx, buffer, "_TEXT_BUFFER_INFO.BufferCapacity", true)
			if err != nil {
				return stop(err)
			}
			if int64(capacity) < 0 {
				return stop(fmt.Errorf("negative console screen capacity %d", int64(capacity)))
			}
			if _, err := screens.rowsAddress(ctx, buffer); err != nil {
				return stop(err)
			}
			seen[link.Address], path[link.Address] = true, true
			if err := emit(link); err != nil {
				return stop(err)
			}
			address, err := screenOffset(link.Target, layout.fields["_SCREEN_INFORMATION.Next"])
			if err != nil {
				return stop(err)
			}
			next, err := screens.field(ctx, link.Target, "_SCREEN_INFORMATION.Next", false)
			if err != nil {
				return stop(err)
			}
			link = ScreenLink{address, next}
		}
	}
	return errors.Join(append(failures, ctx.Err())...)
}

// CommandText projects an embedded _COMMAND without discarding its original
// bytes. A nil string is the pinned extension's None result for length >=1024.
// The returned address identifies the command object (not its pointer payload).
func (r ConsoleReader) CommandText(ctx context.Context, at uint64, field string) (address uint64, text *string, raw []byte, err error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, nil, err
	}
	if r.Layer == nil || r.Layout == nil {
		return 0, nil, nil, fmt.Errorf("console text requires memory and layout")
	}
	f, err := r.Layout.Field(field)
	if err != nil {
		return 0, nil, nil, err
	}
	if f.Type.Kind != "struct" || f.Type.Name != "_COMMAND" {
		return 0, nil, nil, fmt.Errorf("%s is not an embedded console command", field)
	}
	address, err = r.Layout.Address(at, field)
	if err != nil {
		return address, nil, nil, err
	}
	reader := Reader{Objects: &object.Reader{Layer: r.Layer, Symbols: r.Layout.History}}
	text, raw, err = reader.Text(ctx, address)
	return address, text, raw, err
}

var ErrLegacyExeName = errors.New("baseline legacy ExeName pointer dereferences a string without get_string")

// ExeName follows the original method. Older pointer layouts raise an
// AttributeError in the baseline rather than providing a decoded executable;
// callers receive an explicit unsupported error instead of invented text.
func (r ConsoleReader) ExeName(ctx context.Context, at uint64) (address uint64, text *string, raw []byte, err error) {
	f, err := r.Layout.Field("_EXE_ALIAS_LIST.ExeName")
	if err != nil {
		return 0, nil, nil, err
	}
	if f.Type.Kind == "pointer" {
		value, err := r.Scalar(ctx, at, "_EXE_ALIAS_LIST.ExeName")
		if err != nil {
			return value.Address, nil, value.Raw, err
		}
		return value.Address, nil, value.Raw, ErrLegacyExeName
	}
	return r.CommandText(ctx, at, "_EXE_ALIAS_LIST.ExeName")
}
