package wingui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// Reader resolves GUI pointers in one explicitly supplied session layer. Kernel
// fields use a separate matching table, but the same session address space.
// Wrapping Layer with an acquisition recorder retains every original read.
type Reader struct {
	Layer         memory.MemoryLayer
	Layout        *Layout
	KernelSymbols symbols.SymbolTable
}

func (r Reader) objects() (*object.Reader, error) {
	if r.Layer == nil || r.Layout == nil || r.Layout.Types == nil {
		return nil, fmt.Errorf("GUI reader requires a session layer and layout")
	}
	return &object.Reader{Layer: r.Layer, Symbols: r.Layout.Types}, nil
}

func (r Reader) StationSession(ctx context.Context, at uint64) (*uint64, error) {
	o, err := r.objects()
	if err != nil {
		return nil, err
	}
	sid, err := o.Uint(ctx, at, "tagWINDOWSTATION", "dwSessionId")
	if err != nil {
		return nil, err
	}
	return &sid, nil
}
func (r Reader) StationValid(ctx context.Context, at uint64) (bool, error) {
	sid, err := r.StationSession(ctx, at)
	return sid != nil && *sid < 256, err
}
func (r Reader) DesktopStation(ctx context.Context, at uint64) (*uint64, error) {
	o, err := r.objects()
	if err != nil {
		return nil, err
	}
	station, err := o.Uint(ctx, at, "tagDESKTOP", "rpwinstaParent")
	if err != nil {
		return nil, err
	}
	return &station, nil
}
func (r Reader) DesktopSession(ctx context.Context, at uint64) (*uint64, error) {
	station, err := r.DesktopStation(ctx, at)
	if err != nil {
		return nil, err
	}
	// The original dereference constructs an object at zero as well. A mapped
	// zero parent is not automatically absent; its session field is still read.
	return r.StationSession(ctx, *station)
}
func (r Reader) DesktopValid(ctx context.Context, at uint64) (bool, error) {
	sid, err := r.DesktopSession(ctx, at)
	if err != nil || sid == nil || *sid >= 256 {
		return false, err
	}
	_, err = r.DesktopStation(ctx, at)
	return err == nil, err
}

// TraverseStations preserves the fixed baseline's repeated root.rpwinstaNext
// access, including duplicate self and null targets. maxExtra bounds additional
// stations, so zero still emits the root and one can emit two objects. Names,
// session validity and global deduplication belong to the plugin's outer scan.
func (r Reader) TraverseStations(ctx context.Context, at uint64, maxExtra uint64, emit func(uint64) error) error {
	if maxExtra > 1000000 || emit == nil {
		return fmt.Errorf("GUI station traversal requires emitter and extra bound 0..1000000")
	}
	o, err := r.objects()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := emit(at); err != nil {
		return err
	}
	seen := map[uint64]bool{}
	for uint64(len(seen)) < maxExtra {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := o.Uint(ctx, at, "tagWINDOWSTATION", "rpwinstaNext")
		if err != nil {
			return err
		}
		if seen[next] {
			return nil
		}
		if err := emit(next); err != nil {
			return err
		}
		seen[next] = true
	}
	return ctx.Err()
}

type ThreadOwner struct {
	Thread      uint64 `json:"thread"`
	Name        string `json:"name"`
	PID         uint64 `json:"pid"`
	ProcessInfo uint64 `json:"-"`
	Process     uint64 `json:"-"`
	RawName     []byte `json:"-"`
}

// Threads follows the original forward LIST_ENTRY semantics: the target list
// entry must be fully readable, while Blink contents are not compared. A bad
// owner is retained as an error and independent later nodes are still visited.
// Read/limit/cycle failures return after the successfully emitted prefix.
func (r Reader) Threads(ctx context.Context, at uint64, maxNodes uint64, emit func(ThreadOwner) error) error {
	if maxNodes == 0 || maxNodes > 1000000 || emit == nil {
		return fmt.Errorf("GUI threads require emitter and node bound 1..1000000")
	}
	o, err := r.objects()
	if err != nil {
		return err
	}
	if r.KernelSymbols == nil || r.KernelSymbols.PointerSize() != 8 {
		return fmt.Errorf("GUI threads require matching x64 kernel symbols")
	}
	kernel := &object.Reader{Layer: r.Layer, Symbols: r.KernelSymbols}
	listSize, err := kernel.Size(symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"})
	if err != nil || listSize != 16 {
		return fmt.Errorf("invalid GUI kernel list size %d: %v", listSize, err)
	}
	headField := r.Layout.Types.Types["tagDESKTOP"].Fields["PtiList"]
	nodeField := r.Layout.Types.Types["tagTHREADINFO"].Fields["PtiLink"]
	head, err := memory.Add(at, headField.Offset)
	if err != nil {
		return err
	}
	if _, err := memory.Read(ctx, r.Layer, head, 1); err != nil {
		return err
	}
	current := head
	seen := map[uint64]bool{head: true}
	var failures []error
	fail := func(err error) error { return errors.Join(append(failures, err)...) }
	for count := uint64(0); ; {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		next, err := kernel.Uint(ctx, current, "_LIST_ENTRY", "Flink")
		if err != nil {
			return fail(err)
		}
		if next == 0 {
			return fail(fmt.Errorf("null GUI thread link at 0x%x", current))
		}
		if _, err = memory.Read(ctx, r.Layer, next, int(listSize)); err != nil {
			return fail(err)
		}
		if next == head {
			return fail(nil)
		}
		if seen[next] {
			return fail(fmt.Errorf("GUI thread list cycle at 0x%x", next))
		}
		if count >= maxNodes {
			return fail(fmt.Errorf("GUI thread node bound exhausted"))
		}
		if next < nodeField.Offset {
			return fail(fmt.Errorf("GUI thread container underflow"))
		}
		thread := next - nodeField.Offset
		if _, err := memory.Read(ctx, r.Layer, thread, 1); err != nil {
			return fail(err)
		}
		seen[next] = true
		count++
		owner, err := r.threadOwner(ctx, o, kernel, thread)
		if err != nil {
			failures = append(failures, fmt.Errorf("GUI thread 0x%x owner: %w", thread, err))
			if ctx.Err() != nil {
				return fail(ctx.Err())
			}
		} else if err := emit(owner); err != nil {
			return fail(err)
		}
		current = next
	}
}

func (r Reader) threadOwner(ctx context.Context, o, kernel *object.Reader, thread uint64) (ThreadOwner, error) {
	result := ThreadOwner{Thread: thread}
	var err error
	result.ProcessInfo, err = o.Uint(ctx, thread, "tagTHREADINFO", "ppi")
	if err != nil {
		return result, err
	}
	result.Process, err = o.Uint(ctx, result.ProcessInfo, "tagPROCESSINFO", "Process")
	if err != nil {
		return result, err
	}
	field, err := kernel.Field("_EPROCESS", "ImageFileName")
	if err != nil {
		return result, err
	}
	if field.Type.Kind != "array" || field.Type.Subtype == nil {
		return result, fmt.Errorf("GUI process name is not a byte array")
	}
	size, err := kernel.Size(*field.Type.Subtype)
	if err != nil || size != 1 || field.Type.Count == 0 || field.Type.Count > 256 {
		return result, fmt.Errorf("invalid GUI process name array")
	}
	address, err := memory.Add(result.Process, field.Offset)
	if err != nil {
		return result, err
	}
	result.RawName, err = memory.Read(ctx, r.Layer, address, int(field.Type.Count))
	if err != nil {
		return result, err
	}
	result.Name = memoryscan.DisplayUTF8(result.RawName)
	if i := strings.IndexAny(result.Name, "\x00\ufffd"); i >= 0 {
		result.Name = result.Name[:i]
	}
	result.PID, err = kernel.Uint(ctx, result.Process, "_EPROCESS", "UniqueProcessId")
	return result, err
}
