package wincallbacks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type Entry struct {
	Type, Route      string
	Source, Callback uint64
	Detail           evidence.Value
}
type Emit func(Entry) error

// Index walks notification, bugcheck and registry roots. It does not infer
// pool coverage. All reads go through Layer for caller-owned evidence capture.
type Index struct {
	Table           *Table
	Layer           memory.MemoryLayer
	KernelBase      uint64
	Vista           bool
	MaxNodes        uint64
	nodes, failures uint64
	first, stop     error
	reader          *object.Reader
}

func (x *Index) failed(err error) {
	if err != nil {
		x.failures++
		if x.first == nil {
			x.first = err
		}
	}
}
func (x *Index) step(ctx context.Context) error {
	if x.stop != nil {
		return x.stop
	}
	if err := ctx.Err(); err != nil {
		x.stop = err
		return err
	}
	if x.nodes >= x.MaxNodes {
		x.stop = fmt.Errorf("callback index node bound exhausted")
		return x.stop
	}
	x.nodes++
	return nil
}
func (x *Index) has(name string) bool { _, err := x.Table.Lookup(name); return err == nil }
func (x *Index) symbol(name string) (uint64, error) {
	s, err := x.Table.Lookup(name)
	if err != nil {
		return 0, err
	}
	return memory.Add(x.KernelBase, s.Address)
}
func (x *Index) fastRefs(ctx context.Context, root, count uint64, typ, field, label, route string, emit Emit) error {
	declared, err := x.Table.Type("_EX_FAST_REF")
	if err != nil {
		return err
	}
	if declared.Size == 0 || declared.Size > 4096 {
		return fmt.Errorf("invalid fast-reference stride")
	}
	mask := uint64(7)
	if x.Table.PointerSize() == 8 {
		mask = 15
	}
	for i := uint64(0); i < count; i++ {
		if err := x.step(ctx); err != nil {
			return err
		}
		if i > ^uint64(0)/declared.Size {
			return fmt.Errorf("fast-reference stride overflow")
		}
		at, err := memory.Add(root, i*declared.Size)
		if err != nil {
			return err
		}
		raw, err := x.reader.Uint(ctx, at, "_EX_FAST_REF", "Object")
		if err != nil {
			x.failed(err)
			continue
		}
		// Even a null reference is cast at offset zero by the fixed baseline.
		// Its callback field, rather than the reference itself, controls emission.
		source := raw &^ mask
		callback, err := x.reader.Uint(ctx, source, "callbacks!"+typ, field)
		if err != nil {
			x.failed(err)
			continue
		}
		if callback != 0 {
			if err := emit(Entry{Type: label, Route: route, Source: source, Callback: callback, Detail: evidence.Missing("not_applicable", nil)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (x *Index) notify(ctx context.Context, emit Emit) error {
	for _, name := range []string{"PspLoadImageNotifyRoutine", "PspCreateThreadNotifyRoutine", "PspCreateProcessNotifyRoutine"} {
		if !x.has(name) {
			continue
		}
		root, err := x.symbol(name)
		if err != nil {
			x.failed(err)
			continue
		}
		count := uint64(8)
		if x.Vista && name != "PspLoadImageNotifyRoutine" {
			count = 64
		}
		x.failed(x.fastRefs(ctx, root, count, "_GENERIC_CALLBACK", "Callback", name, "notify", emit))
		if x.stop != nil {
			return x.stop
		}
	}
	return nil
}
func (x *Index) component(ctx context.Context, address uint64) (evidence.Value, error) {
	raw, err := memory.Read(ctx, x.Layer, address, 64)
	if err != nil {
		return evidence.Missing("unreadable", err), err
	}
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		raw = raw[:end]
	}
	return evidence.Text(memoryscan.DisplayUTF8(raw)), nil
}
func (x *Index) bugcheck(ctx context.Context, reason bool, emit Emit) error {
	name, typ := "KeBugCheckCallbackListHead", "callbacks!_KBUGCHECK_CALLBACK_RECORD"
	if reason {
		name, typ = "KeBugCheckReasonCallbackListHead", "callbacks!_KBUGCHECK_REASON_CALLBACK_RECORD"
	}
	if !x.has(name) {
		return nil
	}
	head, err := x.symbol(name)
	if err != nil {
		return err
	}
	entry, err := x.reader.Field(typ, "Entry")
	if err != nil {
		return err
	}
	return x.reader.WalkList(ctx, head, entry.Offset, 1000000, func(at uint64) error {
		if err := x.step(ctx); err != nil {
			return err
		}
		callback, err := x.reader.Uint(ctx, at, typ, "CallbackRoutine")
		if err != nil {
			x.failed(err)
			return nil
		}
		if _, err := memory.Read(ctx, x.Layer, callback, 64); err != nil {
			x.failed(err)
			return nil
		}
		component, err := x.reader.Uint(ctx, at, typ, "Component")
		if err != nil {
			x.failed(err)
			return nil
		}
		if !reason {
			// The baseline's ordinary bugcheck path omits absolute=True;
			// only its reason-callback path treats Component as absolute.
			component, err = memory.Add(x.KernelBase, component)
			if err != nil {
				x.failed(err)
				return emit(Entry{Type: name, Route: "bugcheck", Source: at, Callback: callback, Detail: evidence.Missing("unreadable", err)})
			}
		}
		detail, err := x.component(ctx, component)
		x.failed(err)
		return emit(Entry{Type: name, Route: "bugcheck", Source: at, Callback: callback, Detail: detail})
	})
}
func (x *Index) altitude(ctx context.Context, at uint64) (string, error) {
	n, err := x.reader.Uint(ctx, at, "callbacks!_CM_CALLBACK_ENTRY", "Altitude.Length")
	if err != nil {
		return "", err
	}
	if n > 65534 || n%2 != 0 {
		return "", fmt.Errorf("invalid callback altitude UTF-16 length")
	}
	buffer, err := x.reader.Uint(ctx, at, "callbacks!_CM_CALLBACK_ENTRY", "Altitude.Buffer")
	if err != nil {
		return "", err
	}
	raw, err := memory.Read(ctx, x.Layer, buffer, int(n))
	if err != nil {
		return "", err
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(u)), nil
}
func (x *Index) registry(ctx context.Context, emit Emit) error {
	if !x.has("CmpCallBackCount") {
		return nil
	}
	legacy := x.has("CmpCallBackVector")
	if !legacy && !x.has("CallbackListHead") {
		return nil
	}
	countAt, err := x.symbol("CmpCallBackCount")
	if err != nil {
		return err
	}
	raw, err := memory.Read(ctx, x.Layer, countAt, 4)
	if err != nil {
		return err
	}
	count := uint64(binary.LittleEndian.Uint32(raw))
	if count == 0 {
		return nil
	}
	if legacy {
		root, err := x.symbol("CmpCallBackVector")
		if err != nil {
			return err
		}
		return x.fastRefs(ctx, root, count, "_EX_CALLBACK_ROUTINE_BLOCK", "Function", "CmRegisterCallback", "registry_legacy", emit)
	}
	head, err := x.symbol("CallbackListHead")
	if err != nil {
		return err
	}
	link, err := x.reader.Field("callbacks!_CM_CALLBACK_ENTRY", "Link")
	if err != nil {
		return err
	}
	return x.reader.WalkList(ctx, head, link.Offset, 1000000, func(at uint64) error {
		if err := x.step(ctx); err != nil {
			return err
		}
		callback, err := x.reader.Uint(ctx, at, "callbacks!_CM_CALLBACK_ENTRY", "Function")
		if err != nil {
			x.failed(err)
			return nil
		}
		altitude, err := x.altitude(ctx, at)
		x.failed(err)
		detail := evidence.Text("Altitude: " + altitude)
		if err != nil {
			detail = evidence.Missing("unreadable_altitude", err)
		}
		// Unlike legacy registry vectors, this path does not filter Function=0.
		return emit(Entry{Type: "CmRegisterCallbackEx", Route: "registry_list", Source: at, Callback: callback, Detail: detail})
	})
}

// Walk preserves upstream method order and duplicates. Missing optional roots
// are skipped, but a kernel exposing none of these roots is explicitly unsupported.
// Independent damaged roots leave partial entries and a failed result.
func (x *Index) Walk(ctx context.Context, emit Emit) error {
	if x == nil || x.Table == nil || x.Table.local == nil || x.Layer == nil || emit == nil || x.MaxNodes == 0 || x.MaxNodes > 1000000 {
		return fmt.Errorf("invalid callback index configuration")
	}
	x.nodes, x.failures, x.first, x.stop = 0, 0, nil, nil
	x.reader = &object.Reader{Layer: x.Layer, Symbols: x.Table}
	if err := ctx.Err(); err != nil {
		return err
	}
	found := false
	for _, root := range []string{"PspLoadImageNotifyRoutine", "PspCreateThreadNotifyRoutine", "PspCreateProcessNotifyRoutine", "KeBugCheckCallbackListHead", "KeBugCheckReasonCallbackListHead"} {
		found = found || x.has(root)
	}
	found = found || x.has("CmpCallBackCount") && (x.has("CmpCallBackVector") || x.has("CallbackListHead"))
	if !found {
		return fmt.Errorf("callback index roots unavailable")
	}
	send := func(entry Entry) error {
		if x.stop != nil {
			return x.stop
		}
		if err := ctx.Err(); err != nil {
			x.stop = err
			return err
		}
		x.stop = emit(entry)
		if x.stop == nil {
			x.stop = ctx.Err()
		}
		return x.stop
	}
	for _, walk := range []func() error{func() error { return x.notify(ctx, send) }, func() error { return x.bugcheck(ctx, false, send) }, func() error { return x.bugcheck(ctx, true, send) }, func() error { return x.registry(ctx, send) }} {
		x.failed(walk())
		if x.stop != nil || ctx.Err() != nil {
			break
		}
	}
	var cause error
	if x.first != nil {
		cause = fmt.Errorf("callback index: %d failure observations; first: %w", x.failures, x.first)
	}
	return errors.Join(cause, x.stop, ctx.Err())
}

var _ symbols.SymbolTable = (*Table)(nil)
