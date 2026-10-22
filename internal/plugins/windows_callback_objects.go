package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/wincallbacks"
)

type callbackDecoded struct {
	typ, detail evidence.Value
	address     uint64
	valid       bool
}

func callbackReadable(ctx context.Context, r *object.Reader, at uint64, typ string) error {
	t, err := r.Symbols.Type(typ)
	if err != nil {
		return err
	}
	if t.Size == 0 || t.Size > 1<<20 {
		return fmt.Errorf("callback pointer target has invalid %s size", typ)
	}
	_, err = memory.Read(ctx, r.Layer, at, int(t.Size))
	return err
}

func callbackObjectType(ctx context.Context, e plugin.Environment, at uint64, types map[int]string) (string, error) {
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return "", err
	}
	// The pinned callback methods omit get_object_type's cookie argument.
	// Preserve that decision even when ObHeaderCookie exists in the kernel.
	return poolObjectType(ctx, e.Objects, e.Kernel, at, body.Offset, types, 0, false)
}

func callbackObjectName(ctx context.Context, e plugin.Environment, at uint64) (evidence.Value, error) {
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return evidence.Value{}, err
	}
	if at < body.Offset {
		return evidence.Value{}, fmt.Errorf("callback driver object header underflow")
	}
	header := at - body.Offset
	delta, err := mutantNameInfoOffset(ctx, e, e.Objects, header)
	if err != nil {
		return evidence.Value{}, err
	}
	if delta == 0 || header < uint64(delta) {
		return evidence.Value{}, fmt.Errorf("callback driver NameInfo unavailable")
	}
	return volatilityObjectString(ctx, e.Kernel, e.Objects, header-uint64(delta), "_OBJECT_HEADER_NAME_INFO", "Name")
}

// Only the x86 callback table installs _SHUTDOWN_PACKET's extension. The x64
// table intentionally does not run these validity/Device checks in the baseline.
func callbackShutdownValid(ctx context.Context, e plugin.Environment, scan *object.Reader, at uint64, types map[int]string) (bool, error) {
	for _, field := range []string{"Entry.Flink", "Entry.Blink"} {
		link, err := scan.Uint(ctx, at, "callbacks!_SHUTDOWN_PACKET", field)
		if err != nil {
			return false, err
		}
		if err := callbackReadable(ctx, e.Objects, link, "_LIST_ENTRY"); err != nil {
			return false, err
		}
	}
	device, err := scan.Uint(ctx, at, "callbacks!_SHUTDOWN_PACKET", "DeviceObject")
	if err != nil {
		return false, err
	}
	if err := callbackReadable(ctx, e.Objects, device, "_DEVICE_OBJECT"); err != nil {
		return false, err
	}
	if device == 0 {
		return false, nil
	}
	driver, err := e.Objects.Uint(ctx, device, "_DEVICE_OBJECT", "DriverObject")
	if err != nil {
		return false, err
	}
	start, err := e.Objects.Uint(ctx, driver, "_DRIVER_OBJECT", "DriverStart")
	if err != nil {
		return false, err
	}
	if start%0x1000 != 0 {
		return false, nil
	}
	name, err := callbackObjectType(ctx, e, device, types)
	return name == "Device" && err == nil, err
}

func callbackShutdownHandler(ctx context.Context, e plugin.Environment, scan *object.Reader, at uint64) (uint64, evidence.Value, error) {
	device, err := scan.Uint(ctx, at, "callbacks!_SHUTDOWN_PACKET", "DeviceObject")
	if err != nil {
		return at, evidence.Missing("not_applicable", nil), err
	}
	driver, err := e.Objects.Uint(ctx, device, "_DEVICE_OBJECT", "DriverObject")
	if err != nil {
		return at, evidence.Missing("not_applicable", nil), err
	}
	major, err := e.Objects.Field("_DRIVER_OBJECT", "MajorFunction")
	if err != nil {
		return at, evidence.Missing("not_applicable", nil), err
	}
	if major.Type.Kind != "array" || major.Type.Subtype == nil || major.Type.Count <= 16 {
		return at, evidence.Missing("not_applicable", nil), fmt.Errorf("callback driver MajorFunction must contain shutdown slot 16")
	}
	stride, err := e.Objects.Size(*major.Type.Subtype)
	if err != nil || stride != uint64(e.Symbols.PointerSize()) {
		return at, evidence.Missing("not_applicable", nil), fmt.Errorf("invalid callback driver MajorFunction stride")
	}
	slot, err := memory.Add(driver, major.Offset)
	if err == nil {
		slot, err = memory.Add(slot, 16*stride)
	}
	if err != nil {
		return at, evidence.Missing("not_applicable", nil), err
	}
	handler, err := e.Objects.Scalar(ctx, slot, *major.Type.Subtype)
	if err != nil {
		return at, evidence.Missing("not_applicable", nil), err
	}
	name, err := volatilityObjectString(ctx, e.Kernel, e.Objects, driver, "_DRIVER_OBJECT", "DriverName")
	if err != nil {
		return at, evidence.Missing("not_applicable", nil), err
	}
	if name.String() == "" {
		name = evidence.Missing("unparsable", nil)
	}
	return handler, name, nil
}

// callbackPoolObject reads fields in the allocation's source layer, then follows
// DeviceObject/DriverObject pointers in the native kernel layer. It never treats
// a physical allocation offset as the address of a virtual pointer target.
func callbackPoolObject(ctx context.Context, e plugin.Environment, table *wincallbacks.Table, hit poolHit, types map[int]string) (callbackDecoded, error) {
	result := callbackDecoded{detail: evidence.Missing("not_applicable", nil)}
	if table == nil || hit.scan == nil || hit.scan.Layer == nil || e.Objects == nil || e.Kernel == nil {
		return result, fmt.Errorf("invalid callback pool decoding environment")
	}
	scan := &object.Reader{Layer: hit.scan.Layer, Symbols: table}
	typ := "callbacks!" + hit.typ
	var field string
	switch hit.typ {
	case "_SHUTDOWN_PACKET":
		result.typ = evidence.Text("IoRegisterShutdownNotification")
		if table.PointerSize() == 4 {
			valid, err := callbackShutdownValid(ctx, e, scan, hit.object, types)
			if err != nil || !valid {
				return result, err
			}
		}
		result.valid = true
		address, detail, err := callbackShutdownHandler(ctx, e, scan, hit.object)
		result.address, result.detail = address, detail
		return result, err
	case "_NOTIFICATION_PACKET":
		result.typ = evidence.Text("IoRegisterFsRegistrationChange")
		field = "NotificationRoutine"
	case "_GENERIC_CALLBACK":
		result.typ = evidence.Text("GenericKernelCallback")
		field = "Callback"
	case "_DBGPRINT_CALLBACK":
		result.typ = evidence.Text("DbgSetDebugPrintCallback")
		field = "Function"
	case "_NOTIFY_ENTRY_HEADER":
		_, names, err := scan.Enum(ctx, hit.object, typ, "EventCategory")
		if err != nil {
			return result, err
		}
		result.typ = evidence.Missing("unparsable", nil)
		if len(names) > 0 {
			result.typ = evidence.Text(names[0])
		}
		address, err := scan.Uint(ctx, hit.object, typ, "CallbackRoutine")
		if err != nil {
			return result, err
		}
		result.address, result.valid = address, true
		driver, err := scan.Uint(ctx, hit.object, typ, "DriverObject")
		if err == nil {
			err = callbackReadable(ctx, e.Objects, driver, "_DRIVER_OBJECT")
		}
		if err != nil {
			result.detail = evidence.Missing("unreadable", err)
			return result, err
		}
		kind, err := callbackObjectType(ctx, e, driver, types)
		if err != nil {
			result.detail = evidence.Missing("unreadable", err)
			return result, err
		}
		if kind != "Driver" {
			return result, nil
		}
		name, err := callbackObjectName(ctx, e, driver)
		if err != nil {
			result.detail = evidence.Missing("unreadable", err)
			return result, err
		}
		result.detail = name
		return result, nil
	default:
		return result, fmt.Errorf("unexpected callback pool type %q", hit.typ)
	}
	address, err := scan.Uint(ctx, hit.object, typ, field)
	result.address, result.valid = address, err == nil
	return result, err
}

func callbackObjectError(value callbackDecoded, err error) error {
	if err != nil {
		return err
	}
	if value.detail.Error != "" {
		return errors.New(value.detail.Error)
	}
	return nil
}
