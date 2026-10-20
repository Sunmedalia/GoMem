package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

const (
	devicePointerValue = iota
	devicePointerUnread
	devicePointerNull
)

func windowsDeviceTreePlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.devicetree", Upstream: "windows.devicetree.DeviceTree", Platform: "windows", NeedsKernel: true,
		Description: "List each pool-scanned driver and the devices and attached devices linked from it",
		Columns: []evidence.Column{
			{Name: "Offset", Kind: "address"},
			{Name: "Type", Kind: "string"},
			{Name: "DriverName", Kind: "string"},
			{Name: "DeviceName", Kind: "string"},
			{Name: "DriverNameOfAttDevice", Kind: "string"},
			{Name: "DeviceType", Kind: "string"},
			{Name: "Depth", Kind: "uint64"},
			{Name: "ObjectOffset", Kind: "address"},
			{Name: "DriverNameError", Kind: "string"},
			{Name: "DeviceNameError", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsDeviceTree}}
}

func windowsDeviceTree(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if err := requireDeviceTreeFields(e); err != nil {
		return err
	}
	constraints, err := builtinPoolConstraints("Dri\xf6", "Driv")
	if err != nil {
		return err
	}
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return err
	}
	startField, err := e.Objects.Field("_DRIVER_OBJECT", "DriverStart")
	if err != nil {
		return err
	}
	kernelStart, err := kernelSpaceStart(ctx, e)
	if err != nil {
		return err
	}
	kernel := &object.Reader{Layer: e.Kernel, Symbols: e.Symbols}
	extra := map[string]string{"devices": "0", "attached": "0", "stopped_drivers": "0"}
	var pending []evidence.Row
	var token, devices, attached, stopped int
	flush := func(row evidence.Row) error {
		if err := out(row); err != nil {
			return err
		}
		children := pending
		pending = nil
		for _, child := range children {
			if err := out(child); err != nil {
				return err
			}
		}
		return nil
	}
	note := func() {
		extra["devices"] = strconv.Itoa(devices)
		extra["attached"] = strconv.Itoa(attached)
		extra["stopped_drivers"] = strconv.Itoa(stopped)
	}
	return scanPoolObjectsExtra(ctx, e, constraints, "drivers", deviceTreeRow, flush, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		kept, err := driverStartKept(ctx, found, startField.Offset, kernelStart)
		if err != nil || !kept {
			return evidence.Row{}, false, err
		}
		rows, aborted, err := deviceTreeRows(ctx, e, found, kernel, body.Offset, &token)
		if err != nil || len(rows) == 0 {
			return evidence.Row{}, false, err
		}
		for _, row := range rows {
			switch row.Cells["RecordType"].String() {
			case "device":
				devices++
			case "attached":
				attached++
			}
		}
		if aborted {
			stopped++
		}
		note()
		pending = rows[1:]
		return rows[0], true, nil
	}, extra)
}

func requireDeviceTreeFields(e plugin.Environment) error {
	if e.Objects == nil || e.Symbols == nil || e.Kernel == nil {
		return fmt.Errorf("device tree needs kernel symbols and a kernel layer")
	}
	for _, path := range []string{"DriverStart", "DriverName", "DeviceObject"} {
		if _, err := e.Objects.Field("_DRIVER_OBJECT", path); err != nil {
			return fmt.Errorf("_DRIVER_OBJECT.%s: %w", path, err)
		}
	}
	for _, path := range []string{"DeviceType", "NextDevice", "AttachedDevice", "DriverObject"} {
		if _, err := e.Objects.Field("_DEVICE_OBJECT", path); err != nil {
			return fmt.Errorf("_DEVICE_OBJECT.%s: %w", path, err)
		}
	}
	if _, err := e.Symbol("MmSystemRangeStart"); err != nil {
		return fmt.Errorf("MmSystemRangeStart: %w", err)
	}
	return requireObjectNameFields(e)
}

// driverStartKept matches DriverScan.scan_drivers. The eight bytes at
// DriverStart must be readable, and the value must be zero or strictly above
// the kernel range. Names are not filtered.
func driverStartKept(ctx context.Context, found poolHit, startOffset, kernelStart uint64) (bool, error) {
	startAt, err := memory.Add(found.object, startOffset)
	if err != nil {
		return false, nil
	}
	if _, err = memory.Read(ctx, found.scan.Layer, startAt, 8); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	start, err := found.scan.Uint(ctx, found.object, "_DRIVER_OBJECT", "DriverStart")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	if start != 0 && start <= kernelStart {
		return false, nil
	}
	return true, nil
}

func deviceTreeRows(ctx context.Context, e plugin.Environment, found poolHit, kernel *object.Reader, body uint64, token *int) ([]evidence.Row, bool, error) {
	driverName, err := executiveHeaderName(ctx, e, found.scan, e.Kernel, found.object, body)
	if err != nil {
		return nil, false, err
	}
	name, nameErr := splitUnparsable(driverName)
	driverID := nextEvidenceToken(token)
	rows := []evidence.Row{deviceTreeNode(found.layer, found.object, found.object, "DRV", "driver", 0, driverID, "", name, nameErr, evidence.Missing("not_applicable", nil), evidence.Missing("not_applicable", nil), evidence.Missing("not_applicable", nil), evidence.Missing("not_applicable", nil))}
	devices, devKind, err := collectDeviceChain(ctx, found.scan, found.object, "_DRIVER_OBJECT", "DeviceObject", kernel, "_DEVICE_OBJECT", "NextDevice")
	if err != nil {
		return nil, false, err
	}
	aborted := devKind == devicePointerNull
	for _, device := range devices {
		if err = ctx.Err(); err != nil {
			return nil, false, err
		}
		deviceName, err := executiveHeaderName(ctx, e, kernel, e.Kernel, device, body)
		if err != nil {
			return nil, false, err
		}
		devType, err := kernel.Uint(ctx, device, "_DEVICE_OBJECT", "DeviceType")
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, object.ErrFieldAbsent) {
				return nil, false, err
			}
			return rows, true, nil
		}
		shown, shownErr := splitUnparsable(deviceName)
		deviceID := nextEvidenceToken(token)
		rows = append(rows, deviceTreeNode(found.layer, found.object, device, "DEV", "device", 1, deviceID, driverID, name, nameErr, shown, shownErr, evidence.Missing("not_applicable", nil), evidence.Text(deviceTypeName(devType))))
		attached, attKind, err := collectDeviceChain(ctx, kernel, device, "_DEVICE_OBJECT", "AttachedDevice", kernel, "_DEVICE_OBJECT", "AttachedDevice")
		if err != nil {
			return nil, false, err
		}
		parent := deviceID
		for depth, att := range attached {
			attName, err := executiveHeaderName(ctx, e, kernel, e.Kernel, att, body)
			if err != nil {
				return nil, false, err
			}
			driverPtr, driverKind, err := objectPointer(ctx, kernel, att, "_DEVICE_OBJECT", "DriverObject")
			if err != nil {
				return nil, false, err
			}
			if driverKind != devicePointerValue {
				return rows, true, nil
			}
			attachedDriver, err := volatilityObjectString(ctx, e.Kernel, kernel, driverPtr, "_DRIVER_OBJECT", "DriverName")
			if err != nil {
				if ctx.Err() != nil {
					return nil, false, ctx.Err()
				}
				return rows, true, nil
			}
			attType, err := kernel.Uint(ctx, att, "_DEVICE_OBJECT", "DeviceType")
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, object.ErrFieldAbsent) {
					return nil, false, err
				}
				return rows, true, nil
			}
			shown, shownErr = splitUnparsable(attName)
			attID := nextEvidenceToken(token)
			rows = append(rows, deviceTreeNode(found.layer, found.object, att, "ATT", "attached", depth+2, attID, parent, name, nameErr, shown, shownErr, attachedDriver, evidence.Text(deviceTypeName(attType))))
			parent = attID
		}
		if attKind == devicePointerNull {
			return rows, true, nil
		}
	}
	return rows, aborted, nil
}

// collectDeviceChain walks DeviceObject/NextDevice or AttachedDevice. A repeated
// address or an unreadable pointer ends that chain. A null pointer is kept as
// devicePointerNull so the caller can stop the rest of the driver: the pinned
// generator instantiates address 0 and then raises InvalidAddressException.
func collectDeviceChain(ctx context.Context, first *object.Reader, firstBase uint64, firstType, firstField string, next *object.Reader, nextType, nextField string) ([]uint64, int, error) {
	addr, kind, err := objectPointer(ctx, first, firstBase, firstType, firstField)
	if err != nil || kind != devicePointerValue {
		return nil, kind, err
	}
	width := next.Symbols.PointerSize()
	seen := map[uint64]bool{}
	var chain []uint64
	for {
		id := pointerIdentity(addr, width)
		if seen[id] {
			return chain, devicePointerUnread, nil
		}
		seen[id] = true
		chain = append(chain, addr)
		addr, kind, err = objectPointer(ctx, next, addr, nextType, nextField)
		if err != nil || kind != devicePointerValue {
			return chain, kind, err
		}
	}
}

func objectPointer(ctx context.Context, reader *object.Reader, base uint64, typ, field string) (uint64, int, error) {
	value, err := reader.Uint(ctx, base, typ, field)
	if err != nil {
		if ctx.Err() != nil {
			return 0, 0, ctx.Err()
		}
		if errors.Is(err, object.ErrFieldAbsent) {
			return 0, 0, err
		}
		return 0, devicePointerUnread, nil
	}
	value = canonicalPointer(value, reader.Symbols.PointerSize())
	if value == 0 {
		return 0, devicePointerNull, nil
	}
	return value, devicePointerValue, nil
}

func canonicalPointer(value uint64, width int) uint64 {
	if width == 4 {
		return value & 0xffffffff
	}
	value &= 0x0000ffffffffffff
	if value&(uint64(1)<<47) != 0 {
		value |= 0xffff000000000000
	}
	return value
}

func pointerIdentity(value uint64, width int) uint64 {
	if width == 4 {
		return value & 0xffffffff
	}
	return value & 0x0000ffffffffffff
}

func executiveHeaderName(ctx context.Context, e plugin.Environment, reader *object.Reader, kernel memory.MemoryLayer, object, body uint64) (evidence.Value, error) {
	if object < body {
		return evidence.Missing("unparsable", nil), nil
	}
	header := object - body
	offset, err := mutantNameInfoOffset(ctx, e, reader, header)
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("unparsable", err), nil
	}
	if offset == 0 || header < uint64(offset) {
		return evidence.Missing("unparsable", nil), nil
	}
	value, err := volatilityObjectString(ctx, kernel, reader, header-uint64(offset), "_OBJECT_HEADER_NAME_INFO", "Name")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("unparsable", err), nil
	}
	return value, nil
}

func splitUnparsable(value evidence.Value) (evidence.Value, evidence.Value) {
	if value.Kind != "missing" || value.Error == "" {
		return value, evidence.Missing("not_applicable", nil)
	}
	detail := evidence.Value{Kind: "missing", Reason: "unreadable_name", Error: value.Error}
	value.Error = ""
	return value, detail
}

func deviceTreeNode(layer string, driver, object uint64, kind, record string, depth int, id, parent string, driverName, driverErr, deviceName, deviceErr, attachedDriver, deviceType evidence.Value) evidence.Row {
	row := deviceTreeRow(layer, object)
	row.ID = id
	row.ParentID = parent
	row.Cells["Offset"] = evidence.Address(driver)
	row.Cells["ObjectOffset"] = evidence.Address(object)
	row.Cells["Type"] = evidence.Text(kind)
	row.Cells["RecordType"] = evidence.Text(record)
	row.Cells["Depth"] = evidence.Number(uint64(depth))
	row.Cells["DriverName"] = driverName
	row.Cells["DriverNameError"] = driverErr
	row.Cells["DeviceName"] = deviceName
	row.Cells["DeviceNameError"] = deviceErr
	row.Cells["DriverNameOfAttDevice"] = attachedDriver
	row.Cells["DeviceType"] = deviceType
	return row
}

func deviceTreeRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsDeviceTreePlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func nextEvidenceToken(token *int) string {
	id := strconv.Itoa(*token)
	*token++
	return id
}

func deviceTypeName(code uint64) string {
	if name, ok := deviceTypeCodes[code]; ok {
		return name
	}
	return "UNKNOWN"
}

// deviceTypeCodes is the pinned DEVICE_CODES table. Values outside it are UNKNOWN.
var deviceTypeCodes = map[uint64]string{
	0x00000001: "FILE_DEVICE_BEEP",
	0x00000002: "FILE_DEVICE_CD_ROM",
	0x00000003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
	0x00000004: "FILE_DEVICE_CONTROLLER",
	0x00000005: "FILE_DEVICE_DATALINK",
	0x00000006: "FILE_DEVICE_DFS",
	0x00000007: "FILE_DEVICE_DISK",
	0x00000008: "FILE_DEVICE_DISK_FILE_SYSTEM",
	0x00000009: "FILE_DEVICE_FILE_SYSTEM",
	0x0000000A: "FILE_DEVICE_INPORT_PORT",
	0x0000000B: "FILE_DEVICE_KEYBOARD",
	0x0000000C: "FILE_DEVICE_MAILSLOT",
	0x0000000D: "FILE_DEVICE_MIDI_IN",
	0x0000000E: "FILE_DEVICE_MIDI_OUT",
	0x0000000F: "FILE_DEVICE_MOUSE",
	0x00000010: "FILE_DEVICE_MULTI_UNC_PROVIDER",
	0x00000011: "FILE_DEVICE_NAMED_PIPE",
	0x00000012: "FILE_DEVICE_NETWORK",
	0x00000013: "FILE_DEVICE_NETWORK_BROWSER",
	0x00000014: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
	0x00000015: "FILE_DEVICE_NULL",
	0x00000016: "FILE_DEVICE_PARALLEL_PORT",
	0x00000017: "FILE_DEVICE_PHYSICAL_NETCARD",
	0x00000018: "FILE_DEVICE_PRINTER",
	0x00000019: "FILE_DEVICE_SCANNER",
	0x0000001A: "FILE_DEVICE_SERIAL_MOUSE_PORT",
	0x0000001B: "FILE_DEVICE_SERIAL_PORT",
	0x0000001C: "FILE_DEVICE_SCREEN",
	0x0000001D: "FILE_DEVICE_SOUND",
	0x0000001E: "FILE_DEVICE_STREAMS",
	0x0000001F: "FILE_DEVICE_TAPE",
	0x00000020: "FILE_DEVICE_TAPE_FILE_SYSTEM",
	0x00000021: "FILE_DEVICE_TRANSPORT",
	0x00000022: "FILE_DEVICE_UNKNOWN",
	0x00000023: "FILE_DEVICE_VIDEO",
	0x00000024: "FILE_DEVICE_VIRTUAL_DISK",
	0x00000025: "FILE_DEVICE_WAVE_IN",
	0x00000026: "FILE_DEVICE_WAVE_OUT",
	0x00000027: "FILE_DEVICE_8042_PORT",
	0x00000028: "FILE_DEVICE_NETWORK_REDIRECTOR",
	0x00000029: "FILE_DEVICE_BATTERY",
	0x0000002A: "FILE_DEVICE_BUS_EXTENDER",
	0x0000002B: "FILE_DEVICE_MODEM",
	0x0000002C: "FILE_DEVICE_VDM",
	0x0000002D: "FILE_DEVICE_MASS_STORAGE",
	0x0000002E: "FILE_DEVICE_SMB",
	0x0000002F: "FILE_DEVICE_KS",
	0x00000030: "FILE_DEVICE_CHANGER",
	0x00000031: "FILE_DEVICE_SMARTCARD",
	0x00000032: "FILE_DEVICE_ACPI",
	0x00000033: "FILE_DEVICE_DVD",
	0x00000034: "FILE_DEVICE_FULLSCREEN_VIDEO",
	0x00000035: "FILE_DEVICE_DFS_FILE_SYSTEM",
	0x00000036: "FILE_DEVICE_DFS_VOLUME",
	0x00000037: "FILE_DEVICE_SERENUM",
	0x00000038: "FILE_DEVICE_TERMSRV",
	0x00000039: "FILE_DEVICE_KSEC",
	0x0000003A: "FILE_DEVICE_FIPS",
}
