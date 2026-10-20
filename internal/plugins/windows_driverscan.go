package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsDriverScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "Start", Kind: "address"},
		{Name: "Size", Kind: "uint64"},
		{Name: "ServiceKey", Kind: "string"},
		{Name: "ServiceKeyError", Kind: "string"},
		{Name: "DriverName", Kind: "string"},
		{Name: "DriverNameError", Kind: "string"},
		{Name: "Name", Kind: "string"},
		{Name: "NameError", Kind: "string"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.driverscan", Upstream: "windows.driverscan.DriverScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan pool headers for DRIVER_OBJECT entries whose start is zero or in kernel space",
		Columns:     columns,
	}, windowsDriverScan}}
}

func windowsDriverScan(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if err := requireDriverFields(e); err != nil {
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
	return scanPoolObjects(ctx, e, constraints, "drivers", driverScanRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		return driverScanHit(ctx, e, found, body.Offset, startField.Offset, kernelStart)
	})
}

func requireDriverFields(e plugin.Environment) error {
	if e.Objects == nil || e.Symbols == nil || e.Kernel == nil {
		return fmt.Errorf("driver scan needs kernel symbols and a kernel layer")
	}
	for _, path := range []string{"DriverStart", "DriverSize", "DriverName", "DriverExtension"} {
		if _, err := e.Objects.Field("_DRIVER_OBJECT", path); err != nil {
			return fmt.Errorf("_DRIVER_OBJECT.%s: %w", path, err)
		}
	}
	if _, err := e.Objects.Field("_DRIVER_EXTENSION", "ServiceKeyName"); err != nil {
		return fmt.Errorf("_DRIVER_EXTENSION.ServiceKeyName: %w", err)
	}
	if _, err := e.Symbol("MmSystemRangeStart"); err != nil {
		return fmt.Errorf("MmSystemRangeStart: %w", err)
	}
	return requireObjectNameFields(e)
}

func driverScanRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsDriverScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func driverObjectValid(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}

func kernelSpaceStart(ctx context.Context, e plugin.Environment) (uint64, error) {
	width := e.Symbols.PointerSize()
	fallback := uint64(0x80000000)
	if width == 8 {
		fallback = 0xFFFF800000000000
	} else if width != 4 {
		return 0, fmt.Errorf("driver scan needs a 4- or 8-byte pointer")
	}
	address, err := e.Symbol("MmSystemRangeStart")
	if err != nil {
		return 0, err
	}
	value, err := readLE(ctx, e.Kernel, address, width)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return fallback, nil
	}
	if width == 4 {
		value &= 0xffffffff
	}
	return value, nil
}

func driverScanHit(ctx context.Context, e plugin.Environment, found poolHit, body, startOffset, kernelStart uint64) (evidence.Row, bool, error) {
	startAt, err := memory.Add(found.object, startOffset)
	if err != nil {
		return evidence.Row{}, false, nil
	}
	if _, err := memory.Read(ctx, found.scan.Layer, startAt, 8); err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		return evidence.Row{}, false, nil
	}
	start, err := found.scan.Uint(ctx, found.object, "_DRIVER_OBJECT", "DriverStart")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		return evidence.Row{}, false, nil
	}
	if start != 0 && start <= kernelStart {
		return evidence.Row{}, false, nil
	}
	size, err := found.scan.Uint(ctx, found.object, "_DRIVER_OBJECT", "DriverSize")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		return evidence.Row{}, false, nil
	}
	driverName, err := driverHeaderName(ctx, e, found, body)
	if err != nil {
		return evidence.Row{}, false, err
	}
	service, err := driverServiceKey(ctx, e, found)
	if err != nil {
		return evidence.Row{}, false, err
	}
	objectName, err := looseObjectString(ctx, e, found.scan, found.object, "_DRIVER_OBJECT", "DriverName")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		objectName = evidence.Missing("name_unavailable", err)
	}
	if !namePresent(driverName) && !namePresent(service) && !namePresent(objectName) {
		return evidence.Row{}, false, nil
	}
	row := driverScanRow(found.layer, found.object)
	row.Cells["Start"] = evidence.Address(start)
	row.Cells["Size"] = evidence.Number(size)
	row.Cells["DriverName"], row.Cells["DriverNameError"] = splitName(driverName)
	row.Cells["ServiceKey"], row.Cells["ServiceKeyError"] = splitName(service)
	row.Cells["Name"], row.Cells["NameError"] = splitName(objectName)
	row.Cells["RecordType"] = evidence.Text("driver")
	return row, true, nil
}

func namePresent(value evidence.Value) bool {
	return value.Kind != "missing"
}

func splitName(value evidence.Value) (evidence.Value, evidence.Value) {
	if value.Kind != "missing" || value.Error == "" {
		return value, evidence.Missing("not_applicable", nil)
	}
	detail := evidence.Value{Kind: "missing", Reason: "unreadable_name", Error: value.Error}
	value.Error = ""
	return value, detail
}

func driverHeaderName(ctx context.Context, e plugin.Environment, found poolHit, body uint64) (evidence.Value, error) {
	if found.object < body {
		return evidence.Missing("name_unavailable", nil), nil
	}
	header := found.object - body
	offset, err := mutantNameInfoOffset(ctx, e, found.scan, header)
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("name_unavailable", err), nil
	}
	if offset == 0 || header < uint64(offset) {
		return evidence.Missing("name_unavailable", nil), nil
	}
	value, err := looseObjectString(ctx, e, found.scan, header-uint64(offset), "_OBJECT_HEADER_NAME_INFO", "Name")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("name_unavailable", err), nil
	}
	return value, nil
}

func driverServiceKey(ctx context.Context, e plugin.Environment, found poolHit) (evidence.Value, error) {
	extension, err := found.scan.Uint(ctx, found.object, "_DRIVER_OBJECT", "DriverExtension")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("name_unavailable", err), nil
	}
	if extension == 0 {
		return evidence.Missing("name_unavailable", nil), nil
	}
	kernel := &object.Reader{Layer: e.Kernel, Symbols: e.Symbols}
	value, err := looseObjectString(ctx, e, kernel, extension, "_DRIVER_EXTENSION", "ServiceKeyName")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("name_unavailable", err), nil
	}
	return value, nil
}

func looseObjectString(ctx context.Context, e plugin.Environment, scan *object.Reader, base uint64, typ, field string) (evidence.Value, error) {
	member, err := scan.Field(typ, field)
	if err != nil {
		return evidence.Value{}, err
	}
	address, err := memory.Add(base, member.Offset)
	if err != nil {
		return evidence.Value{}, err
	}
	length, err := scan.Uint(ctx, address, "_UNICODE_STRING", "Length")
	if err != nil {
		return evidence.Value{}, err
	}
	if length == 0 {
		return evidence.Missing("name_unavailable", nil), nil
	}
	if length > 65534 || length%2 != 0 {
		return evidence.Missing("name_unavailable", nil), nil
	}
	buffer, err := scan.Uint(ctx, address, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return evidence.Value{}, err
	}
	raw, err := memory.Read(ctx, e.Kernel, buffer, int(length))
	if err != nil {
		return evidence.Value{}, err
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	text := string(utf16.Decode(units))
	if index := indexRune(text, 0); index >= 0 {
		text = text[:index]
	}
	if text == "" {
		return evidence.Missing("name_unavailable", nil), nil
	}
	return evidence.Text(text), nil
}

func indexRune(text string, want rune) int {
	for i, r := range text {
		if r == want {
			return i
		}
	}
	return -1
}
