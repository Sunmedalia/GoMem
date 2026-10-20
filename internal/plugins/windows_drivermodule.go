package plugins

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsDriverModulePlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.drivermodule", Upstream: "windows.malware.drivermodule.DriverModule", Platform: "windows", NeedsKernel: true,
		Description: "List pool-scanned drivers whose start address is not inside a loaded kernel module",
		Columns: []evidence.Column{
			{Name: "Offset", Kind: "address"},
			{Name: "KnownException", Kind: "bool"},
			{Name: "DriverName", Kind: "string"},
			{Name: "DriverNameError", Kind: "string"},
			{Name: "ServiceKey", Kind: "string"},
			{Name: "ServiceKeyError", Kind: "string"},
			{Name: "Name", Kind: "string"},
			{Name: "NameError", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsDriverModule}}
}

func windowsDriverModule(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if err := requireDriverFields(e); err != nil {
		return err
	}
	pointer := e.Symbols.PointerSize()
	if pointer != 4 && pointer != 8 {
		return fmt.Errorf("windows.drivermodule needs a 4- or 8-byte pointer")
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
	kernelStart = maskKernelStart(kernelStart, pointer)
	modules, err := windowsKernelModules(ctx, e)
	if err != nil {
		return err
	}
	extra := map[string]string{}
	stats := driverModuleStats{}
	note := func() {
		extra["passed_start"] = formatCount(uint64(stats.passed))
		extra["in_module"] = formatCount(uint64(stats.inModule))
		extra["unnamed"] = formatCount(uint64(stats.unnamed))
		extra["hidden"] = formatCount(uint64(stats.hidden))
		extra["known_exceptions"] = formatCount(uint64(stats.known))
		extra["skipped_start"] = formatCount(uint64(stats.skippedStart))
	}
	note()
	return scanPoolObjectsExtra(ctx, e, constraints, "pool_hits", driverModuleRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		kept, err := driverIRPStartKept(ctx, found, startField.Offset, kernelStart, pointer)
		if err != nil || !kept {
			if err == nil {
				stats.skippedStart++
				note()
			}
			return evidence.Row{}, false, err
		}
		start, err := found.scan.Uint(ctx, found.object, "_DRIVER_OBJECT", "DriverStart")
		if err != nil {
			if ctx.Err() != nil {
				return evidence.Row{}, false, ctx.Err()
			}
			stats.skippedStart++
			note()
			return evidence.Row{}, false, nil
		}
		stats.passed++
		header, err := driverHeaderName(ctx, e, found, body.Offset)
		if err != nil {
			return evidence.Row{}, false, err
		}
		service, err := driverServiceKey(ctx, e, found)
		if err != nil {
			return evidence.Row{}, false, err
		}
		alt, err := looseObjectString(ctx, e, found.scan, found.object, "_DRIVER_OBJECT", "DriverName")
		if err != nil {
			if ctx.Err() != nil {
				return evidence.Row{}, false, ctx.Err()
			}
			alt = evidence.Missing("name_unavailable", err)
		}
		emit, known, why := driverModuleDecide(start, pointer, kernelStart, modules, header, service, alt)
		switch why {
		case "in_module":
			stats.inModule++
		case "unnamed":
			stats.unnamed++
		}
		note()
		if !emit {
			return evidence.Row{}, false, nil
		}
		stats.hidden++
		if known {
			stats.known++
		}
		note()
		row := driverModuleRow(found.layer, found.object)
		row.Cells["KnownException"] = evidence.Value{Kind: "bool", Data: known}
		row.Cells["DriverName"], row.Cells["DriverNameError"] = splitName(header)
		row.Cells["ServiceKey"], row.Cells["ServiceKeyError"] = splitName(service)
		row.Cells["Name"], row.Cells["NameError"] = splitName(alt)
		row.Cells["RecordType"] = evidence.Text("driver")
		return row, true, nil
	}, extra)
}

type driverModuleStats struct {
	passed, inModule, unnamed, hidden, known, skippedStart int
}

// driverModuleDecide matches the pinned generator after scan_drivers. A start
// of zero is kept. Any other masked start at or below the masked kernel range
// was already rejected. A start inside any loaded module is a normal driver.
// Rows with no usable name are omitted. Known exceptions compare only the
// object-header driver name.
func driverModuleDecide(start uint64, pointer int, kernelStart uint64, modules []kernelModule, header, service, alt evidence.Value) (emit bool, known bool, why string) {
	canon := canonicalPointer(start, pointer)
	masked := pointerIdentity(canon, pointer)
	if masked != 0 && masked <= kernelStart {
		return false, false, "smear"
	}
	for _, module := range modules {
		if addressInModule(module.base, module.size, canon) {
			return false, false, "in_module"
		}
	}
	if !namePresent(header) && !namePresent(service) && !namePresent(alt) {
		return false, false, "unnamed"
	}
	if header.Kind != "missing" && knownDriverModuleName(header.String()) {
		known = true
	}
	return true, known, "hidden"
}

func knownDriverModuleName(name string) bool {
	switch name {
	case "ACPI_HAL", "PnpManager", "RAW", "WMIxWDM", "Win32k", "Fs_Rec":
		return true
	default:
		return false
	}
}

func driverModuleRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsDriverModulePlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}
