package plugins

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

var driverIRPMajor = []string{
	"IRP_MJ_CREATE",
	"IRP_MJ_CREATE_NAMED_PIPE",
	"IRP_MJ_CLOSE",
	"IRP_MJ_READ",
	"IRP_MJ_WRITE",
	"IRP_MJ_QUERY_INFORMATION",
	"IRP_MJ_SET_INFORMATION",
	"IRP_MJ_QUERY_EA",
	"IRP_MJ_SET_EA",
	"IRP_MJ_FLUSH_BUFFERS",
	"IRP_MJ_QUERY_VOLUME_INFORMATION",
	"IRP_MJ_SET_VOLUME_INFORMATION",
	"IRP_MJ_DIRECTORY_CONTROL",
	"IRP_MJ_FILE_SYSTEM_CONTROL",
	"IRP_MJ_DEVICE_CONTROL",
	"IRP_MJ_INTERNAL_DEVICE_CONTROL",
	"IRP_MJ_SHUTDOWN",
	"IRP_MJ_LOCK_CONTROL",
	"IRP_MJ_CLEANUP",
	"IRP_MJ_CREATE_MAILSLOT",
	"IRP_MJ_QUERY_SECURITY",
	"IRP_MJ_SET_SECURITY",
	"IRP_MJ_POWER",
	"IRP_MJ_SYSTEM_CONTROL",
	"IRP_MJ_DEVICE_CHANGE",
	"IRP_MJ_QUERY_QUOTA",
	"IRP_MJ_SET_QUOTA",
	"IRP_MJ_PNP",
}

func windowsDriverIRPPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.driverirp", Upstream: "windows.driverirp.DriverIrp", Platform: "windows", NeedsKernel: true,
		Description: "List IRP major-function handlers for pool-scanned drivers and the module that contains each handler",
		Columns: []evidence.Column{
			{Name: "Offset", Kind: "address"},
			{Name: "DriverName", Kind: "string"},
			{Name: "DriverNameError", Kind: "string"},
			{Name: "IRP", Kind: "string"},
			{Name: "Address", Kind: "address"},
			{Name: "Module", Kind: "string"},
			{Name: "Symbol", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsDriverIRP}}
}

func windowsDriverIRP(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.driverirp requires a kernel layer and symbols")
	}
	pointer := e.Symbols.PointerSize()
	if pointer != 4 && pointer != 8 {
		return fmt.Errorf("windows.driverirp needs a 4- or 8-byte pointer")
	}
	major, err := e.Objects.Field("_DRIVER_OBJECT", "MajorFunction")
	if err != nil {
		return fmt.Errorf("_DRIVER_OBJECT.MajorFunction: %w", err)
	}
	if major.Type.Kind != "array" || major.Type.Count == 0 || int(major.Type.Count) > len(driverIRPMajor) {
		return fmt.Errorf("invalid _DRIVER_OBJECT.MajorFunction array")
	}
	if _, err := e.Objects.Field("_DRIVER_OBJECT", "DriverStart"); err != nil {
		return fmt.Errorf("_DRIVER_OBJECT.DriverStart: %w", err)
	}
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return fmt.Errorf("_OBJECT_HEADER.Body: %w", err)
	}
	if err := requireObjectNameFields(e); err != nil {
		return err
	}
	constraints, err := builtinPoolConstraints("Dri\xf6", "Driv")
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
	symbolsByAddress := ssdtSymbols(e.Symbols)
	extra := map[string]string{}
	stats := driverIRPStats{}
	note := func() {
		extra["drivers"] = formatCount(uint64(stats.drivers))
		extra["irps"] = formatCount(uint64(stats.rows))
		extra["low_handlers"] = formatCount(uint64(stats.low))
		extra["unreadable_handlers"] = formatCount(uint64(stats.unreadable))
		extra["outside_modules"] = formatCount(uint64(stats.outside))
		extra["symbols_unavailable"] = formatCount(uint64(stats.unavailable))
	}
	note()
	return scanPoolObjectsExtra(ctx, e, constraints, "pool_hits", driverIRPRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		kept, err := driverIRPStartKept(ctx, found, startField.Offset, kernelStart, pointer)
		if err != nil || !kept {
			return evidence.Row{}, false, err
		}
		name, err := executiveHeaderName(ctx, e, found.scan, e.Kernel, found.object, body.Offset)
		if err != nil {
			return evidence.Row{}, false, err
		}
		shown, detail := driverIRPName(name)
		stats.drivers++
		if err := driverIRPObject(ctx, e, found.scan.Layer, found.object, shown, detail, major.Offset, int(major.Type.Count), pointer, kernelStart, modules, symbolsByAddress, &stats, out); err != nil {
			return evidence.Row{}, false, err
		}
		note()
		return evidence.Row{}, false, nil
	}, extra)
}

func driverIRPName(name evidence.Value) (evidence.Value, evidence.Value) {
	if name.Kind != "missing" {
		return name, evidence.Missing("not_applicable", nil)
	}
	detail := name
	if detail.Error != "" {
		detail.Reason = "unreadable_name"
	}
	return evidence.Missing("not_applicable", nil), detail
}

type driverIRPStats struct {
	drivers, rows, low, unreadable, outside, unavailable int
}

func driverIRPObject(ctx context.Context, e plugin.Environment, layer memory.MemoryLayer, object uint64, name, nameError evidence.Value, majorOffset uint64, count, pointer int, kernelStart uint64, modules []kernelModule, symbols map[uint64][]string, stats *driverIRPStats, out plugin.Emit) error {
	for index := 0; index < count; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		slot, err := memory.Add(object, majorOffset+uint64(index*pointer))
		if err != nil {
			return err
		}
		handler, err := readLE(ctx, layer, slot, pointer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			stats.unreadable++
			continue
		}
		// Pointer objects are masked to the layer address width, then the
		// canonical form is what module ranges use. The smear check compares
		// that masked value with the already masked kernel start.
		handler = canonicalPointer(handler, pointer)
		if pointerIdentity(handler, pointer) < kernelStart {
			stats.low++
			continue
		}
		matched := false
		for _, module := range modules {
			if !addressInModule(module.base, module.size, handler) {
				continue
			}
			matched = true
			names := symbols[handler-module.base]
			if len(names) == 0 {
				stats.unavailable++
				stats.rows++
				if err := out(driverIRPRowValue(e, object, name, nameError, driverIRPMajor[index], handler, evidence.Text(module.stem), evidence.Missing("not_available", nil))); err != nil {
					return err
				}
				continue
			}
			for _, symbol := range names {
				stats.rows++
				if err := out(driverIRPRowValue(e, object, name, nameError, driverIRPMajor[index], handler, evidence.Text(module.stem), evidence.Text(symbol))); err != nil {
					return err
				}
			}
		}
		if !matched {
			stats.outside++
			stats.rows++
			if err := out(driverIRPRowValue(e, object, name, nameError, driverIRPMajor[index], handler, evidence.Missing("not_available", nil), evidence.Missing("not_available", nil))); err != nil {
				return err
			}
		}
	}
	return nil
}

func driverIRPRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsDriverIRPPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func driverIRPRowValue(e plugin.Environment, object uint64, name, nameError evidence.Value, irp string, handler uint64, module, symbol evidence.Value) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{
		"Offset":          evidence.Address(object),
		"DriverName":      name,
		"DriverNameError": nameError,
		"IRP":             evidence.Text(irp),
		"Address":         evidence.Address(handler),
		"Module":          module,
		"Symbol":          symbol,
		"RecordType":      evidence.Text("irp"),
		"Coverage":        evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", object)}}
}

// driverIRPStartKept matches DriverScan.scan_drivers after the address mask.
// The eight bytes at DriverStart must be readable. The masked value must be
// zero or strictly above the masked kernel range. Names are not filtered.
func driverIRPStartKept(ctx context.Context, found poolHit, startOffset, kernelStart uint64, pointer int) (bool, error) {
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
	if masked := pointerIdentity(start, pointer); masked != 0 && masked <= kernelStart {
		return false, nil
	}
	return true, nil
}

// maskKernelStart matches IntelLayer.address_mask. Volatility returns
// MmSystemRangeStart with that mask, and pointer values are masked the same
// way before the IRP smear check.
func maskKernelStart(value uint64, pointer int) uint64 {
	if pointer == 8 {
		return value & 0x0000ffffffffffff
	}
	return value & 0xffffffff
}
