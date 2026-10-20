package plugins

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsUnloadedModulePlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Name", Kind: "string"},
		{Name: "StartAddress", Kind: "address"},
		{Name: "EndAddress", Kind: "address"},
		{Name: "Time", Kind: "string"},
		{Name: "TimeRaw", Kind: "uint64"},
		{Name: "StartRaw", Kind: "address"},
		{Name: "EndRaw", Kind: "address"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.unloadedmodules", Upstream: "windows.unloadedmodules.UnloadedModules", Platform: "windows", NeedsKernel: true,
		Description: "List unloaded kernel modules from MmUnloadedDrivers using the pinned 1024-entry cap and address checks",
		Columns:     columns,
	}, windowsUnloadedModules}}
}

func windowsUnloadedModules(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Objects == nil || e.Symbols == nil || e.Kernel == nil {
		return fmt.Errorf("windows.unloadedmodules needs kernel symbols and a kernel layer")
	}
	if _, err := e.Objects.Field("_UNICODE_STRING", "Length"); err != nil {
		return fmt.Errorf("_UNICODE_STRING.Length: %w", err)
	}
	if _, err := e.Objects.Field("_UNICODE_STRING", "Buffer"); err != nil {
		return fmt.Errorf("_UNICODE_STRING.Buffer: %w", err)
	}
	tableSymbol, err := e.Symbol("MmUnloadedDrivers")
	if err != nil {
		return fmt.Errorf("MmUnloadedDrivers: %w", err)
	}
	countSymbol, err := e.Symbol("MmLastUnloadedDriver")
	if err != nil {
		return fmt.Errorf("MmLastUnloadedDriver: %w", err)
	}
	layout, err := unloadedModuleLayout(e.Symbols.PointerSize())
	if err != nil {
		return err
	}
	table, err := readLE(ctx, e.Kernel, tableSymbol, layout.pointer)
	if err != nil {
		return fmt.Errorf("MmUnloadedDrivers: %w", err)
	}
	rawCount, err := readLE(ctx, e.Kernel, countSymbol, layout.count)
	if err != nil {
		return fmt.Errorf("MmLastUnloadedDriver: %w", err)
	}
	count := rawCount
	capped := false
	if count > 1024 {
		count = 1024
		capped = true
	}
	kernelStart, err := kernelSpaceStart(ctx, e)
	if err != nil {
		return err
	}
	kernelStart &= layout.mask
	var hits, skipped, unreadable int
	for index := uint64(0); index < count; index++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		entry, err := memory.Add(table, index*layout.stride)
		if err != nil {
			return err
		}
		startRaw, endRaw, stamp, name, ok, err := readUnloadedModule(ctx, e, entry, layout)
		if err != nil {
			return err
		}
		if !ok {
			unreadable++
			continue
		}
		start, end := startRaw&layout.mask, endRaw&layout.mask
		if !(stamp > 1024 && start > kernelStart && start&0xfff == 0 && end&0xfff == 0 && end > kernelStart) {
			skipped++
			continue
		}
		row := unloadedModuleRow(e, entry)
		row.Cells["Name"] = name
		row.Cells["StartAddress"] = evidence.Address(startRaw)
		row.Cells["EndAddress"] = evidence.Address(endRaw)
		row.Cells["StartRaw"] = evidence.Address(startRaw)
		row.Cells["EndRaw"] = evidence.Address(endRaw)
		row.Cells["Time"], row.Cells["TimeRaw"] = unloadedModuleTime(stamp)
		row.Cells["RecordType"] = evidence.Text("module")
		hits++
		if err = out(row); err != nil {
			return err
		}
	}
	summary := unloadedModuleRow(e, table)
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"count":        strconv.FormatUint(rawCount, 10),
		"visited":      strconv.FormatUint(count, 10),
		"capped":       strconv.FormatBool(capped),
		"hits":         strconv.Itoa(hits),
		"skipped":      strconv.Itoa(skipped),
		"unreadable":   strconv.Itoa(unreadable),
		"kernel_space": fmt.Sprintf("0x%x", kernelStart),
		"address_mask": fmt.Sprintf("0x%x", layout.mask),
	}}
	return out(summary)
}

type unloadedLayout struct {
	pointer, count   int
	stride           uint64
	start, end, when uint64
	mask             uint64
}

func unloadedModuleLayout(pointer int) (unloadedLayout, error) {
	switch pointer {
	case 8:
		return unloadedLayout{pointer: 8, count: 8, stride: 40, start: 16, end: 24, when: 32, mask: 0x0000ffffffffffff}, nil
	case 4:
		return unloadedLayout{pointer: 4, count: 4, stride: 24, start: 8, end: 12, when: 16, mask: 0xffffffff}, nil
	default:
		return unloadedLayout{}, fmt.Errorf("windows.unloadedmodules needs a 4- or 8-byte pointer")
	}
}

func readUnloadedModule(ctx context.Context, e plugin.Environment, entry uint64, layout unloadedLayout) (start, end, stamp uint64, name evidence.Value, ok bool, err error) {
	startAt, err := memory.Add(entry, layout.start)
	if err != nil {
		return 0, 0, 0, evidence.Value{}, false, err
	}
	endAt, err := memory.Add(entry, layout.end)
	if err != nil {
		return 0, 0, 0, evidence.Value{}, false, err
	}
	timeAt, err := memory.Add(entry, layout.when)
	if err != nil {
		return 0, 0, 0, evidence.Value{}, false, err
	}
	start, err = readLE(ctx, e.Kernel, startAt, layout.pointer)
	if err != nil {
		return droppedUnloaded(ctx, err)
	}
	end, err = readLE(ctx, e.Kernel, endAt, layout.pointer)
	if err != nil {
		return droppedUnloaded(ctx, err)
	}
	stamp, err = readLE(ctx, e.Kernel, timeAt, 8)
	if err != nil {
		return droppedUnloaded(ctx, err)
	}
	name, err = unloadedModuleName(ctx, e, entry)
	if err != nil {
		return droppedUnloaded(ctx, err)
	}
	return start, end, stamp, name, true, nil
}

func droppedUnloaded(ctx context.Context, err error) (uint64, uint64, uint64, evidence.Value, bool, error) {
	if ctx.Err() != nil {
		return 0, 0, 0, evidence.Value{}, false, ctx.Err()
	}
	return 0, 0, 0, evidence.Value{}, false, nil
}

func unloadedModuleName(ctx context.Context, e plugin.Environment, entry uint64) (evidence.Value, error) {
	length, err := e.Objects.Uint(ctx, entry, "_UNICODE_STRING", "Length")
	if err != nil {
		return evidence.Value{}, err
	}
	buffer, err := e.Objects.Uint(ctx, entry, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return evidence.Value{}, err
	}
	if length == 0 {
		return evidence.Text(""), nil
	}
	if length > uint64(memory.MaxRead) {
		return evidence.Value{}, fmt.Errorf("unloaded module name is %d bytes", length)
	}
	raw, err := memory.Read(ctx, e.Kernel, buffer, int(length))
	if err != nil {
		return evidence.Value{}, err
	}
	return evidence.Text(poolUTF16(raw)), nil
}

func unloadedModuleTime(stamp uint64) (evidence.Value, evidence.Value) {
	raw := evidence.Number(stamp)
	if stamp > math.MaxInt64 {
		return evidence.Missing("unparsable_filetime", nil), raw
	}
	ticks := int64(stamp)
	when, ok := volatilityFiletime(ticks)
	if !ok {
		reason := "unparsable_filetime"
		if floorDivInt64(ticks, 10000000) == 0 {
			reason = "not_set"
		}
		return evidence.Missing(reason, nil), raw
	}
	return evidence.Text(when.Format("2006-01-02T15:04:05Z07:00")), raw
}

func unloadedModuleRow(e plugin.Environment, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsUnloadedModulePlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	return row
}
