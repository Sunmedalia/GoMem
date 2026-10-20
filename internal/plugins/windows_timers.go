package plugins

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsTimerPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.timers", Upstream: "windows.timers.Timers", Platform: "windows", NeedsKernel: true,
		Description: "List kernel timers whose DPC routine can be read, with the module and symbol at that address",
		Columns: []evidence.Column{
			{Name: "Offset", Kind: "address"},
			{Name: "DueTime", Kind: "string"},
			{Name: "Period", Kind: "uint64"},
			{Name: "Signaled", Kind: "string"},
			{Name: "Routine", Kind: "address"},
			{Name: "Module", Kind: "string"},
			{Name: "Symbol", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsTimers}}
}

type timerLayout struct {
	pointer                        int
	listOff, flink                 uint64
	typeAt, signalAt               uint64
	dueAt, highAt, lowAt, periodAt uint64
	dpcAt, routineAt               uint64
	encoded                        bool
	waitNever, waitAlways          uint64
}

type timerStats struct {
	examined, invalidType, skippedDPC, outside, unavailable, rows int
}

func windowsTimers(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.timers requires a kernel layer and symbols")
	}
	pointer := e.Symbols.PointerSize()
	if pointer != 4 && pointer != 8 {
		return fmt.Errorf("windows.timers needs a 4- or 8-byte pointer")
	}
	layout, err := timerReadLayout(e, pointer)
	if err != nil {
		return err
	}
	modules, err := windowsKernelModules(ctx, e)
	if err != nil {
		return err
	}
	byAddress := ssdtSymbols(e.Symbols)
	var heads []uint64
	if timerUsesProcessorTable(e.Symbols) {
		heads, err = timerProcessorHeads(ctx, e)
	} else if _, lookupErr := e.Symbol("KiTimerTableListHead"); lookupErr == nil {
		heads, err = timerLegacyHeads(ctx, e)
	} else {
		return fmt.Errorf("windows.timers does not support this kernel")
	}
	if err != nil {
		return err
	}
	stats := timerStats{}
	for _, head := range heads {
		if err = ctx.Err(); err != nil {
			return err
		}
		err = walkTimerList(ctx, e, head, layout, func(object uint64) error {
			return emitTimer(ctx, e, object, layout, modules, byAddress, &stats, out)
		})
		if err != nil {
			return err
		}
	}
	coverage := map[string]string{
		"lists":               formatCount(uint64(len(heads))),
		"examined":            formatCount(uint64(stats.examined)),
		"invalid_type":        formatCount(uint64(stats.invalidType)),
		"skipped_dpc":         formatCount(uint64(stats.skippedDPC)),
		"rows":                formatCount(uint64(stats.rows)),
		"outside_modules":     formatCount(uint64(stats.outside)),
		"symbols_unavailable": formatCount(uint64(stats.unavailable)),
		"encoded_dpc":         yesNo(layout.encoded),
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{
		"Offset": evidence.Missing("not_applicable", nil), "DueTime": evidence.Missing("not_applicable", nil),
		"Period": evidence.Missing("not_applicable", nil), "Signaled": evidence.Missing("not_applicable", nil),
		"Routine": evidence.Missing("not_applicable", nil), "Module": evidence.Missing("not_applicable", nil),
		"Symbol": evidence.Missing("not_applicable", nil), "RecordType": evidence.Text("summary"),
		"Coverage": poolCoverage(coverage),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}})
}

func timerReadLayout(e plugin.Environment, pointer int) (timerLayout, error) {
	listOff, err := e.Objects.Field("_KTIMER", "TimerListEntry")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_KTIMER.TimerListEntry: %w", err)
	}
	header, err := e.Objects.Field("_KTIMER", "Header")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_KTIMER.Header: %w", err)
	}
	typeField, err := e.Objects.Field("_DISPATCHER_HEADER", "Type")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_DISPATCHER_HEADER.Type: %w", err)
	}
	signalField, err := e.Objects.Field("_DISPATCHER_HEADER", "SignalState")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_DISPATCHER_HEADER.SignalState: %w", err)
	}
	dueField, err := e.Objects.Field("_KTIMER", "DueTime")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_KTIMER.DueTime: %w", err)
	}
	highField, err := e.Objects.Field("_ULARGE_INTEGER", "HighPart")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_ULARGE_INTEGER.HighPart: %w", err)
	}
	lowField, err := e.Objects.Field("_ULARGE_INTEGER", "LowPart")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_ULARGE_INTEGER.LowPart: %w", err)
	}
	periodField, err := e.Objects.Field("_KTIMER", "Period")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_KTIMER.Period: %w", err)
	}
	dpcField, err := e.Objects.Field("_KTIMER", "Dpc")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_KTIMER.Dpc: %w", err)
	}
	routineField, err := e.Objects.Field("_KDPC", "DeferredRoutine")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_KDPC.DeferredRoutine: %w", err)
	}
	flink, err := e.Objects.Field("_LIST_ENTRY", "Flink")
	if err != nil {
		return timerLayout{}, fmt.Errorf("_LIST_ENTRY.Flink: %w", err)
	}
	layout := timerLayout{
		pointer: pointer, listOff: listOff.Offset, flink: flink.Offset,
		typeAt: header.Offset + typeField.Offset, signalAt: header.Offset + signalField.Offset,
		dueAt: dueField.Offset, highAt: highField.Offset, lowAt: lowField.Offset, periodAt: periodField.Offset,
		dpcAt: dpcField.Offset, routineAt: routineField.Offset,
	}
	neverAddr, neverErr := e.Symbol("KiWaitNever")
	alwaysAddr, alwaysErr := e.Symbol("KiWaitAlways")
	layout.encoded = neverErr == nil && alwaysErr == nil
	if layout.encoded {
		layout.waitNever = neverAddr
		layout.waitAlways = alwaysAddr
	}
	return layout, nil
}

func emitTimer(ctx context.Context, e plugin.Environment, object uint64, layout timerLayout, modules []kernelModule, symbols map[uint64][]string, stats *timerStats, out plugin.Emit) error {
	stats.examined++
	kind, err := readLE(ctx, e.Kernel, object+layout.typeAt, 1)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("timer type at %#x: %w", object, err)
	}
	if kind != 8 && kind != 9 {
		stats.invalidType++
		return nil
	}
	routine, ok, err := timerRoutine(ctx, e, object, layout)
	if err != nil {
		return err
	}
	if !ok {
		stats.skippedDPC++
		return nil
	}
	due, period, signaled, err := timerFields(ctx, e, object, layout)
	if err != nil {
		return err
	}
	canon := canonicalPointer(routine, layout.pointer)
	found := false
	for _, module := range modules {
		if !addressInModule(module.base, module.size, canon) {
			continue
		}
		found = true
		names := symbols[canon-module.base]
		moduleCell := evidence.Text(module.stem)
		if len(names) == 0 {
			stats.unavailable++
			stats.rows++
			if err = out(timerEvidence(e, object, due, period, signaled, canon, moduleCell, evidence.Missing("not_available", nil))); err != nil {
				return err
			}
			continue
		}
		for _, name := range names {
			stats.rows++
			if err = out(timerEvidence(e, object, due, period, signaled, canon, moduleCell, evidence.Text(name))); err != nil {
				return err
			}
		}
	}
	if !found {
		stats.outside++
		stats.rows++
		return out(timerEvidence(e, object, due, period, signaled, canon, evidence.Missing("not_available", nil), evidence.Missing("not_available", nil)))
	}
	return nil
}

func timerEvidence(e plugin.Environment, object uint64, due string, period uint64, signaled string, routine uint64, module, symbol evidence.Value) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{
		"Offset": evidence.Address(object), "DueTime": evidence.Text(due), "Period": evidence.Number(period),
		"Signaled": evidence.Text(signaled), "Routine": evidence.Address(routine), "Module": module, "Symbol": symbol,
		"RecordType": evidence.Text("timer"), "Coverage": evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", object)}}
}

func timerFields(ctx context.Context, e plugin.Environment, object uint64, layout timerLayout) (string, uint64, string, error) {
	highRaw, err := readLE(ctx, e.Kernel, object+layout.dueAt+layout.highAt, 4)
	if err != nil {
		if ctx.Err() != nil {
			return "", 0, "", ctx.Err()
		}
		return "", 0, "", fmt.Errorf("timer due time at %#x: %w", object, err)
	}
	lowRaw, err := readLE(ctx, e.Kernel, object+layout.dueAt+layout.lowAt, 4)
	if err != nil {
		if ctx.Err() != nil {
			return "", 0, "", ctx.Err()
		}
		return "", 0, "", fmt.Errorf("timer due time at %#x: %w", object, err)
	}
	period, err := readLE(ctx, e.Kernel, object+layout.periodAt, 4)
	if err != nil {
		if ctx.Err() != nil {
			return "", 0, "", ctx.Err()
		}
		return "", 0, "", fmt.Errorf("timer period at %#x: %w", object, err)
	}
	signal, err := readLE(ctx, e.Kernel, object+layout.signalAt, 4)
	if err != nil {
		if ctx.Err() != nil {
			return "", 0, "", ctx.Err()
		}
		return "", 0, "", fmt.Errorf("timer signal at %#x: %w", object, err)
	}
	signaled := "-"
	if int32(signal) != 0 {
		signaled = "Yes"
	}
	due := pythonHex010(int64(int32(highRaw))) + ":" + pythonHex010(int64(lowRaw))
	return due, period, signaled, nil
}

func timerRoutine(ctx context.Context, e plugin.Environment, object uint64, layout timerLayout) (uint64, bool, error) {
	raw, err := readLE(ctx, e.Kernel, object+layout.dpcAt, layout.pointer)
	if err != nil {
		if ctx.Err() != nil {
			return 0, false, ctx.Err()
		}
		return 0, false, nil
	}
	dpc := canonicalPointer(raw, layout.pointer)
	if layout.encoded {
		never, err := readLE(ctx, e.Kernel, layout.waitNever, 8)
		if err != nil {
			if ctx.Err() != nil {
				return 0, false, ctx.Err()
			}
			return 0, false, nil
		}
		always, err := readLE(ctx, e.Kernel, layout.waitAlways, 8)
		if err != nil {
			if ctx.Err() != nil {
				return 0, false, ctx.Err()
			}
			return 0, false, nil
		}
		dpc = canonicalPointer(decodeTimerDPC(raw, never, always, object), layout.pointer)
	}
	if dpc == 0 {
		return 0, false, nil
	}
	routineAt, err := memory.Add(dpc, layout.routineAt)
	if err != nil {
		return 0, false, nil
	}
	routine, err := readLE(ctx, e.Kernel, routineAt, layout.pointer)
	if err != nil {
		if ctx.Err() != nil {
			return 0, false, ctx.Err()
		}
		return 0, false, nil
	}
	if pointerIdentity(routine, layout.pointer) == 0 {
		return 0, false, nil
	}
	return routine, true, nil
}

func walkTimerList(ctx context.Context, e plugin.Environment, head uint64, layout timerLayout, emit func(uint64) error) error {
	if _, err := memory.Read(ctx, e.Kernel, head, 1); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	next, err := timerPointer(ctx, e, head+layout.flink, layout.pointer)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	seen := map[uint64]bool{head: true}
	for next != 0 && !seen[next] {
		if len(seen) > 100000 {
			return fmt.Errorf("timer list exceeded 100000 entries")
		}
		if next < layout.listOff {
			return nil
		}
		object := next - layout.listOff
		if _, err = memory.Read(ctx, e.Kernel, object, 1); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
		if err = emit(object); err != nil {
			return err
		}
		seen[next] = true
		next, err = timerPointer(ctx, e, next+layout.flink, layout.pointer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
	}
	return nil
}

func timerPointer(ctx context.Context, e plugin.Environment, address uint64, pointer int) (uint64, error) {
	raw, err := readLE(ctx, e.Kernel, address, pointer)
	if err != nil {
		return 0, err
	}
	return canonicalPointer(raw, pointer), nil
}

func timerProcessorHeads(ctx context.Context, e plugin.Environment) ([]uint64, error) {
	cpuAddr, err := e.Symbol("KeNumberProcessors")
	if err != nil {
		return nil, err
	}
	blockAddr, err := e.Symbol("KiProcessorBlock")
	if err != nil {
		return nil, err
	}
	prcbField, err := e.Objects.Field("_KPCR", "Prcb")
	if err != nil {
		return nil, fmt.Errorf("_KPCR.Prcb: %w", err)
	}
	tableField, err := e.Objects.Field("_KPRCB", "TimerTable")
	if err != nil {
		return nil, fmt.Errorf("_KPRCB.TimerTable: %w", err)
	}
	entries, err := e.Objects.Field("_KTIMER_TABLE", "TimerEntries")
	if err != nil {
		return nil, fmt.Errorf("_KTIMER_TABLE.TimerEntries: %w", err)
	}
	entryField, err := e.Objects.Field("_KTIMER_TABLE_ENTRY", "Entry")
	if err != nil {
		return nil, fmt.Errorf("_KTIMER_TABLE_ENTRY.Entry: %w", err)
	}
	entryType, err := e.Symbols.Type("_KTIMER_TABLE_ENTRY")
	if err != nil || entryType.Size == 0 {
		return nil, fmt.Errorf("_KTIMER_TABLE_ENTRY: %w", err)
	}
	_, hasState := mustTypeFields(e.Symbols, "_KTIMER_TABLE")["TableState"]
	if hasState && (entries.Type.Kind != "array" || entries.Type.Subtype == nil || entries.Type.Subtype.Kind != "array") {
		return nil, fmt.Errorf("_KTIMER_TABLE.TimerEntries is not a two-dimensional array")
	}
	count, err := readUnsignedInt(ctx, e, cpuAddr)
	if err != nil {
		return nil, fmt.Errorf("KeNumberProcessors: %w", err)
	}
	if count > 1024 {
		return nil, fmt.Errorf("KeNumberProcessors %d exceeds 1024", count)
	}
	width := e.Symbols.PointerSize()
	var heads []uint64
	for i := uint64(0); i < count; i++ {
		slot, err := memory.Add(blockAddr, i*uint64(width))
		if err != nil {
			return nil, err
		}
		target, err := readPointer(ctx, e, slot)
		if err != nil {
			return nil, fmt.Errorf("KiProcessorBlock[%d]: %w", i, err)
		}
		target = canonicalPointer(target, width)
		if _, err = memory.Read(ctx, e.Kernel, target, 1); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if target < prcbField.Offset {
			return nil, fmt.Errorf("PRCB %#x is below _KPCR.Prcb", target)
		}
		table := target + tableField.Offset + entries.Offset
		heads = append(heads, timerEntryHeads(table, entries.Type, entryType.Size, entryField.Offset, hasState)...)
	}
	return heads, nil
}

func timerEntryHeads(base uint64, entries symbols.TypeRef, entrySize, entryOff uint64, twoDimensional bool) []uint64 {
	if entries.Kind != "array" || entries.Count == 0 || entries.Subtype == nil {
		return nil
	}
	var heads []uint64
	if twoDimensional {
		inner := entries.Subtype
		if inner.Kind != "array" || inner.Count == 0 {
			return nil
		}
		for outer := uint64(0); outer < entries.Count; outer++ {
			for index := uint64(0); index < inner.Count; index++ {
				heads = append(heads, base+((outer*inner.Count+index)*entrySize)+entryOff)
			}
		}
		return heads
	}
	for index := uint64(0); index < entries.Count; index++ {
		heads = append(heads, base+index*entrySize+entryOff)
	}
	return heads
}

func timerLegacyHeads(ctx context.Context, e plugin.Environment) ([]uint64, error) {
	address, err := e.Symbol("KiTimerTableListHead")
	if err != nil {
		return nil, err
	}
	listType, err := e.Symbols.Type("_LIST_ENTRY")
	if err != nil || listType.Size == 0 {
		return nil, fmt.Errorf("_LIST_ENTRY: %w", err)
	}
	count := 256
	if e.Symbols.PointerSize() == 8 || windowsVistaOrLater(e.Symbols) {
		count = 512
	}
	heads := make([]uint64, 0, count)
	for index := 0; index < count; index++ {
		heads = append(heads, address+uint64(index)*listType.Size)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return heads, nil
}

func mustTypeFields(table symbols.SymbolTable, name string) map[string]symbols.Field {
	typ, err := table.Type(name)
	if err != nil || typ.Fields == nil {
		return map[string]symbols.Field{}
	}
	return typ.Fields
}

// timerUsesProcessorTable matches is_windows_7 or is_windows_8_or_later.
// A present PE version is a 4-tuple, so the Win7 equality with (6, 1) is false
// and only Windows 8 or later takes this path. Without PE metadata, the Win7
// and Windows 8 fallbacks apply.
func timerUsesProcessorTable(table symbols.SymbolTable) bool {
	if _, _, ok := windowsPEVersion(table); ok {
		return windows8OrLater(table)
	}
	return timerWindows7Fallback(table) || windows8OrLater(table)
}

func timerWindows7Fallback(table symbols.SymbolTable) bool {
	header, err := table.Type("_OBJECT_HEADER")
	if err != nil {
		return false
	}
	if _, ok := header.Fields["TypeIndex"]; !ok {
		return false
	}
	handles, err := table.Type("_HANDLE_TABLE")
	if err != nil {
		return false
	}
	_, ok := handles.Fields["HandleCount"]
	return ok
}

// decodeTimerDPC matches KTIMER.get_dpc when KiWaitNever and KiWaitAlways exist.
func decodeTimerDPC(raw, waitNever, waitAlways, timer uint64) uint64 {
	entry := rol64(raw^waitNever, uint(waitNever&0xff))
	entry = bswap64(entry ^ canonicalPointer(timer, 8))
	return entry ^ waitAlways
}

func rol64(value uint64, count uint) uint64 {
	count %= 64
	if count == 0 {
		return value
	}
	return (value << count) | (value >> (64 - count))
}

func bswap64(value uint64) uint64 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	return binary.LittleEndian.Uint64(buf[:])
}

// pythonHex010 matches format(n, "#010x"): the 0x prefix counts toward the
// width, and a negative value keeps the minus sign outside that prefix.
func pythonHex010(value int64) string {
	prefix := "0x"
	magnitude := uint64(value)
	if value < 0 {
		prefix = "-0x"
		magnitude = uint64(-value)
	}
	digits := fmt.Sprintf("%x", magnitude)
	for len(prefix)+len(digits) < 10 {
		digits = "0" + digits
	}
	return prefix + digits
}
