package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsKPCRPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.kpcrs", Upstream: "windows.kpcrs.KPCRs", Platform: "windows", NeedsKernel: true,
		Description: "List each processor KPCR and its PRCB from KiProcessorBlock",
		Columns: []evidence.Column{
			{Name: "Offset", Kind: "address"},
			{Name: "PRCB", Kind: "address"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsKPCRs}}
}

func windowsKPCRs(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.kpcrs requires a kernel layer and symbols")
	}
	cpuAddr, err := e.Symbol("KeNumberProcessors")
	if err != nil {
		return err
	}
	blockAddr, err := e.Symbol("KiProcessorBlock")
	if err != nil {
		return err
	}
	prcb, err := e.Objects.Field("_KPCR", "Prcb")
	if err != nil {
		return fmt.Errorf("windows.kpcrs requires _KPCR.Prcb: %w", err)
	}
	memberName := "CurrentPrcb"
	member, err := e.Objects.Field("_KPCR", memberName)
	if err != nil {
		memberName = "Prcb"
		member = prcb
	}
	count, err := readUnsignedInt(ctx, e, cpuAddr)
	if err != nil {
		return fmt.Errorf("windows.kpcrs cannot read KeNumberProcessors: %w", err)
	}
	if count > 1024 {
		return fmt.Errorf("windows.kpcrs KeNumberProcessors %d exceeds 1024", count)
	}
	width := e.Symbols.PointerSize()
	if width < 1 || width > 8 {
		return fmt.Errorf("windows.kpcrs invalid pointer width %d", width)
	}
	var rows, skipped int
	for i := uint64(0); i < count; i++ {
		slot, err := memory.Add(blockAddr, i*uint64(width))
		if err != nil {
			return err
		}
		target, err := readPointer(ctx, e, slot)
		if err != nil {
			return fmt.Errorf("windows.kpcrs cannot read KiProcessorBlock[%d]: %w", i, err)
		}
		if _, err = memory.Read(ctx, e.Kernel, target, 1); err != nil {
			skipped++
			continue
		}
		if target < prcb.Offset {
			return fmt.Errorf("windows.kpcrs PRCB %#x is below _KPCR.Prcb offset %#x", target, prcb.Offset)
		}
		kpcr := target - prcb.Offset
		prcbValue, err := kpcrMember(ctx, e, kpcr, memberName, member)
		if err != nil {
			return err
		}
		rows++
		if err = out(kpcrRow(e, kpcr, prcbValue)); err != nil {
			return err
		}
	}
	summary := kpcrBase(e, 0)
	summary.Provenance.Offset = "0x0"
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"processors": strconv.FormatUint(count, 10),
		"rows":       strconv.Itoa(rows),
		"skipped":    strconv.Itoa(skipped),
	}}
	return out(summary)
}

func readUnsignedInt(ctx context.Context, e plugin.Environment, address uint64) (uint64, error) {
	size := 4
	endian := "little"
	if typ, err := e.Symbols.Type("unsigned int"); err == nil && typ.Size >= 1 && typ.Size <= 8 {
		size = int(typ.Size)
		if typ.Endian != "" {
			endian = typ.Endian
		}
	}
	raw, err := memory.Read(ctx, e.Kernel, address, size)
	if err != nil {
		return 0, err
	}
	var value uint64
	if endian == "big" {
		for _, b := range raw {
			value = value<<8 | uint64(b)
		}
		return value, nil
	}
	for i, b := range raw {
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}

func kpcrMember(ctx context.Context, e plugin.Environment, kpcr uint64, name string, field symbols.Field) (uint64, error) {
	address, err := memory.Add(kpcr, field.Offset)
	if err != nil {
		return 0, err
	}
	if field.Type.Kind == "pointer" {
		value, err := readPointer(ctx, e, address)
		if err != nil {
			return 0, fmt.Errorf("windows.kpcrs cannot read _KPCR.%s: %w", name, err)
		}
		return value, nil
	}
	return address, nil
}

func kpcrRow(e plugin.Environment, kpcr, prcb uint64) evidence.Row {
	row := kpcrBase(e, kpcr)
	row.Cells["RecordType"] = evidence.Text("kpcr")
	row.Cells["Offset"] = evidence.Address(kpcr)
	row.Cells["PRCB"] = evidence.Address(prcb)
	return row
}

func kpcrBase(e plugin.Environment, kpcr uint64) evidence.Row {
	layer := ""
	if e.Kernel != nil {
		layer = e.Kernel.Name()
	}
	offset := evidence.Missing("not_applicable", nil)
	text := "0x0"
	if kpcr != 0 {
		offset = evidence.Address(kpcr)
		text = fmt.Sprintf("0x%x", kpcr)
	}
	return evidence.Row{Cells: map[string]evidence.Value{
		"Offset": offset, "PRCB": evidence.Missing("not_applicable", nil),
		"RecordType": evidence.Missing("not_applicable", nil),
		"Error":      evidence.Missing("not_applicable", nil),
		"Coverage":   evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: layer, Offset: text}}
}
