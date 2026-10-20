package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsSSDTPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.ssdt", Upstream: "windows.ssdt.SSDT", Platform: "windows", NeedsKernel: true,
		Description: "List native KiServiceTable entries, with the containing module and any kernel symbol at that relative address",
		Columns: []evidence.Column{
			{Name: "Index", Kind: "uint64"},
			{Name: "Address", Kind: "address"},
			{Name: "Module", Kind: "string"},
			{Name: "Symbol", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsSSDT}}
}

func windowsSSDT(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.ssdt requires a kernel layer and symbols")
	}
	pointer := e.Symbols.PointerSize()
	if pointer != 4 && pointer != 8 {
		return fmt.Errorf("windows.ssdt needs a 4- or 8-byte pointer")
	}
	table, err := e.Symbol("KiServiceTable")
	if err != nil {
		return fmt.Errorf("KiServiceTable: %w", err)
	}
	limitAddress, err := e.Symbol("KiServiceLimit")
	if err != nil {
		return fmt.Errorf("KiServiceLimit: %w", err)
	}
	limitRaw, err := memory.Read(ctx, e.Kernel, limitAddress, 4)
	if err != nil {
		return fmt.Errorf("KiServiceLimit: %w", err)
	}
	limit := int32(binary.LittleEndian.Uint32(limitRaw))
	if limit < 0 {
		return fmt.Errorf("KiServiceLimit %d is negative", limit)
	}
	modules, err := windowsKernelModules(ctx, e)
	if err != nil {
		return err
	}
	byAddress := ssdtSymbols(e.Symbols)
	var emitted, outside, unavailable int
	for index := int32(0); index < limit; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		slot, err := memory.Add(table, uint64(index)*4)
		if err != nil {
			return err
		}
		raw, err := memory.Read(ctx, e.Kernel, slot, 4)
		if err != nil {
			return fmt.Errorf("service %d: %w", index, err)
		}
		address := uint64(binary.LittleEndian.Uint32(raw))
		if pointer == 8 {
			// The low 4 bits are the argument count. The signed remainder is a
			// displacement from KiServiceTable, and it may be negative.
			address = table + uint64(int64(int32(binary.LittleEndian.Uint32(raw))>>4))
		}
		matched := false
		for _, module := range modules {
			if !addressInModule(module.base, module.size, address) {
				continue
			}
			matched = true
			names := byAddress[address-module.base]
			if len(names) == 0 {
				unavailable++
				emitted++
				if err := out(ssdtRow(e, uint64(index), address, module.stem, evidence.Missing("not_available", nil))); err != nil {
					return err
				}
				continue
			}
			for _, name := range names {
				emitted++
				if err := out(ssdtRow(e, uint64(index), address, module.stem, evidence.Text(name))); err != nil {
					return err
				}
			}
		}
		if !matched {
			outside++
		}
	}
	coverage := map[string]string{
		"entries":             formatCount(uint64(limit)),
		"rows":                formatCount(uint64(emitted)),
		"modules":             formatCount(uint64(len(modules))),
		"outside":             formatCount(uint64(outside)),
		"symbols_unavailable": formatCount(uint64(unavailable)),
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{
		"Index":      evidence.Missing("not_applicable", nil),
		"Address":    evidence.Missing("not_applicable", nil),
		"Module":     evidence.Missing("not_applicable", nil),
		"Symbol":     evidence.Missing("not_applicable", nil),
		"RecordType": evidence.Text("summary"),
		"Coverage":   poolCoverage(coverage),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}})
}

func ssdtRow(e plugin.Environment, index, address uint64, module string, symbol evidence.Value) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{
		"Index":      evidence.Number(index),
		"Address":    evidence.Address(address),
		"Module":     evidence.Text(module),
		"Symbol":     symbol,
		"RecordType": evidence.Text("service"),
		"Coverage":   evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
}

func ssdtSymbols(table symbols.SymbolTable) map[uint64][]string {
	grouped := map[uint64][]string{}
	for _, name := range table.Names() {
		sym, err := table.Lookup(name)
		if err != nil {
			continue
		}
		grouped[sym.Address] = append(grouped[sym.Address], ssdtDisplaySymbol(name))
	}
	return grouped
}

// ssdtDisplaySymbol keeps the pinned split: the yielded name is table!name
// split on every bang, then only the second piece.
func ssdtDisplaySymbol(name string) string {
	parts := strings.Split("table!"+name, "!")
	if len(parts) < 2 {
		return name
	}
	return parts[1]
}
