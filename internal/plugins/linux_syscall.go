package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxSyscallPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.check_syscall", Upstream: "linux.malware.check_syscall.Check_syscall", Platform: "linux", NeedsKernel: true, Description: "Inspect system-call pointers using metadata/next-symbol sizing (native disassembly unavailable)", Parameters: []plugin.Parameter{{Name: "max-entries", Kind: "uint", Default: "65536", Description: "Maximum entries per syscall table, 1..1000000"}}, Columns: []evidence.Column{{Name: "Table Address", Kind: "address"}, {Name: "Table Name", Kind: "string"}, {Name: "Index", Kind: "uint64"}, {Name: "Handler Address", Kind: "address"}, {Name: "Handler Symbol", Kind: "string"}, {Name: "TableVirtualAddress", Kind: "address"}, {Name: "EntryAddress", Kind: "address"}, {Name: "ExactSymbols", Kind: "structure"}, {Name: "Sizing", Kind: "structure"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Status", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}}}, linuxSyscall}}
}

type linuxSyscallSymbol struct {
	address uint64
	name    string
}

func linuxSyscallPointer(raw []byte, endian string) (uint64, error) {
	var order binary.ByteOrder = binary.LittleEndian
	if endian == "big" {
		order = binary.BigEndian
	} else if endian != "little" && endian != "" {
		return 0, fmt.Errorf("unsupported syscall pointer byte order %q", endian)
	}
	switch len(raw) {
	case 4:
		return uint64(order.Uint32(raw)), nil
	case 8:
		return order.Uint64(raw), nil
	default:
		return 0, fmt.Errorf("invalid syscall pointer capture size %d", len(raw))
	}
}

type linuxSyscallSize struct {
	metadata, next, nextAddress, entries uint64
	nextNames                            []string
}

func linuxSyscallTableSize(symbols []linuxSyscallSymbol, metadata, address, width uint64) (linuxSyscallSize, error) {
	result := linuxSyscallSize{metadata: metadata, nextNames: []string{}}
	if width != 4 && width != 8 {
		return result, fmt.Errorf("invalid syscall pointer width %d", width)
	}
	i := sort.Search(len(symbols), func(i int) bool { return symbols[i].address > address })
	if i < len(symbols) {
		result.nextAddress = symbols[i].address
		result.next = (result.nextAddress - address) / width
		for j := i; j < len(symbols) && symbols[j].address == result.nextAddress; j++ {
			result.nextNames = append(result.nextNames, symbols[j].name)
		}
	}
	result.entries = metadata
	if result.entries == 0 || result.next != 0 && result.next < result.entries {
		result.entries = result.next
	}
	if result.entries == 0 {
		return result, fmt.Errorf("no positive syscall metadata or next-symbol table size")
	}
	return result, nil
}

func (s linuxSyscallSize) proof(digest string) evidence.Value {
	return evidence.Value{Kind: "structure", Data: map[string]any{"Method": "minimum_positive_metadata_and_next_symbol", "MetadataCount": strconv.FormatUint(s.metadata, 10), "NextSymbolCount": strconv.FormatUint(s.next, 10), "NextSymbolAddress": fmt.Sprintf("0x%x", s.nextAddress), "NextSymbolNames": s.nextNames, "SelectedEntries": strconv.FormatUint(s.entries, 10), "SymbolDigest": digest, "NativeDisassembly": "unavailable"}}
}

func linuxSyscall(ctx context.Context, e plugin.Environment, p map[string]string, emit plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("system-call inspection requires kernel memory and symbols")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	width := uint64(e.Symbols.PointerSize())
	if width != 4 && width != 8 {
		return fmt.Errorf("system-call inspection requires 32-bit or 64-bit symbols")
	}
	pointerType, err := e.Symbols.Type("pointer")
	if err != nil {
		return err
	}
	if _, err := linuxSyscallPointer(make([]byte, int(width)), pointerType.Endian); err != nil {
		return err
	}
	max, err := strconv.ParseUint(p["max-entries"], 0, 32)
	if err != nil || max < 1 || max > 1000000 {
		return fmt.Errorf("max-entries must be 1..1000000")
	}
	if _, err := e.Symbols.Lookup("sys_call_table"); err != nil {
		return fmt.Errorf("required sys_call_table unavailable: %w", err)
	}
	var symbols []linuxSyscallSymbol
	var metadata uint64
	exact := map[uint64][]string{}
	for _, name := range e.Symbols.Names() {
		if err := ctx.Err(); err != nil {
			return err
		}
		symbol, err := e.Symbols.Lookup(name)
		if err != nil {
			return err
		}
		address, err := e.Symbol(name)
		if err != nil {
			return err
		}
		symbols = append(symbols, linuxSyscallSymbol{symbol.Address, name})
		exact[address&mask] = append(exact[address&mask], name)
		if strings.HasPrefix(name, "__syscall_meta__") {
			metadata++
		}
	}
	sort.Slice(symbols, func(i, j int) bool {
		if symbols[i].address != symbols[j].address {
			return symbols[i].address < symbols[j].address
		}
		return symbols[i].name < symbols[j].name
	})
	linuxAFSortSymbols(exact)
	row := func(name, kind string) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
		for _, c := range linuxSyscallPlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		r.Cells["Table Name"], r.Cells["RecordType"] = evidence.Text(name), evidence.Text(kind)
		return r
	}
	out := func(r evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return emit(r)
	}
	var failures pluginFailures
	var tables, absent, visits, unknown, diagnostics uint64
	problem := func(r evidence.Row, reason string, cause error) error {
		failures.add(cause)
		diagnostics++
		r.Cells["RecordType"], r.Cells["Status"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Text(reason), evidence.Missing(reason, cause)
		return out(r)
	}
	primary := "64bit"
	if width == 4 {
		primary = "32bit"
	}
	for _, table := range []struct{ symbol, name string }{{"sys_call_table", primary}, {"ia32_sys_call_table", "32bit"}} {
		r := row(table.name, "table_observation")
		symbol, err := e.Symbols.Lookup(table.symbol)
		if err != nil {
			absent++
			r.Cells["Status"] = evidence.Text("optional_ia32_table_absent")
			if err := out(r); err != nil {
				return err
			}
			continue
		}
		tables++
		base, err := e.Symbol(table.symbol)
		if err != nil {
			return err
		}
		r.Provenance.Offset = fmt.Sprintf("0x%x", base)
		r.Cells["Table Address"], r.Cells["TableVirtualAddress"] = evidence.Address(symbol.Address), evidence.Address(base)
		size, err := linuxSyscallTableSize(symbols, metadata, symbol.Address, width)
		r.Cells["Sizing"] = size.proof(e.Symbols.Digest())
		if err != nil {
			if err := problem(r, "table_size_unavailable", err); err != nil {
				return err
			}
			continue
		}
		if size.entries > max {
			if err := problem(r, "table_exceeds_bound", fmt.Errorf("%s has %d inferred entries, above max-entries %d", table.symbol, size.entries, max)); err != nil {
				return err
			}
			continue
		}
		r.Cells["Status"] = evidence.Text("metadata_next_symbol_sizing")
		if err := out(r); err != nil {
			return err
		}
		for i := uint64(0); i < size.entries; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			entry, err := memory.Add(base, i*width)
			if err != nil {
				if err := problem(r, "entry_address_invalid", err); err != nil {
					return err
				}
				break
			}
			visits++
			r := row(table.name, "syscall")
			r.Provenance.Offset = fmt.Sprintf("0x%x", entry)
			r.Cells["Table Address"], r.Cells["TableVirtualAddress"], r.Cells["EntryAddress"], r.Cells["Index"], r.Cells["Sizing"] = evidence.Address(symbol.Address), evidence.Address(base), evidence.Address(entry), evidence.Number(i), size.proof(e.Symbols.Digest())
			raw, proof, err := linuxCaptureRange(ctx, e.Kernel, entry, int(width))
			r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"pointer": proof}}
			if err != nil {
				if err := problem(r, "entry_pointer_unreadable", err); err != nil {
					return err
				}
				continue
			}
			// Decode the captured bytes; do not issue a second evidence read.
			address, err := linuxSyscallPointer(raw, pointerType.Endian)
			if err != nil {
				return err
			}
			names := exact[address&mask]
			name := "UNKNOWN"
			if len(names) > 0 {
				name = linuxUnqualifiedSymbol(names[0])
			} else {
				unknown++
			}
			r.Cells["Handler Address"], r.Cells["Handler Symbol"], r.Cells["Status"] = evidence.Address(address), evidence.Text(name), evidence.Text("inspected")
			r.Cells["ExactSymbols"] = evidence.Value{Kind: "structure", Data: map[string]any{"Names": append([]string{}, names...), "Mask": fmt.Sprintf("0x%x", mask), "SymbolDigest": e.Symbols.Digest()}}
			if err := out(r); err != nil {
				return err
			}
		}
	}
	r := row("", "summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"tables_present": formatCount(tables), "optional_ia32_absent": formatCount(absent), "entry_visits": formatCount(visits), "unknown_exact_symbols": formatCount(unknown), "diagnostics": formatCount(diagnostics), "read_layout_errors": strconv.Itoa(failures.count), "native_disassembly": "unavailable", "scope": "metadata/next-symbol sizing is heuristic and exact membership is not a malware verdict"})
	if err := out(r); err != nil {
		return err
	}
	return failures.err("Linux system-call inspection")
}
