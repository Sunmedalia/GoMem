package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxIDTPlugins() []builtin {
	columns := []evidence.Column{{Name: "Index", Kind: "address"}, {Name: "Address", Kind: "address"}, {Name: "Module", Kind: "string"}, {Name: "Symbol", Kind: "string"}, {Name: "EntryAddress", Kind: "address"}, {Name: "DescriptorType", Kind: "string"}, {Name: "Matches", Kind: "structure"}}
	for _, c := range linuxModxviewPlugins()[0].spec.Columns {
		if c.Name != "Address" {
			columns = append(columns, c)
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.check_idt", Upstream: "linux.malware.check_idt.Check_idt", Platform: "linux", NeedsKernel: true, Description: "Inspect hardware and system-call IDT entries with module and exact symbol attribution", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Module source and per-list traversal bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"}}, Columns: columns}, linuxIDT}}
}

func linuxIDTType(e plugin.Environment) (string, uint64, error) {
	names := []string{"gate_struct64", "gate_struct", "idt_desc"}
	if e.Symbols.PointerSize() == 4 {
		names = []string{"gate_struct", "desc_struct", "gate_struct32"}
	} else if e.Symbols.PointerSize() != 8 {
		return "", 0, fmt.Errorf("IDT requires 32-bit or 64-bit symbols")
	}
	for _, name := range names {
		if typ, err := e.Symbols.Type(name); err == nil {
			if typ.Size < 1 || typ.Size > 4096 {
				return "", 0, fmt.Errorf("invalid IDT descriptor size %d", typ.Size)
			}
			return name, typ.Size, nil
		}
	}
	return "", 0, fmt.Errorf("unsupported IDT descriptor types %v", names)
}

func linuxIDTAddress(n *linuxModuleRead, entry uint64, typ string, mask uint64) (uint64, error) {
	packed, err := n.has(typ, "a")
	if err != nil {
		return 0, err
	}
	if packed {
		a, err := n.uint(entry, typ, "a")
		if err != nil {
			return 0, err
		}
		b, err := n.uint(entry, typ, "b")
		if err != nil {
			return 0, err
		}
		return (b & 0xffff0000) | (a & 0xffff), nil
	}
	low, err := n.uint(entry, typ, "offset_low")
	if err != nil {
		return 0, err
	}
	middle, err := n.uint(entry, typ, "offset_middle")
	if err != nil {
		return 0, err
	}
	high := uint64(0)
	has, err := n.has(typ, "offset_high")
	if err != nil {
		return 0, err
	}
	if has {
		high, err = n.uint(entry, typ, "offset_high")
		if err != nil {
			return 0, err
		}
	}
	return ((high << 32) | (middle << 16) | low) & mask, nil
}

func linuxIDT(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("IDT inspection requires kernel memory and symbols")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	typ, stride, err := linuxIDTType(e)
	if err != nil {
		return err
	}
	table, err := e.Symbol("idt_table")
	if err != nil {
		return err
	}
	columns := linuxIDTPlugins()[0].spec.Columns
	emit := func(r evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, c := range columns {
			if _, ok := r.Cells[c.Name]; !ok {
				r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
			}
		}
		return out(r)
	}
	s, err := linuxGatherModuleSources(ctx, e, p, emit)
	if err != nil {
		return err
	}
	if err := s.kernel(); err != nil {
		if err := s.issue(0, "kernel", "kernel_bounds_unavailable", err); err != nil {
			return err
		}
	}
	modules := linuxFlattenModuleSources(s.results, mask)
	index, err := linuxKernelSymbolIndex(ctx, e, mask)
	if err != nil {
		return err
	}
	var checked, zeros, unknown, overlaps, missingSymbols, unreadable uint64
	for i := uint64(0); i <= 20; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		idx := i
		if i == 20 {
			idx = 128
		}
		entry, err := memory.Add(table, idx*stride)
		if err != nil {
			return err
		}
		r := linuxModuleRow(e, entry, "idt_entry", "idt_table")
		r.Cells["Index"], r.Cells["EntryAddress"], r.Cells["DescriptorType"] = evidence.Address(idx), evidence.Address(entry), evidence.Text(typ)
		r.Cells["Address"] = evidence.Missing("handler_unavailable", nil)
		r.Cells["Module"], r.Cells["Symbol"] = evidence.Missing("not_available", nil), evidence.Missing("not_available", nil)
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		fields["idt_table_symbol"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Name": evidence.Text("idt_table"), "Address": evidence.Address(table), "SymbolDigest": evidence.Text(e.Symbols.Digest())}}
		before := s.failures.count
		finish := func(status string) error {
			r.Cells["Status"] = evidence.Text(status)
			if s.failures.count > before {
				r.Cells["Error"] = evidence.Missing("idt_inspection_incomplete", fmt.Errorf("%d read/layout errors", s.failures.count-before))
			}
			return s.out(r)
		}
		// is_valid in the pinned generator probes the entry start, not the
		// descriptor's entire extent. Keep the probe and actual member reads.
		_, proof, err := linuxCaptureRange(ctx, e.Kernel, entry, 1)
		fields["entry_start"] = proof
		if err != nil {
			s.failures.add(err)
			unreadable++
			r.Cells["RecordType"] = evidence.Text("entry_observation")
			if err := finish("entry_start_unreadable"); err != nil {
				return err
			}
			continue
		}
		address, err := linuxIDTAddress(s.reader(fields), entry, typ, mask)
		if err != nil {
			s.failures.add(err)
			unreadable++
			r.Cells["RecordType"] = evidence.Text("entry_observation")
			if err := finish("descriptor_unreadable"); err != nil {
				return err
			}
			continue
		}
		checked++
		r.Cells["Address"] = evidence.Address(address)
		if address == 0 {
			zeros++
			if err := finish("uninitialized_zero"); err != nil {
				return err
			}
			continue
		}
		match, name, matches, err := linuxModuleLookup(s.reader(fields), modules, index, address)
		s.failures.add(err)
		if match != nil {
			r.Cells["Module"] = evidence.Text(match.name)
		} else {
			unknown++
		}
		if name != "" {
			r.Cells["Symbol"] = evidence.Text(name)
		} else {
			missingSymbols++
			if err != nil {
				r.Cells["Symbol"] = evidence.Missing("module_symbol_unavailable", err)
			}
		}
		ranges := []map[string]evidence.Value{}
		for _, m := range matches {
			ranges = append(ranges, map[string]evidence.Value{"Module": evidence.Text(m.name), "Offset": evidence.Address(m.offset), "Base": evidence.Address(m.base), "Size": evidence.Number(m.size), "Source": evidence.Text(m.source)})
		}
		r.Cells["Matches"] = evidence.Value{Kind: "structure", Data: map[string]any{"ranges": ranges, "overlap": len(matches) > 1}}
		if len(matches) > 1 {
			overlaps++
		}
		if err := finish("inspected"); err != nil {
			return err
		}
	}
	r := linuxModuleRow(e, table, "summary", "idt_table")
	r.Cells["DescriptorType"] = evidence.Text(typ)
	r.Cells["Coverage"] = poolCoverage(map[string]string{"table": fmt.Sprintf("0x%x", table), "descriptor_size": formatCount(stride), "declared_entries": "256", "selected_indices": "0..19,128", "checked_entries": formatCount(checked), "zero_entries": formatCount(zeros), "unattributed_entries": formatCount(unknown), "missing_exact_symbols": formatCount(missingSymbols), "unreadable_entries": formatCount(unreadable), "overlapping_matches": formatCount(overlaps), "source_diagnostics": formatCount(s.diagnostics), "read_layout_errors": strconv.Itoa(s.failures.count), "scope": "selected interrupt entries and ownership are not a malware verdict"})
	if err := s.out(r); err != nil {
		return err
	}
	return s.failures.err("Linux IDT inspection")
}
