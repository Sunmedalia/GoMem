package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxKeyboardPlugins() []builtin {
	columns := []evidence.Column{{Name: "Address", Kind: "address"}, {Name: "Module", Kind: "string"}, {Name: "Symbol", Kind: "string"}, {Name: "Callback", Kind: "address"}, {Name: "Matches", Kind: "structure"}}
	for _, c := range linuxModxviewPlugins()[0].spec.Columns {
		if c.Name != "Address" {
			columns = append(columns, c)
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.keyboard_notifiers", Upstream: "linux.malware.keyboard_notifiers.Keyboard_notifiers", Platform: "linux", NeedsKernel: true, Description: "Walk the keyboard notifier chain and attribute each callback", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Module source and per-list traversal bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"}}, Columns: columns}, linuxKeyboard}}
}

// walk_internal_list yields the pointer itself, checks only forward readability,
// stops on a repeated pointer, and includes entry 4096 before stopping.
func linuxKeyboardWalk(ctx context.Context, e plugin.Environment, start uint64, max int, emit func(uint64) error) (stopped string, err error) {
	if max < 1 || max > 1000000 {
		return "", fmt.Errorf("invalid notifier walk limit")
	}
	seen := map[uint64]bool{}
	current := start
	for count := 0; ; count++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if seen[current] {
			return "repeat", nil
		}
		seen[current] = true
		if _, _, err := linuxCaptureRange(ctx, e.Kernel, current, 1); err != nil {
			return "unreadable", err
		}
		if err := emit(current); err != nil {
			return "", err
		}
		if count == max {
			return "bound", fmt.Errorf("keyboard notifier walk reached %d entries", max)
		}
		next, err := e.Objects.Uint(ctx, current, "notifier_block", "next")
		if err != nil {
			return "next", err
		}
		current = next
	}
}

func linuxKeyboard(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("keyboard notifier inspection requires kernel memory and symbols")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	for _, name := range []string{"atomic_notifier_head", "notifier_block"} {
		if _, err := e.Symbols.Type(name); err != nil {
			return fmt.Errorf("keyboard notifier layout unavailable: %w", err)
		}
	}
	headField, err := e.Objects.Field("atomic_notifier_head", "head")
	if err != nil {
		return err
	}
	for _, name := range []string{"next", "notifier_call"} {
		if _, err := e.Objects.Field("notifier_block", name); err != nil {
			return err
		}
	}
	list, err := e.Symbol("keyboard_notifier_list")
	if err != nil {
		return fmt.Errorf("keyboard_notifier_list unavailable: %w", err)
	}
	if _, err := memory.Add(list, headField.Offset); err != nil {
		return err
	}
	columns := linuxKeyboardPlugins()[0].spec.Columns
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
	_, proof, err := linuxCaptureRange(ctx, e.Kernel, list, 1)
	headRow := linuxModuleRow(e, list, "list_observation", "keyboard_notifier_list")
	headRow.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"list_start": proof, "symbol": {Kind: "structure", Data: map[string]evidence.Value{"Name": evidence.Text("keyboard_notifier_list"), "Address": evidence.Address(list), "SymbolDigest": evidence.Text(e.Symbols.Digest())}}}}
	if err != nil {
		s.failures.add(err)
		headRow.Cells["Status"], headRow.Cells["Error"] = evidence.Text("list_head_unreadable"), evidence.Missing("list_head_unreadable", err)
		if err := s.out(headRow); err != nil {
			return err
		}
		return s.failures.err("Linux keyboard notifier inspection")
	}
	headRow.Cells["Status"] = evidence.Text("readable")
	if err := s.out(headRow); err != nil {
		return err
	}
	start, err := s.reader(map[string]evidence.Value{}).uint(list, "atomic_notifier_head", "head")
	if err != nil {
		s.failures.add(err)
		if err := s.out(linuxModuleRow(e, list, "summary", "keyboard_notifier_list")); err != nil {
			return err
		}
		return s.failures.err("Linux keyboard notifier inspection")
	}
	if start == 0 {
		// The fixed walk constructs notifier_block at address zero before stopping.
		if _, _, err := linuxCaptureRange(ctx, e.Kernel, 0, 1); err != nil {
			s.failures.add(err)
			headRow := linuxModuleRow(e, 0, "notifier", "keyboard_notifier_list")
			headRow.Cells["Status"], headRow.Cells["Error"] = evidence.Text("null_callback_unreadable"), evidence.Missing("null_callback_unreadable", err)
			if err := s.out(headRow); err != nil {
				return err
			}
			if err := s.out(linuxModuleRow(e, list, "summary", "keyboard_notifier_list")); err != nil {
				return err
			}
			return s.failures.err("Linux keyboard notifier inspection")
		}
	}
	var callbacks, unknown, missingSymbols, overlaps uint64
	stop, walkErr := linuxKeyboardWalk(ctx, e, start, 4096, func(callback uint64) error {
		r := linuxModuleRow(e, callback, "notifier", "keyboard_notifier_list")
		r.Cells["Callback"] = evidence.Address(callback)
		r.Cells["Module"], r.Cells["Symbol"] = evidence.Missing("not_available", nil), evidence.Missing("not_available", nil)
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		n := s.reader(fields)
		call, err := n.uint(callback, "notifier_block", "notifier_call")
		if err != nil {
			s.failures.add(err)
			r.Cells["Status"], r.Cells["Error"] = evidence.Text("callback_unreadable"), evidence.Missing("callback_unreadable", err)
			return s.out(r)
		}
		r.Cells["Address"] = evidence.Address(call)
		match, name, matches, err := linuxModuleLookup(n, modules, index, call)
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
		callbacks++
		r.Cells["Status"] = evidence.Text("inspected")
		return s.out(r)
	})
	if walkErr != nil && stop != "bound" {
		s.failures.add(walkErr)
	}
	if stop == "bound" {
		s.failures.add(walkErr)
	}
	summary := linuxModuleRow(e, list, "summary", "keyboard_notifier_list")
	summary.Cells["Coverage"] = poolCoverage(map[string]string{"list": fmt.Sprintf("0x%x", list), "head": fmt.Sprintf("0x%x", start), "callbacks": formatCount(callbacks), "unattributed": formatCount(unknown), "missing_exact_symbols": formatCount(missingSymbols), "overlapping_matches": formatCount(overlaps), "walk_stop": stop, "source_diagnostics": formatCount(s.diagnostics), "read_layout_errors": strconv.Itoa(s.failures.count), "pinned_walk_limit": "4096", "scope": "keyboard notifier ownership is not a malware verdict"})
	if err := s.out(summary); err != nil {
		return err
	}
	return s.failures.err("Linux keyboard notifier inspection")
}
