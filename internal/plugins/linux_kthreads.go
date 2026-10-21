package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxKthreadsPlugins() []builtin {
	columns := []evidence.Column{{Name: "TID", Kind: "uint64"}, {Name: "Thread Name", Kind: "string"}, {Name: "Handler Address", Kind: "address"}, {Name: "Module", Kind: "string"}, {Name: "Symbol", Kind: "string"}, {Name: "TaskOffset", Kind: "address"}, {Name: "LeaderOffset", Kind: "address"}, {Name: "TaskIdentity", Kind: "string"}, {Name: "Kthread", Kind: "address"}, {Name: "NameSource", Kind: "string"}, {Name: "Matches", Kind: "structure"}}
	columns = append(columns, linuxModxviewPlugins()[0].spec.Columns...)
	return []builtin{{plugin.Spec{Name: "linux.kthreads", Upstream: "linux.kthreads.Kthreads", Platform: "linux", NeedsKernel: true, Description: "Enumerate Linux 5.8+ kernel thread entry functions with module and exact symbol attribution", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Source and per-list traversal bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"}, {Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total task/thread inspection bound, 1..1000000"}}, Columns: columns}, linuxKthreads}}
}

func linuxKthreads(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("kernel threads require kernel memory and symbols")
	}
	if _, err := e.Objects.Field("kthread", "threadfn"); err != nil {
		return fmt.Errorf("unsupported kthread implementation: typed kthread.threadfn requires Linux >= 5.8: %w", err)
	}
	if _, err := linuxModuleAddressMask(e); err != nil {
		return err
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	maxTasks, err := strconv.ParseUint(p["max-tasks"], 0, 32)
	if err != nil || maxTasks < 1 || maxTasks > 1000000 {
		return fmt.Errorf("max-tasks must be 1..1000000")
	}
	member := "worker_private"
	if _, err := e.Objects.Field("task_struct", member); errors.Is(err, object.ErrFieldAbsent) {
		member = "set_child_tid"
	} else if err != nil {
		return err
	}
	for _, name := range []string{member, "flags", "pid", "comm", "tasks"} {
		if _, err := e.Objects.Field("task_struct", name); err != nil {
			return err
		}
	}
	columns := linuxKthreadsPlugins()[0].spec.Columns
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
	mask, _ := linuxModuleAddressMask(e)
	modules := linuxFlattenModuleSources(s.results, mask)
	kernelSymbols, err := linuxKernelSymbolIndex(ctx, e, mask)
	if err != nil {
		return err
	}
	init, err := e.Symbol("init_task")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("task_struct", "tasks")
	if err != nil {
		return err
	}
	head, err := memory.Add(init, links.Offset)
	if err != nil {
		return err
	}
	var tasks, kernelThreads, selected, skipped, fallbacks, overlaps uint64
	seen := map[uint64]bool{}
	inspect := func(task, leader uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if seen[task] {
			return fmt.Errorf("task %#x appears in multiple task/thread groups", task)
		}
		if tasks >= maxTasks {
			return fmt.Errorf("task inspection exceeds max-tasks %d", maxTasks)
		}
		seen[task] = true
		tasks++
		r := linuxModuleRow(e, task, "task_observation", "")
		r.Cells["TaskOffset"], r.Cells["LeaderOffset"] = evidence.Address(task), evidence.Address(leader)
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		n := s.reader(fields)
		before := s.failures.count
		finish := func(status string) error {
			r.Cells["Status"] = evidence.Text(status)
			if s.failures.count > before {
				r.Cells["Error"] = evidence.Missing("kthread_observation_incomplete", fmt.Errorf("%d read/layout errors", s.failures.count-before))
			}
			return s.out(r)
		}
		// Preserve list links even for user tasks or pointers the reference skips.
		n.capture(task, "task_struct", "tasks")
		if _, err := e.Objects.Field("task_struct", "thread_group"); err == nil {
			n.capture(task, "task_struct", "thread_group")
		} else if _, err := e.Objects.Field("task_struct", "thread_node"); err == nil {
			n.capture(task, "task_struct", "thread_node")
		}
		flags, err := n.uint(task, "task_struct", "flags")
		if err != nil {
			return finish("flags_unreadable")
		}
		if flags&linuxPFKThread == 0 {
			return finish("not_kernel_thread")
		}
		kernelThreads++
		tid, err := n.uint(task, "task_struct", "pid")
		if err != nil {
			return finish("tid_unreadable")
		}
		r.Cells["TID"] = evidence.Number(tid)
		stamp := ""
		created := linuxStartTime(ctx, e, task)
		if created.Kind != "missing" {
			stamp = created.String()
		}
		// Identity inputs include their raw timestamp when available.
		if f, err := e.Objects.Field("task_struct", "start_time"); err == nil && f.Type.Kind != "struct" {
			n.capture(task, "task_struct", "start_time")
		}
		r.Cells["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), task, tid, stamp))
		private, err := n.uint(task, "task_struct", member)
		if err != nil {
			return finish("kthread_pointer_unreadable")
		}
		r.Cells["Kthread"] = evidence.Address(private)
		if private == 0 {
			skipped++
			return finish("null_kthread_pointer")
		}
		_, proof, err := linuxCaptureRange(ctx, e.Kernel, private, 1)
		fields["kthread_pointer_target"] = proof
		if err != nil {
			s.failures.add(err)
			skipped++
			return finish("kthread_target_unreadable")
		}
		fn, err := n.uint(private, "kthread", "threadfn")
		if err != nil {
			return finish("handler_pointer_unreadable")
		}
		r.Cells["Handler Address"] = evidence.Address(fn)
		if fn == 0 {
			skipped++
			return finish("null_handler_pointer")
		}
		_, proof, err = linuxCaptureRange(ctx, e.Kernel, fn, 1)
		fields["handler_pointer_target"] = proof
		if err != nil {
			s.failures.add(err)
			skipped++
			return finish("handler_target_unreadable")
		}
		comm, err := n.text(task, "task_struct", "comm")
		if err != nil {
			return finish("comm_unreadable")
		}
		r.Cells["Thread Name"], r.Cells["NameSource"] = evidence.Text(comm), evidence.Text("task.comm")
		full, hasErr := n.has("kthread", "full_name")
		if hasErr != nil {
			s.failures.add(hasErr)
		} else if full {
			at, fullErr := n.uint(private, "kthread", "full_name")
			if fullErr == nil {
				raw, capture, cause := linuxCaptureRange(ctx, e.Kernel, at, 255)
				fields["full_name_bytes"] = capture
				if cause == nil {
					r.Cells["Thread Name"], r.Cells["NameSource"] = evidence.Text(spoofDecoded(raw)), evidence.Text("kthread.full_name")
				} else {
					fullErr = cause
				}
			}
			if fullErr != nil {
				fallbacks++
				fields["full_name_fallback"] = evidence.Missing("comm_fallback", fullErr)
			}
		}
		match, symbol, matches, cause := linuxModuleLookup(n, modules, kernelSymbols, fn)
		s.failures.add(cause)
		r.Cells["Module"], r.Cells["Symbol"] = evidence.Missing("not_available", nil), evidence.Missing("not_available", nil)
		if match != nil {
			r.Cells["Module"] = evidence.Text(match.name)
		}
		if symbol != "" {
			r.Cells["Symbol"] = evidence.Text(symbol)
		} else if cause != nil {
			r.Cells["Symbol"] = evidence.Missing("module_symbol_unavailable", cause)
		}
		ranges := []map[string]evidence.Value{}
		for _, m := range matches {
			ranges = append(ranges, map[string]evidence.Value{"Module": evidence.Text(m.name), "Offset": evidence.Address(m.offset), "Base": evidence.Address(m.base), "Size": evidence.Number(m.size), "Source": evidence.Text(m.source)})
		}
		r.Cells["Matches"] = evidence.Value{Kind: "structure", Data: map[string]any{"ranges": ranges, "overlap": len(matches) > 1}}
		if len(matches) > 1 {
			overlaps++
		}
		r.Cells["RecordType"] = evidence.Text("kthread")
		selected++
		return finish("selected")
	}
	err = e.Objects.WalkList(ctx, head, links.Offset, max, func(leader uint64) error {
		if err := inspect(leader, leader); err != nil {
			return err
		}
		err := linuxThreadAddresses(ctx, e, leader, max, func(task uint64) error {
			if task == leader {
				return nil
			}
			return inspect(task, leader)
		})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.emitErr != nil {
			return s.emitErr
		}
		if err != nil {
			return s.issue(leader, "tasks", "thread_enumeration_incomplete", err)
		}
		return nil
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.emitErr != nil {
		return s.emitErr
	}
	if err != nil {
		if err := s.issue(head, "tasks", "task_enumeration_incomplete", err); err != nil {
			return err
		}
	}
	r := linuxModuleRow(e, 0, "summary", "")
	r.Cells["Address"] = evidence.Missing("not_applicable", nil)
	r.Provenance.Offset = ""
	r.Cells["Coverage"] = poolCoverage(map[string]string{"tasks": formatCount(tasks), "kernel_threads": formatCount(kernelThreads), "selected": formatCount(selected), "skipped_pointers": formatCount(skipped), "name_fallbacks": formatCount(fallbacks), "overlapping_matches": formatCount(overlaps), "module_ranges": strconv.Itoa(len(modules)), "scan_positions": formatCount(s.positions), "scan_unreadable": formatCount(s.unreadable), "diagnostics": formatCount(s.diagnostics), "read_layout_errors": strconv.Itoa(s.failures.count), "pointer_member": member, "scope": "symbol-described Intel Linux 5.8+; exact symbols only; incomplete reads do not establish absence"})
	if err := s.out(r); err != nil {
		return err
	}
	return s.failures.err("Linux kernel thread enumeration")
}
