package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

var linuxPtraceBits = []struct {
	bit  uint64
	name string
}{
	{1, "PT_PTRACED"}, {0x10000, "PT_SEIZED"}, {8, "PT_TRACESYSGOOD"}, {16, "PT_TRACE_FORK"}, {32, "PT_TRACE_VFORK"}, {64, "PT_TRACE_CLONE"}, {128, "PT_TRACE_EXEC"}, {256, "PT_TRACE_VFORK_DONE"}, {512, "PT_TRACE_EXIT"}, {1024, "PT_TRACE_SECCOMP"}, {1 << 23, "PT_EXITKILL"}, {1 << 24, "PT_SUSPEND_SECCOMP"},
}

func linuxPtraceFlags(raw uint64) (string, uint64, error) {
	var known uint64
	var names []string
	for _, f := range linuxPtraceBits {
		known |= f.bit
		if raw&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	unknown := raw &^ known
	if unknown != 0 {
		return "", unknown, fmt.Errorf("unknown ptrace flag bits %#x", unknown)
	}
	if raw == 0 {
		return "PT_FLAGS(0)", 0, nil
	}
	return strings.Join(names, "|"), 0, nil
}

func linuxPtracePlugins() []builtin {
	var columns []evidence.Column
	for _, name := range []string{"Process", "Flags", "TaskIdentity", "RecordType"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "string"})
	}
	for _, name := range []string{"PID", "TID", "Tracer TID", "Tracee TID", "Depth", "PtraceRaw", "UnknownFlagBits"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "uint64"})
	}
	for _, name := range []string{"Offset", "ProcessOffset"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "address"})
	}
	for _, name := range []string{"IsBeingTraced", "IsTracer", "TraceesComplete"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "bool"})
	}
	for _, name := range []string{"FieldEvidence", "Tracer", "Tracee", "Coverage"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "structure"})
	}
	columns = append(columns, evidence.Column{Name: "Error", Kind: "string"})
	return []builtin{{plugin.Spec{Name: "linux.ptrace", Upstream: "linux.ptrace.Ptrace", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate ptrace tracers and tracees including threads, with raw flags and object identities",
		Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-list traversal bound, 1..1000000"}, {Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total task/thread bound, 1..1000000"}, {Name: "max-relations", Kind: "uint", Default: "1000000", Description: "Total traced-list entry bound, 1..1000000"}}, Columns: columns}, linuxPtrace}}
}

func linuxPtrace(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.ptrace requires kernel memory and symbols")
	}
	maxNodes, _, err := limits(p)
	if err != nil {
		return err
	}
	bound := func(name string) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 32)
		if err != nil || n == 0 || n > 1000000 {
			return 0, fmt.Errorf("%s must be 1..1000000", name)
		}
		return n, nil
	}
	maxTasks, err := bound("max-tasks")
	if err != nil {
		return err
	}
	maxRelations, err := bound("max-relations")
	if err != nil {
		return err
	}
	for _, name := range []string{"pid", "tgid", "comm", "parent", "ptrace", "ptraced.next", "ptraced.prev", "ptrace_entry"} {
		if _, err := e.Objects.Field("task_struct", name); err != nil {
			return err
		}
	}
	init, err := e.Symbol("init_task")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("task_struct", "tasks")
	if err != nil {
		return err
	}
	listField, err := e.Objects.Field("task_struct", "ptraced")
	if err != nil {
		return err
	}
	entry, err := e.Objects.Field("task_struct", "ptrace_entry")
	if err != nil {
		return err
	}
	head, err := memory.Add(init, links.Offset)
	if err != nil {
		return err
	}
	var tasks, checked, selected, being, tracers, relationships, entries, diagnostics uint64
	var failures pluginFailures
	var outputErr error
	emit := func(r evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = out(r)
		return outputErr
	}
	base := func(task, leader uint64) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", task)}}
		for _, c := range linuxPtracePlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		r.Cells["Offset"], r.Cells["ProcessOffset"], r.Cells["RecordType"] = evidence.Address(task), evidence.Address(leader), evidence.Text("task")
		for _, name := range []string{"Tracer TID", "Tracee TID", "Flags"} {
			r.Cells[name] = evidence.Missing("not_available", nil)
		}
		return r
	}
	seen := map[uint64]bool{}
	inspect := func(task, leader uint64) error {
		if seen[task] {
			return fmt.Errorf("task %#x appears in multiple task/thread groups", task)
		}
		if tasks >= maxTasks {
			return fmt.Errorf("task enumeration exceeds max-tasks %d", maxTasks)
		}
		seen[task] = true
		tasks++
		r := base(task, leader)
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		var taskErr error
		issue := func(label string, cause error) {
			if cause == nil {
				return
			}
			failures.add(cause)
			if taskErr == nil {
				taskErr = cause
			}
			fields[label] = evidence.Missing(label, cause)
		}
		read := func(address uint64, typ, member, label string) (uint64, error) {
			_, capture, err := linuxCaptureField(ctx, e, address, typ, member)
			fields[label] = capture
			if err != nil {
				return 0, err
			}
			value, err := e.Objects.Uint(ctx, address, typ, member)
			if err == nil {
				capture.Data.(map[string]evidence.Value)["Value"] = evidence.Number(value)
			}
			return value, err
		}
		finish := func() error {
			if taskErr != nil {
				diagnostics++
				r.Cells["Error"] = evidence.Missing("ptrace_observation_incomplete", taskErr)
			}
			return emit(r)
		}
		tid, tidErr := read(task, "task_struct", "pid", "pid")
		tgid, tgidErr := read(task, "task_struct", "tgid", "tgid")
		if tidErr != nil || tgidErr != nil {
			issue("tid_unreadable", tidErr)
			issue("tgid_unreadable", tgidErr)
			r.Cells["RecordType"] = evidence.Text("diagnostic")
			return finish()
		}
		r.Cells["TID"], r.Cells["PID"] = evidence.Number(tid), evidence.Number(tgid)
		if task != leader {
			owner, cause := read(leader, "task_struct", "tgid", "leader.tgid")
			if cause == nil && owner != tgid {
				cause = fmt.Errorf("thread %#x tgid %d differs from owning task %d", task, tgid, owner)
			}
			if cause == nil {
				if _, lookupErr := e.Objects.Field("task_struct", "group_leader"); lookupErr == nil {
					var actual uint64
					actual, cause = read(task, "task_struct", "group_leader", "group_leader")
					if cause == nil && actual != leader {
						cause = fmt.Errorf("thread %#x group_leader differs from owning task %#x", task, leader)
					}
				}
			}
			if cause != nil {
				issue("thread_owner_invalid", cause)
				r.Cells["RecordType"] = evidence.Text("diagnostic")
				return finish()
			}
		}

		stamp := ""
		created := linuxStartTime(ctx, e, task)
		if created.Kind != "missing" {
			stamp = created.String()
		}
		r.Cells["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), task, tid, stamp))
		comm, capture, nameErr := linuxCaptureField(ctx, e, task, "task_struct", "comm")
		fields["comm"] = capture
		r.Cells["Process"] = evidence.Text(spoofDecoded(comm))
		if nameErr != nil {
			issue("comm_unreadable", nameErr)
			if len(comm) == 0 {
				r.Cells["Process"] = evidence.Missing("comm_unreadable", nameErr)
			}
		}
		raw, ptraceErr := read(task, "task_struct", "ptrace", "ptrace")
		if ptraceErr != nil {
			issue("ptrace_unreadable", ptraceErr)
			r.Cells["RecordType"] = evidence.Text("diagnostic")
			return finish()
		}
		checked++
		r.Cells["PtraceRaw"], r.Cells["IsBeingTraced"] = evidence.Number(raw), evidence.Bool(raw != 0)
		if raw != 0 {
			being++
			flags, unknown, cause := linuxPtraceFlags(raw)
			r.Cells["UnknownFlagBits"] = evidence.Number(unknown)
			if cause == nil {
				r.Cells["Flags"] = evidence.Text(flags)
			} else {
				issue("ptrace_flags_unknown", cause)
				r.Cells["Flags"] = evidence.Missing("ptrace_flags_unknown", cause)
			}
		} else {
			r.Cells["UnknownFlagBits"] = evidence.Number(0)
		}
		listHead, cause := memory.Add(task, listField.Offset)
		if cause != nil {
			issue("ptraced_head_invalid", cause)
			r.Cells["RecordType"] = evidence.Text("diagnostic")
			return finish()
		}
		_, capture, listErr := linuxCaptureField(ctx, e, task, "task_struct", "ptraced")
		fields["ptraced"] = capture
		next, nextErr := read(task, "task_struct", "ptraced.next", "ptraced.next")
		isTracer := false
		if listErr == nil && nextErr == nil {
			if next == 0 {
				nextErr = fmt.Errorf("null ptraced.next")
			} else if next != listHead {
				// is_ptracing tests readability of the list_head pointer target, not
				// membership of the target task in the active task list.
				_, capture, nextErr = linuxCaptureField(ctx, e, next, "list_head", "")
				fields["next_target"] = capture
				isTracer = nextErr == nil
			}
		}
		if listErr != nil || nextErr != nil {
			issue("ptraced_head_unreadable", listErr)
			issue("ptraced_next_unreadable", nextErr)
			r.Cells["IsTracer"] = evidence.Missing("ptraced_next_unreadable", taskErr)
		} else {
			r.Cells["IsTracer"] = evidence.Bool(isTracer)
		}
		if isTracer {
			tracers++
		}
		if raw == 0 && !isTracer {
			return finish()
		}
		selected++
		if raw != 0 {
			parent, cause := read(task, "task_struct", "parent", "parent")
			tracer := map[string]evidence.Value{"Offset": evidence.Address(parent)}
			if cause != nil {
				tracer["Offset"] = evidence.Missing("tracer_pointer_unreadable", cause)
			}
			if cause == nil && parent == 0 {
				cause = fmt.Errorf("null ptrace tracer parent")
			}
			var tracerTID uint64
			if cause == nil {
				tracerTID, cause = read(parent, "task_struct", "pid", "parent.pid")
			}
			if cause != nil {
				issue("tracer_unreadable", cause)
				r.Cells["Tracer TID"] = evidence.Missing("tracer_unreadable", cause)
			} else {
				tracer["TID"] = evidence.Number(tracerTID)
				stamp := ""
				created := linuxStartTime(ctx, e, parent)
				if created.Kind != "missing" {
					stamp = created.String()
				}
				tracer["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), parent, tracerTID, stamp))
				if tracerTID != 0 {
					r.Cells["Tracer TID"] = evidence.Number(tracerTID)
				}
			}
			r.Cells["Tracer"] = evidence.Value{Kind: "structure", Data: tracer}
		}
		type tracee struct {
			tid     uint64
			details evidence.Value
		}
		var tracees []tracee
		listErr = e.Objects.WalkList(ctx, listHead, entry.Offset, maxNodes, func(address uint64) error {
			if entries >= maxRelations {
				return fmt.Errorf("tracee entries exceed max-relations %d", maxRelations)
			}
			entries++
			_, capture, cause := linuxCaptureField(ctx, e, address, "task_struct", "pid")
			details := map[string]evidence.Value{"Offset": evidence.Address(address), "PIDField": capture}
			failed := func(err error) error {
				fields["FailedTracee"] = evidence.Value{Kind: "structure", Data: details}
				return err
			}
			if cause != nil {
				return failed(cause)
			}
			tid, cause := e.Objects.Uint(ctx, address, "task_struct", "pid")
			if cause != nil {
				return failed(cause)
			}
			_, capture, cause = linuxCaptureField(ctx, e, address, "task_struct", "ptrace_entry")
			details["EntryField"] = capture
			if cause != nil {
				return failed(cause)
			}
			details["TID"] = evidence.Number(tid)
			stamp := ""
			created := linuxStartTime(ctx, e, address)
			if created.Kind != "missing" {
				stamp = created.String()
			}
			details["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), address, tid, stamp))
			tracees = append(tracees, tracee{tid, evidence.Value{Kind: "structure", Data: details}})
			return nil
		})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if listErr != nil {
			issue("tracee_list_incomplete", listErr)
		}
		r.Cells["TraceesComplete"] = evidence.Bool(listErr == nil)
		if err := finish(); err != nil {
			return err
		}
		// Match the pinned renderer's incrementing depths for each task's rows.
		// Actual tracee relationships remain explicit in the object-based fields.
		for i := 0; i < max(1, len(tracees)); i++ {
			relation := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: r.Provenance}
			for k, v := range r.Cells {
				relation.Cells[k] = v
			}
			relation.Cells["RecordType"], relation.Cells["Depth"] = evidence.Text("relationship"), evidence.Number(uint64(i))
			relation.ID = fmt.Sprintf("ptrace:%x:%d", task, i)
			if i > 0 {
				relation.ParentID = fmt.Sprintf("ptrace:%x:%d", task, i-1)
			}
			if len(tracees) > 0 {
				relation.Cells["Tracee TID"], relation.Cells["Tracee"] = evidence.Number(tracees[i].tid), tracees[i].details
			} else if listErr != nil {
				relation.Cells["Tracee TID"] = evidence.Missing("tracee_list_incomplete", listErr)
			}
			if err := emit(relation); err != nil {
				return err
			}
			relationships++
		}
		return nil
	}
	err = e.Objects.WalkList(ctx, head, links.Offset, maxNodes, func(leader uint64) error {
		if err := inspect(leader, leader); err != nil {
			return err
		}
		cause := linuxThreadAddresses(ctx, e, leader, maxNodes, func(task uint64) error {
			if task == leader {
				return nil
			}
			return inspect(task, leader)
		})
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if cause != nil {
			failures.add(cause)
			diagnostics++
			r := base(leader, leader)
			r.Cells["RecordType"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("thread_enumeration_incomplete", cause)
			return emit(r)
		}
		return nil
	})
	if err != nil {
		return err
	}
	r := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": poolCoverage(map[string]string{"tasks": formatCount(tasks), "checked": formatCount(checked), "selected": formatCount(selected), "traced_tasks": formatCount(being), "tracer_tasks": formatCount(tracers), "relationships": formatCount(relationships), "tracee_entries": formatCount(entries), "diagnostics": formatCount(diagnostics)})}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	if err := emit(r); err != nil {
		return err
	}
	return failures.err("Linux ptrace enumeration")
}
