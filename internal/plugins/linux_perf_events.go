package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxPerfEventsPlugins() []builtin {
	var columns []evidence.Column

	for _, name := range []string{"Process", "Event", "Short Program Name", "Full Name", "TaskIdentity", "RecordType", "Status"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "string"})
	}
	for _, name := range []string{"Address", "Offset", "TaskOffset", "LeaderOffset", "PMU", "Aux"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "address"})
	}
	columns = append(columns, evidence.Column{Name: "PID", Kind: "uint64"}, evidence.Column{Name: "CreationCounterNS", Kind: "uint64"}, evidence.Column{Name: "FieldEvidence", Kind: "structure"}, evidence.Column{Name: "Coverage", Kind: "structure"}, evidence.Column{Name: "Error", Kind: "missing"})
	return []builtin{{plugin.Spec{Name: "linux.perf_events", Upstream: "linux.tracing.perf_events.PerfEvents", Platform: "linux", NeedsKernel: true, Description: "Enumerate task and thread perf-event programs with acquisition evidence", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-list traversal bound, 1..1000000"}, {Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total task/thread bound, 1..1000000"}, {Name: "max-events", Kind: "uint", Default: "1000000", Description: "Total event-entry bound, 1..1000000"}, {Name: "max-bytes", Kind: "uint", Default: "268435456", Description: "Cumulative acquired-byte budget, 1..1073741824"}}, Columns: columns}, linuxPerfEvents}}
}

type perfReadBudget struct {
	memory.MemoryLayer
	remaining func() uint64
}

func (l *perfReadBudget) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if uint64(len(p)) > l.remaining() {
		return 0, fmt.Errorf("perf event byte budget exhausted")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

func linuxPerfEvents(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	bound := func(name string, max uint64) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || n == 0 || n > max {
			return 0, fmt.Errorf("%s must be 1..%d", name, max)
		}
		return n, nil
	}
	maxNodes, err := bound("max-nodes", 1000000)
	if err != nil {
		return err
	}
	maxTasks, err := bound("max-tasks", 1000000)
	if err != nil {
		return err
	}
	maxEvents, err := bound("max-events", 1000000)
	if err != nil {
		return err
	}
	maxBytes, err := bound("max-bytes", 1<<30)
	if err != nil {
		return err
	}
	if _, err := e.Objects.Field("perf_event", "owner_entry"); err != nil {
		return fmt.Errorf("CONFIG_PERF_EVENTS layout unavailable: %w", err)
	}
	taskLinks, err := e.Objects.Field("task_struct", "tasks")
	if err != nil {
		return err
	}
	eventHead, err := e.Objects.Field("task_struct", "perf_event_list")
	if err != nil {
		return err
	}
	eventLink, err := e.Objects.Field("perf_event", "owner_entry")
	if err != nil {
		return err
	}

	for _, entry := range []struct{ typ, path string }{{"task_struct", "tasks"}, {"task_struct", "perf_event_list"}, {"perf_event", "owner_entry"}} {
		f, err := e.Objects.Field(entry.typ, entry.path)
		if err != nil {
			return err
		}
		if f.Type.Kind != "struct" || f.Type.Name != "list_head" {
			return fmt.Errorf("%s.%s is not an embedded list_head", entry.typ, entry.path)
		}
	}
	for _, entry := range []struct {
		name   string
		offset uint64
	}{{"next", 0}, {"prev", uint64(e.Symbols.PointerSize())}} {
		f, err := e.Objects.Field("list_head", entry.name)
		if err != nil {
			return err
		}
		if f.Type.Kind != "pointer" || f.Offset != entry.offset {
			return fmt.Errorf("unsupported list_head.%s layout", entry.name)
		}
	}

	init, err := e.Symbol("init_task")
	if err != nil {
		return err
	}
	head, err := memory.Add(init, taskLinks.Offset)
	if err != nil {
		return err
	}
	var tasks, events, selected, reads, acquired uint64
	var outputErr error
	send := func(row evidence.Row) error {
		if outputErr != nil {
			return outputErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = out(row)
		return outputErr
	}
	rowAt := func(kind string, at uint64) evidence.Row {
		return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Offset": evidence.Address(at), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", at)}}
	}
	trace := &linuxIDRLayer{MemoryLayer: &perfReadBudget{MemoryLayer: e.Kernel, remaining: func() uint64 { return maxBytes - acquired }}}
	trace.observe = func(at uint64, raw []byte, want int, readErr error) error {
		reads++
		acquired += uint64(len(raw))
		row := rowAt("event_read", at)
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(readErr == nil)}
		if readErr != nil {
			proof["Error"] = evidence.Missing("read_failed", readErr)
			row.Cells["Error"] = proof["Error"]
		}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return send(row)
	}
	e.Kernel = trace
	e.Objects = &object.Reader{Layer: trace, Symbols: e.Symbols}
	pointer := func(at uint64, typ, path string) (uint64, error) {
		f, err := e.Objects.Field(typ, path)
		if err != nil {
			return 0, err
		}
		if f.Type.Kind != "pointer" {
			return 0, fmt.Errorf("%s.%s is not a pointer", typ, path)
		}
		return e.Objects.Uint(ctx, at, typ, path)
	}
	decode := func(raw []byte) string {
		if i := bytes.IndexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		text, _ := replaceInvalidUTF8(raw)
		text, _, _ = strings.Cut(text, "\uFFFD")
		return text
	}
	available := func(text string) evidence.Value {
		if text == "" {
			return evidence.Missing("not_available", nil)
		}
		return evidence.Text(text)
	}
	stringArray := func(at uint64, typ, path string, count int) (string, error) {
		f, err := e.Objects.Field(typ, path)
		if err != nil {
			return "", err
		}
		if f.Type.Kind != "array" || f.Type.Underlying() == nil {
			return "", fmt.Errorf("%s.%s is not an array", typ, path)
		}
		width, err := e.Objects.Size(*f.Type.Underlying())
		if err != nil || width != 1 {
			return "", fmt.Errorf("%s.%s is not a byte array: %v", typ, path, err)
		}
		if count == 0 {
			if f.Type.Count == 0 || f.Type.Count > 256 {
				return "", fmt.Errorf("invalid %s.%s array bound", typ, path)
			}
			count = int(f.Type.Count)
		}
		location, err := memory.Add(at, f.Offset)
		if err != nil {
			return "", err
		}
		raw, err := memory.Read(ctx, trace, location, count)
		if err != nil {
			return "", err
		}
		return decode(raw), nil
	}
	// Reproduce the selected task validity predicates before associating any
	// event. Invalid tasks are explicit failed observations instead of silently
	// entering a successful inventory.
	validateTask := func(task uint64) error {
		typ, err := e.Symbols.Type("task_struct")
		if err != nil {
			return err
		}
		if typ.Size == 0 || typ.Size > 1<<20 {
			return fmt.Errorf("invalid task extent")
		}
		if _, err := memory.Read(ctx, trace, task, int(typ.Size)); err != nil {
			return err
		}
		for _, name := range []string{"pid", "tgid"} {
			f, err := e.Objects.Field("task_struct", name)
			if err != nil {
				return err
			}
			t, err := e.Objects.ScalarType(f.Type)
			if err != nil {
				return err
			}
			value, err := e.Objects.Uint(ctx, task, "task_struct", name)
			if err != nil {
				return err
			}
			if t.Signed && t.Size > 0 && t.Size <= 8 && value&(uint64(1)<<(t.Size*8-1)) != 0 {
				return fmt.Errorf("negative task %s", name)
			}
		}
		probe := func(name string, required, nonnull bool) (uint64, error) {
			f, err := e.Objects.Field("task_struct", name)
			if errors.Is(err, object.ErrFieldAbsent) && !required {
				return 0, nil
			}
			if err != nil {
				return 0, err
			}
			value, err := pointer(task, "task_struct", name)
			if err != nil {
				return 0, err
			}
			if value == 0 {
				if nonnull {
					return 0, fmt.Errorf("null task %s", name)
				}
				return 0, nil
			}
			if f.Type.Underlying() == nil {
				return 0, fmt.Errorf("task %s lacks a pointed type", name)
			}
			size, err := e.Objects.Size(*f.Type.Underlying())
			if err != nil {
				return 0, err
			}
			if size == 0 || size > 1<<20 {
				return 0, fmt.Errorf("invalid task %s pointer extent", name)
			}
			_, err = memory.Read(ctx, trace, value, int(size))
			return value, err
		}
		for _, name := range []string{"signal", "nsproxy", "real_parent"} {
			if _, err := probe(name, false, true); err != nil {
				return err
			}
		}
		active, err := probe("active_mm", false, false)
		if err != nil {
			return err
		}
		mm, err := probe("mm", true, false)
		if err != nil {
			return err
		}
		if mm != 0 && mm != active {
			return fmt.Errorf("task mm differs from active_mm")
		}
		return nil
	}

	var failures pluginFailures
	inspectEvent := func(task, leader, event uint64) error {
		if events >= maxEvents {
			return fmt.Errorf("perf-event traversal exceeds max-events")
		}
		events++
		row := rowAt("event_observation", event)
		row.Cells["TaskOffset"], row.Cells["LeaderOffset"] = evidence.Address(task), evidence.Address(leader)
		parse := func() error {
			pmu, err := pointer(event, "perf_event", "pmu")
			if err != nil {
				return err
			}
			row.Cells["PMU"] = evidence.Address(pmu)
			nameAt, err := pointer(pmu, "pmu", "name")
			if err != nil {
				return err
			}
			raw, err := memory.Read(ctx, trace, nameAt, 64)
			if err != nil {
				return err
			}
			row.Cells["Event"] = available(decode(raw))
			prog, err := pointer(event, "perf_event", "prog")
			if err != nil {
				return err
			}
			row.Cells["Address"] = evidence.Address(prog)
			aux, err := pointer(prog, "bpf_prog", "aux")
			if err != nil {
				return err
			}
			row.Cells["Aux"] = evidence.Address(aux)
			row.Cells["Full Name"] = evidence.Missing("not_available", nil)
			if _, err := e.Objects.Field("bpf_prog_aux", "ksym.name"); err == nil {
				full, err := stringArray(aux, "bpf_prog_aux", "ksym.name", 512)
				if err != nil {
					return err
				}
				row.Cells["Full Name"] = available(full)
			} else if !errors.Is(err, object.ErrFieldAbsent) {
				return err
			}
			short, err := stringArray(aux, "bpf_prog_aux", "name", 0)
			if err != nil {
				return err
			}
			row.Cells["Short Program Name"] = available(short)
			// Preserve the reference's post-read null-program exclusion. A mapped zero
			// address can still be read, so zero is not substituted for an access error.
			if prog == 0 {
				row.Cells["Status"] = evidence.Text("null_program")
				return nil
			}
			pid, err := e.Objects.Uint(ctx, task, "task_struct", "pid")
			if err != nil {
				return err
			}
			row.Cells["PID"] = evidence.Number(pid)
			comm, err := stringArray(task, "task_struct", "comm", 0)
			if err != nil {
				return err
			}
			row.Cells["Process"] = evidence.Text(comm)
			stamp := evidence.Missing("field_not_available", nil)
			if _, err := e.Objects.Field("task_struct", "start_time"); err == nil {
				stamp = linuxStartTime(ctx, e, task)
				if stamp.Kind == "missing" {
					return fmt.Errorf("task creation counter unavailable: %s", stamp.String())
				}
			} else if !errors.Is(err, object.ErrFieldAbsent) {
				return err
			}
			row.Cells["CreationCounterNS"] = stamp
			identityStamp := ""
			if stamp.Kind != "missing" {
				identityStamp = stamp.String()
			}
			row.Cells["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), task, pid, identityStamp))
			row.Cells["RecordType"], row.Cells["Status"] = evidence.Text("perf_event"), evidence.Text("selected")
			selected++
			return nil
		}
		if err := parse(); err != nil {
			if outputErr != nil {
				return outputErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures.add(err)
			row.Cells["Error"] = evidence.Missing("event_incomplete", err)
			row.Cells["Status"] = evidence.Text("incomplete")
		}
		return send(row)
	}
	seen := map[uint64]bool{}
	rejectedTasks := map[uint64]bool{}
	inspectTask := func(task, leader uint64) error {
		if tasks >= maxTasks {
			return fmt.Errorf("task traversal exceeds max-tasks")
		}
		if seen[task] {
			return fmt.Errorf("repeated task across thread groups at %#x", task)
		}
		seen[task] = true
		tasks++
		if err := validateTask(task); err != nil {
			if outputErr != nil {
				return outputErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures.add(err)
			rejectedTasks[task] = true
			row := rowAt("task_observation", task)
			row.Cells["TaskOffset"], row.Cells["LeaderOffset"] = evidence.Address(task), evidence.Address(leader)
			row.Cells["Status"] = evidence.Text("invalid_task")
			row.Cells["Error"] = evidence.Missing("task_incomplete", err)
			return send(row)
		}
		at, err := memory.Add(task, eventHead.Offset)
		if err != nil {
			return err
		}
		before := events
		walkErr := e.Objects.WalkList(ctx, at, eventLink.Offset, int(maxNodes), func(event uint64) error { return inspectEvent(task, leader, event) })
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		row := rowAt("task_observation", task)
		row.Cells["TaskOffset"], row.Cells["LeaderOffset"] = evidence.Address(task), evidence.Address(leader)
		row.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Events": evidence.Number(events - before), "Completed": evidence.Bool(walkErr == nil)}}
		if walkErr != nil {
			failures.add(walkErr)
			row.Cells["Error"] = evidence.Missing("event_list_incomplete", walkErr)
		}
		if err := send(row); err != nil {
			return err
		}
		if events >= maxEvents && walkErr != nil {
			return walkErr
		}
		return nil
	}
	walkErr := e.Objects.WalkList(ctx, head, taskLinks.Offset, int(maxNodes), func(leader uint64) error {
		if err := inspectTask(leader, leader); err != nil {
			return err
		}
		if rejectedTasks[leader] {
			return nil
		}
		err := linuxThreadAddresses(ctx, e, leader, int(maxNodes), func(task uint64) error {
			if task == leader {
				return nil
			}
			// Native ownership checks prevent silently associating a foreign task with
			// this leader when a damaged list happens to remain traversable.
			owner, err := e.Objects.Uint(ctx, task, "task_struct", "tgid")
			if err != nil {
				return err
			}
			tgid, err := e.Objects.Uint(ctx, leader, "task_struct", "tgid")
			if err != nil {
				return err
			}
			if owner != tgid {
				return fmt.Errorf("thread TGID differs from owning process")
			}
			return inspectTask(task, leader)
		})
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			failures.add(err)
			row := rowAt("task_observation", leader)
			row.Cells["Error"] = evidence.Missing("thread_enumeration_incomplete", err)
			if er := send(row); er != nil {
				return er
			}
		}
		return nil
	})
	if outputErr != nil {
		return outputErr
	}
	if trace.outputErr != nil {
		return trace.outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	runErr := errors.Join(walkErr, failures.err("perf events"))
	summary := rowAt("event_summary", 0)
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Tasks": evidence.Number(tasks), "Events": evidence.Number(events), "Selected": evidence.Number(selected), "Reads": evidence.Number(reads), "AcquiredBytes": evidence.Number(acquired), "Completed": evidence.Bool(runErr == nil)}}
	if runErr != nil {
		summary.Cells["Error"] = evidence.Missing("enumeration_incomplete", runErr)
	}
	return errors.Join(runErr, send(summary))
}
