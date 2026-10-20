package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// PF_KTHREAD has been 0x00200000 in the baseline Linux sched.h definitions.
// It selects tasks the pinned plugin skips; a zero mm without this flag is
// reported instead of being treated as a kernel thread.
const linuxPFKThread = 0x00200000

func linuxEnvarPlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"uint64", "PID PPID Length Index"},
		{"address", "ProcessOffset MM EnvStart EnvEnd"},
		{"string", "COMM Key Value RecordType ProcessIdentity Error"},
		{"bytes", "KeyRaw ValueRaw EntryRaw"},
		{"structure", "Coverage"},
	} {
		for _, name := range splitFields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.envars", Upstream: "linux.envars.Envars", Platform: "linux", NeedsKernel: true,
		Description: "Read process environment blocks through each task page table, retaining raw bytes and parse stops",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated task PID filter"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task traversal bound"},
			{Name: "max-env", Kind: "uint", Default: "8192", Description: "Environment byte limit, 1..16777216; the default matches the pinned sanity bound"},
		}, Columns: columns}, linuxEnvars}}
}

func splitFields(names string) []string {
	parts := bytes.Fields([]byte(names))
	out := make([]string, len(parts))
	for i, part := range parts {
		out[i] = string(part)
	}
	return out
}

func linuxEnvars(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	maxEnv, err := strconv.ParseUint(p["max-env"], 0, 32)
	if err != nil || maxEnv == 0 || maxEnv > memory.MaxRead {
		return fmt.Errorf("max-env must be 1..%d", memory.MaxRead)
	}
	var failures pluginFailures
	coverage := map[string]int{}
	err = visitLinuxProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		rows, kind, cause := readLinuxEnvironment(ctx, e, process, pid, name, created, maxEnv)
		if kind == "kernel_thread" {
			coverage["kernel_threads"]++
		} else {
			coverage["user_tasks"]++
		}
		for _, row := range rows {
			switch row.Cells["RecordType"].String() {
			case "variable":
				coverage["variables"]++
			case "diagnostic":
				coverage["diagnostics"]++
			}
		}
		failures.add(cause)
		for _, row := range rows {
			if err := out(row); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	for _, column := range linuxEnvarPlugins()[0].spec.Columns {
		summary.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	summary.Cells["RecordType"] = evidence.Text("summary")
	data := map[string]any{}
	for key, value := range coverage {
		data[key] = strconv.Itoa(value)
	}
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: data}
	if cause := failures.err("Linux process environments"); cause != nil {
		summary.Cells["Error"] = evidence.Missing("environment_incomplete", cause)
	}
	if err = out(summary); err != nil {
		return err
	}
	return failures.err("Linux process environments")
}

func readLinuxEnvironment(ctx context.Context, e plugin.Environment, process, pid uint64, name string, created evidence.Value, maxEnv uint64) ([]evidence.Row, string, error) {
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
	base := func(kind string) evidence.Row {
		row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", process)}}
		for _, column := range linuxEnvarPlugins()[0].spec.Columns {
			row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
		}
		row.Cells["PID"] = evidence.Number(pid)
		row.Cells["COMM"] = evidence.Text(name)
		row.Cells["ProcessOffset"] = evidence.Address(process)
		row.Cells["ProcessIdentity"] = evidence.Text(identity)
		row.Cells["RecordType"] = evidence.Text(kind)
		parent, err := e.Objects.Uint(ctx, process, "task_struct", "real_parent")
		row.Cells["PPID"] = evidence.Number(0)
		if err != nil {
			row.Cells["PPID"] = evidence.Missing("parent_pointer_unreadable", err)
		} else if parent != 0 {
			row.Cells["PPID"] = optionalUint(ctx, e, parent, "task_struct", "tgid", false)
		}
		return row
	}
	kthread, err := linuxKThread(ctx, e, process)
	if err != nil {
		row := base("diagnostic")
		row.Cells["Error"] = evidence.Missing("task_flags_unreadable", err)
		return []evidence.Row{row}, "diagnostic", err
	}
	if kthread {
		return nil, "kernel_thread", nil
	}
	mm, err := e.Objects.Uint(ctx, process, "task_struct", "mm")
	if err != nil {
		row := base("diagnostic")
		row.Cells["Error"] = evidence.Missing("mm_pointer_unreadable", err)
		return []evidence.Row{row}, "diagnostic", err
	}
	if mm == 0 {
		row := base("diagnostic")
		row.Cells["MM"] = evidence.Address(0)
		row.Cells["Error"] = evidence.Missing("no_user_mm", nil)
		return []evidence.Row{row}, "no_user_mm", nil
	}
	fail := func(reason string, cause error, start, end uint64, captured []byte) ([]evidence.Row, string, error) {
		row := base("diagnostic")
		row.Cells["MM"] = evidence.Address(mm)
		if start != 0 || end != 0 {
			row.Cells["EnvStart"] = evidence.Address(start)
			row.Cells["EnvEnd"] = evidence.Address(end)
		}
		if end >= start {
			row.Cells["Length"] = evidence.Number(end - start)
		}
		if captured != nil {
			row.Cells["EntryRaw"] = evidence.Bytes(captured)
			row.Cells["Index"] = evidence.Number(uint64(len(captured)))
		}
		row.Cells["Error"] = evidence.Missing(reason, cause)
		return []evidence.Row{row}, "diagnostic", cause
	}
	start, err := e.Objects.Uint(ctx, mm, "mm_struct", "env_start")
	if err != nil {
		reason := "environment_range_unreadable"
		if errors.Is(err, object.ErrFieldAbsent) {
			reason = "environment_layout_unavailable"
		}
		return fail(reason, err, 0, 0, nil)
	}
	end, err := e.Objects.Uint(ctx, mm, "mm_struct", "env_end")
	if err != nil {
		return fail("environment_range_unreadable", err, start, 0, nil)
	}
	if end < start {
		return fail("invalid_environment_range", fmt.Errorf("environment end %#x precedes start %#x", end, start), start, end, nil)
	}
	size := end - start
	if size == 0 {
		row := base("diagnostic")
		row.Cells["MM"] = evidence.Address(mm)
		row.Cells["EnvStart"] = evidence.Address(start)
		row.Cells["EnvEnd"] = evidence.Address(end)
		row.Cells["Length"] = evidence.Number(0)
		row.Cells["Error"] = evidence.Missing("empty_environment_range", nil)
		return []evidence.Row{row}, "empty_environment", nil
	}
	if size > maxEnv {
		return fail("environment_size_limit", fmt.Errorf("environment range %d exceeds max-env=%d", size, maxEnv), start, end, nil)
	}
	layer, err := processMemory(ctx, e, process, mm, identity)
	if err != nil {
		return fail("process_address_space_unavailable", err, start, end, nil)
	}
	raw := make([]byte, int(size))
	got, err := layer.ReadAt(ctx, raw, start)
	if got < 0 || got > len(raw) {
		return fail("invalid_environment_read", fmt.Errorf("source returned an invalid byte count"), start, end, nil)
	}
	if err != nil || got != len(raw) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		rows, _, _ := fail("environment_buffer_unreadable", err, start, end, raw[:got])
		rows[0].Provenance.Layer = layer.Name()
		rows[0].Provenance.Offset = fmt.Sprintf("0x%x", start)
		rows[0].Cells["Index"] = evidence.Number(uint64(got))
		return rows, "diagnostic", err
	}
	parsed := bytes.TrimRight(raw, "\x00")
	if len(parsed) == 0 {
		row := base("diagnostic")
		row.Cells["MM"] = evidence.Address(mm)
		row.Cells["EnvStart"] = evidence.Address(start)
		row.Cells["EnvEnd"] = evidence.Address(end)
		row.Cells["Length"] = evidence.Number(size)
		row.Cells["Error"] = evidence.Missing("empty_environment", nil)
		row.Provenance.Layer = layer.Name()
		row.Provenance.Offset = fmt.Sprintf("0x%x", start)
		return []evidence.Row{row}, "empty_environment", nil
	}
	var rows []evidence.Row
	for index, part := range bytes.Split(parsed, []byte{0}) {
		key, value, ok := bytes.Cut(part, []byte{'='})
		if !ok {
			row := base("diagnostic")
			row.Cells["MM"] = evidence.Address(mm)
			row.Cells["EnvStart"] = evidence.Address(start)
			row.Cells["EnvEnd"] = evidence.Address(end)
			row.Cells["Length"] = evidence.Number(size)
			row.Cells["Index"] = evidence.Number(uint64(index))
			row.Cells["EntryRaw"] = evidence.Bytes(part)
			cause := fmt.Errorf("environment entry %d has no separator", index)
			row.Cells["Error"] = evidence.Missing("environment_entry_malformed", cause)
			row.Provenance.Layer = layer.Name()
			row.Provenance.Offset = fmt.Sprintf("0x%x", start)
			return append(rows, row), "diagnostic", cause
		}
		keyText, _ := replaceInvalidUTF8(key)
		valueText, _ := replaceInvalidUTF8(value)
		row := base("variable")
		row.Cells["MM"] = evidence.Address(mm)
		row.Cells["EnvStart"] = evidence.Address(start)
		row.Cells["EnvEnd"] = evidence.Address(end)
		row.Cells["Length"] = evidence.Number(size)
		row.Cells["Index"] = evidence.Number(uint64(index))
		row.Cells["Key"] = evidence.Text(keyText)
		row.Cells["Value"] = evidence.Text(valueText)
		row.Cells["KeyRaw"] = evidence.Bytes(key)
		row.Cells["ValueRaw"] = evidence.Bytes(value)
		row.Cells["EntryRaw"] = evidence.Bytes(part)
		row.Provenance.Layer = layer.Name()
		row.Provenance.Offset = fmt.Sprintf("0x%x", start)
		rows = append(rows, row)
	}
	return rows, "variable", nil
}

func linuxKThread(ctx context.Context, e plugin.Environment, process uint64) (bool, error) {
	if _, err := e.Objects.Field("task_struct", "flags"); err != nil {
		if errors.Is(err, object.ErrFieldAbsent) {
			return false, nil
		}
		return false, err
	}
	flags, err := e.Objects.Uint(ctx, process, "task_struct", "flags")
	if err != nil {
		return false, err
	}
	return flags&linuxPFKThread != 0, nil
}
