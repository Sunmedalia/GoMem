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

func processPlugins() []builtin {
	var out []builtin
	for _, os := range []string{"windows", "linux"} {
		s := plugin.Spec{Name: os + ".pslist", Upstream: os + ".pslist.PsList", Platform: os, NeedsKernel: true, Description: "Enumerate the active process list using verified symbols", Parameters: []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated PID filter"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Traversal safety limit"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "PID", Kind: "uint64"}, {Name: "PPID", Kind: "uint64"}, {Name: "Name", Kind: "string"}, {Name: "Created", Kind: "string"}, {Name: "DTB", Kind: "address"}, {Name: "Identity", Kind: "string"}}}
		fn := windowsProcesses
		if os == "linux" {
			fn = linuxProcesses
			s.Parameters = append(s.Parameters, linuxELFParameters()...)
			s.Parameters = append(s.Parameters, plugin.Parameter{Name: "threads", Kind: "bool", Default: "false", Description: "Include threads of selected task-list entries"}, plugin.Parameter{Name: "decorate-comm", Kind: "bool", Default: "false", Description: "Bracket PF_KTHREAD names and brace user-thread names"}, plugin.Parameter{Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total process/thread traversal bound (1..1000000)"})
			s.Columns = []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "PID", Kind: "uint64"}, {Name: "PPID", Kind: "uint64"}, {Name: "Name", Kind: "string"}, {Name: "TID", Kind: "uint64"}, {Name: "NameRaw", Kind: "string"}, {Name: "UID", Kind: "uint64"}, {Name: "GID", Kind: "uint64"}, {Name: "EUID", Kind: "uint64"}, {Name: "EGID", Kind: "uint64"}, {Name: "Cred", Kind: "address"}, {Name: "Created", Kind: "string"}, {Name: "CreatedExact", Kind: "string"}, {Name: "CreationCounterNS", Kind: "uint64"}, {Name: "CreationCounterField", Kind: "string"}, {Name: "BootTime", Kind: "string"}, {Name: "ClockProof", Kind: "structure"}, {Name: "StartTimeNS", Kind: "uint64"}, {Name: "PGDVirtual", Kind: "address"}, {Name: "Identity", Kind: "string"}, {Name: "TaskIdentity", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "Flags", Kind: "uint64"}, {Name: "IsKernelThread", Kind: "bool"}, {Name: "IsUserThread", Kind: "bool"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "ImageBase", Kind: "address"}, {Name: "ELF", Kind: "structure"}, {Name: "FileOutput", Kind: "artifact"}}
		} else {
			s.Parameters = append(s.Parameters, plugin.Parameter{Name: "physical", Kind: "bool", Default: "false", Description: "Display physical object offsets; identity and provenance retain virtual addresses"}, plugin.Parameter{Name: "dump", Kind: "bool", Default: "false", Description: "Reconstruct main PE images through each process PEB"})
			s.Columns = append(s.Columns, []evidence.Column{{Name: "VirtualOffset", Kind: "address"}, {Name: "OffsetSpace", Kind: "string"}, {Name: "Threads", Kind: "uint64"}, {Name: "Handles", Kind: "uint64"}, {Name: "SessionId", Kind: "uint64"}, {Name: "Wow64", Kind: "bool"}, {Name: "CreatedRaw", Kind: "uint64"}, {Name: "Exited", Kind: "string"}, {Name: "ExitedRaw", Kind: "uint64"}, {Name: "ImageBase", Kind: "address"}, {Name: "FileOutput", Kind: "artifact"}, {Name: "Patches", Kind: "structure"}}...)
		}
		out = append(out, builtin{s, fn})
	}
	return out
}
func limits(p map[string]string) (int, map[uint64]bool, error) {
	n, e := strconv.ParseUint(p["max-nodes"], 0, 32)
	if e != nil || n < 1 || n > 1000000 {
		return 0, nil, fmt.Errorf("max-nodes must be 1..1000000")
	}
	var pid map[uint64]bool
	if p["pid"] != "" {
		pid = map[uint64]bool{}
		for _, token := range strings.Split(p["pid"], ",") {
			v, e := strconv.ParseUint(strings.TrimSpace(token), 0, 32)
			if e != nil {
				return 0, nil, fmt.Errorf("pid: %w", e)
			}
			pid[v] = true
		}
	}
	return int(n), pid, nil
}
func optionalUint(ctx context.Context, e plugin.Environment, a uint64, t, f string, address bool) evidence.Value {
	v, err := e.Objects.Uint(ctx, a, t, f)
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	if address {
		return evidence.Address(v)
	}
	return evidence.Number(v)
}
func processRow(e plugin.Environment, a, pid uint64, name string, ppid, created, dtb evidence.Value) evidence.Row {
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), a, pid, stamp)
	return evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "PID": evidence.Number(pid), "PPID": ppid, "Name": evidence.Text(name), "Created": created, "DTB": dtb, "Identity": evidence.Text(identity)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", a)}}
}
func windowsProcesses(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pid, e1 := limits(p)
	if e1 != nil {
		return e1
	}
	physical, err := strconv.ParseBool(p["physical"])
	if err != nil {
		return err
	}
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return err
	}
	var failures pluginFailures
	err = visitWindowsProcesses(ctx, e, max, pid, func(a, v uint64, name string, created evidence.Value) error {
		row := processRow(e, a, v, name, optionalUint(ctx, e, a, "_EPROCESS", "InheritedFromUniqueProcessId", false), created, optionalUint(ctx, e, a, "_EPROCESS", "Pcb.DirectoryTableBase", true))
		row.Cells["VirtualOffset"], row.Cells["OffsetSpace"] = evidence.Address(a), evidence.Text("kernel_virtual")
		if physical {
			row.Cells["OffsetSpace"] = evidence.Text("physical")
			var offset uint64
			var er error
			if layer, ok := e.Kernel.(*memory.Virtual); ok {
				mapping, err := layer.Translator.Translate(ctx, a)
				offset, er = mapping.Physical, err
			} else {
				er = fmt.Errorf("kernel translator is unavailable for physical offset")
			}
			row.Cells["Offset"] = evidence.Address(offset)
			if er != nil {
				row.Cells["Offset"] = evidence.Missing("physical_offset_unavailable", er)
				failures.add(er)
			}
		}
		row.Cells["Threads"] = optionalUint(ctx, e, a, "_EPROCESS", "ActiveThreads", false)
		row.Cells["Handles"] = windowsHandleCount(ctx, e, a)
		row.Cells["SessionId"] = windowsSessionID(ctx, e, a)
		row.Cells["Wow64"] = windowsIsWow64(ctx, e, a)
		_, row.Cells["CreatedRaw"] = windowsTime(ctx, e, a, "_EPROCESS", "CreateTime")
		row.Cells["Exited"], row.Cells["ExitedRaw"] = windowsTime(ctx, e, a, "_EPROCESS", "ExitTime")
		for _, key := range []string{"ImageBase", "FileOutput", "Patches"} {
			row.Cells[key] = evidence.Missing("not_requested", nil)
		}
		if dump {
			failures.add(dumpProcessPE(ctx, e, a, v, name, row))
		}
		return out(row)
	})
	if err != nil {
		return err
	}
	return failures.err("process analysis")
}
func visitWindowsProcesses(ctx context.Context, e plugin.Environment, max int, pid map[uint64]bool, emit func(uint64, uint64, string, evidence.Value) error) error {
	head, err := e.Symbol("PsActiveProcessHead")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return err
	}
	return e.Objects.WalkList(ctx, head, links.Offset, max, func(a uint64) error {
		v, err := e.Objects.Uint(ctx, a, "_EPROCESS", "UniqueProcessId")
		if err != nil {
			return err
		}
		if pid != nil && !pid[v] {
			return nil
		}
		name, err := e.Objects.String(ctx, a, "_EPROCESS", "ImageFileName", 64)
		if err != nil {
			return err
		}
		created, _ := windowsTime(ctx, e, a, "_EPROCESS", "CreateTime")
		return emit(a, v, name, created)
	})
}
func linuxProcesses(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	return linuxTaskListing(ctx, e, p, out)
}

func visitLinuxProcesses(ctx context.Context, e plugin.Environment, max int, pid map[uint64]bool, emit func(uint64, uint64, string, evidence.Value) error) error {
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
	return e.Objects.WalkList(ctx, head, links.Offset, max, func(a uint64) error {
		v, err := e.Objects.Uint(ctx, a, "task_struct", "pid")
		if err != nil {
			return err
		}
		if pid != nil && !pid[v] {
			return nil
		}
		name, err := e.Objects.String(ctx, a, "task_struct", "comm", 64)
		if err != nil {
			return err
		}
		return emit(a, v, name, linuxStartTime(ctx, e, a))
	})
}

func linuxStartTime(ctx context.Context, e plugin.Environment, a uint64) evidence.Value {
	f, err := e.Objects.Field("task_struct", "start_time")
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	if f.Type.Kind != "struct" {
		return optionalUint(ctx, e, a, "task_struct", "start_time", false)
	}
	sec, err := e.Objects.Uint(ctx, a, "task_struct", "start_time.tv_sec")
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	ns, err := e.Objects.Uint(ctx, a, "task_struct", "start_time.tv_nsec")
	if err != nil {
		return evidence.Missing("unreadable_or_unavailable", err)
	}
	if ns >= 1000000000 || sec > (^uint64(0)-ns)/1000000000 {
		return evidence.Missing("invalid_start_time", nil)
	}
	return evidence.Number(sec*1000000000 + ns)
}
