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
		s := plugin.Spec{Name: os + ".pslist", Upstream: os + ".pslist.PsList", Platform: os, NeedsKernel: true, Description: "Enumerate the active process list using verified symbols; no pool scan or process extraction", Parameters: []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated PID filter"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Traversal safety limit"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "PID", Kind: "uint64"}, {Name: "PPID", Kind: "uint64"}, {Name: "Name", Kind: "string"}, {Name: "Created", Kind: "string"}, {Name: "DTB", Kind: "address"}, {Name: "Identity", Kind: "string"}}}
		fn := windowsProcesses
		if os == "linux" {
			fn = linuxProcesses
			s.Columns = []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "PID", Kind: "uint64"}, {Name: "PPID", Kind: "uint64"}, {Name: "Name", Kind: "string"}, {Name: "StartTimeNS", Kind: "uint64"}, {Name: "PGDVirtual", Kind: "address"}, {Name: "Identity", Kind: "string"}}
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
	return visitWindowsProcesses(ctx, e, max, pid, func(a, v uint64, name string, created evidence.Value) error {
		return out(processRow(e, a, v, name, optionalUint(ctx, e, a, "_EPROCESS", "InheritedFromUniqueProcessId", false), created, optionalUint(ctx, e, a, "_EPROCESS", "Pcb.DirectoryTableBase", true)))
	})
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
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	return visitLinuxProcesses(ctx, e, max, pids, func(a, v uint64, name string, created evidence.Value) error {
		ppid := evidence.Missing("unreadable_or_unavailable", nil)
		parent, err := e.Objects.Uint(ctx, a, "task_struct", "real_parent")
		if err == nil && parent != 0 {
			ppid = optionalUint(ctx, e, parent, "task_struct", "pid", false)
		} else if err != nil {
			ppid = evidence.Missing("unreadable_or_unavailable", err)
		}
		dtb := evidence.Missing("not_set", nil)
		mm, err := e.Objects.Uint(ctx, a, "task_struct", "mm")
		if err != nil {
			dtb = evidence.Missing("unreadable_or_unavailable", err)
		} else if mm != 0 {
			pgd, er := e.Objects.Uint(ctx, mm, "mm_struct", "pgd")
			if er != nil {
				dtb = evidence.Missing("unreadable_or_unavailable", er)
			} else {
				dtb = evidence.Address(pgd)
			}
		}
		row := processRow(e, a, v, name, ppid, created, dtb)
		// Linux pgd is a kernel virtual address, explicitly labeled to avoid passing it as CR3.
		row.Cells["DTB"] = evidence.Missing("use_PGDVirtual_to_resolve_physical_root", nil)
		row.Cells["PGDVirtual"] = dtb
		row.Cells["StartTimeNS"] = created
		row.Cells["Created"] = evidence.Missing("wall_clock_unavailable", nil)
		return out(row)
	})
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
