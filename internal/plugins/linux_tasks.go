package plugins

import (
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

func linuxCredentials(ctx context.Context, e plugin.Environment, address uint64) map[string]evidence.Value {
	cells := map[string]evidence.Value{}
	cred, err := e.Objects.Uint(ctx, address, "task_struct", "cred")
	for _, field := range []string{"Cred", "UID", "GID", "EUID", "EGID"} {
		cells[field] = evidence.Missing("credential_pointer_unreadable", err)
	}
	if err != nil {
		return cells
	}
	cells["Cred"] = evidence.Address(cred)
	for _, name := range []string{"uid", "gid", "euid", "egid"} {
		key := strings.ToUpper(name)
		if cred == 0 {
			cells[key] = evidence.Missing("credential_not_set", nil)
			continue
		}
		field, err := e.Objects.Field("cred", name)
		if err != nil {
			cells[key] = evidence.Missing("credential_layout_unavailable", err)
			continue
		}
		path := name
		if field.Type.Kind == "struct" {
			path += ".val"
		}
		cells[key] = optionalUint(ctx, e, cred, "cred", path, false)
	}
	return cells
}

func linuxTaskRow(ctx context.Context, e plugin.Environment, task, leader, tid, tgid uint64, name string, start evidence.Value, identity string, decorate bool, clock linuxBootClock) evidence.Row {
	ppid := evidence.Number(0)
	parent, err := e.Objects.Uint(ctx, task, "task_struct", "real_parent")
	if err != nil {
		ppid = evidence.Missing("parent_pointer_unreadable", err)
	} else if parent != 0 {
		ppid = optionalUint(ctx, e, parent, "task_struct", "tgid", false)
	}
	pgd := evidence.Missing("not_set", nil)
	mm, err := e.Objects.Uint(ctx, task, "task_struct", "mm")
	if err != nil {
		pgd = evidence.Missing("mm_pointer_unreadable", err)
	} else if mm != 0 {
		pgd = optionalUint(ctx, e, mm, "mm_struct", "pgd", true)
	}
	row := processRow(e, task, tgid, name, ppid, start, pgd)
	c := row.Cells
	c["PhysicalLayer"] = evidence.Text(e.Physical.Name())
	c["PhysicalOffset"] = evidence.Missing("physical_translation_unavailable", nil)
	if layer, ok := e.Kernel.(*memory.Virtual); ok {
		mapping, er := layer.Translator.Translate(ctx, task)
		if er == nil {
			c["PhysicalOffset"] = evidence.Address(mapping.Physical)
		} else {
			c["PhysicalOffset"] = evidence.Missing("physical_translation_unavailable", er)
		}
	}
	c["DTB"] = evidence.Missing("use_PGDVirtual_to_resolve_physical_root", nil)
	c["PGDVirtual"], c["StartTimeNS"] = pgd, start
	c["Identity"], c["ProcessOffset"] = evidence.Text(identity), evidence.Address(leader)
	stamp := ""
	if start.Kind != "missing" {
		stamp = start.String()
	}
	c["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), task, tid, stamp))
	c["TID"], c["NameRaw"] = evidence.Number(tid), evidence.Text(name)
	c["RecordType"], c["Error"] = evidence.Text("task"), evidence.Missing("not_applicable", nil)
	if task != leader {
		c["RecordType"] = evidence.Text("thread")
	}
	for key, value := range linuxCredentials(ctx, e, task) {
		c[key] = value
	}
	counter, field := linuxCreationCounter(ctx, e, task)
	c["CreationCounterNS"], c["CreationCounterField"] = counter, evidence.Text(field)
	c["Created"], c["CreatedExact"], c["BootTime"], c["ClockProof"] = clock.apply(counter)
	c["Flags"] = optionalUint(ctx, e, task, "task_struct", "flags", false)
	flags, err := c["Flags"].Uint()
	if err != nil {
		c["IsKernelThread"], c["IsUserThread"] = c["Flags"], c["Flags"]
		if decorate {
			c["Name"] = evidence.Missing("decoration_flags_unavailable", fmt.Errorf("cannot classify task flags: %s", c["Flags"].String()))
			c["Error"] = c["Name"]
		}
	} else {
		kernel := flags&0x00200000 != 0 // PF_KTHREAD, not inferred from a null mm.
		user := !kernel && tid != tgid
		c["IsKernelThread"], c["IsUserThread"] = evidence.Value{Kind: "bool", Data: kernel}, evidence.Value{Kind: "bool", Data: user}
		if decorate && kernel {
			c["Name"] = evidence.Text("[" + name + "]")
		} else if decorate && user {
			c["Name"] = evidence.Text("{" + name + "}")
		}
	}
	return row
}

func linuxThreadAddresses(ctx context.Context, e plugin.Environment, leader uint64, max int, emit func(uint64) error) error {
	if _, err := e.Symbols.Type("signal_struct"); err == nil {
		if field, err := e.Objects.Field("signal_struct", "thread_head"); err == nil {
			signal, err := e.Objects.Uint(ctx, leader, "task_struct", "signal")
			if err != nil {
				return err
			}
			if signal == 0 {
				return fmt.Errorf("task signal pointer is not set")
			}
			head, err := memory.Add(signal, field.Offset)
			if err != nil {
				return err
			}
			link, err := e.Objects.Field("task_struct", "thread_node")
			if err != nil {
				return err
			}
			return e.Objects.WalkList(ctx, head, link.Offset, max, emit)
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return err
		}
	}
	link, err := e.Objects.Field("task_struct", "thread_group")
	if err != nil {
		return err
	}
	head, err := memory.Add(leader, link.Offset)
	if err != nil {
		return err
	}
	return e.Objects.WalkList(ctx, head, link.Offset, max, emit)
}

func linuxTaskListing(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	threads, err := strconv.ParseBool(p["threads"])
	if err != nil {
		return err
	}
	decorate, err := strconv.ParseBool(p["decorate-comm"])
	if err != nil {
		return err
	}
	maxTasks, err := strconv.ParseUint(p["max-tasks"], 0, 32)
	if err != nil || maxTasks == 0 || maxTasks > 1000000 {
		return fmt.Errorf("max-tasks must be 1..1000000")
	}
	clock := linuxClock(ctx, e)
	dump, layout, elfLimit, err := linuxELFOptions(p)
	if err != nil {
		return err
	}
	seen := map[uint64]bool{}
	var failures pluginFailures
	var outputErr error
	emit := func(row evidence.Row) error {
		row.Cells["FileOutput"], row.Cells["ELF"], row.Cells["ImageBase"] = evidence.Missing("not_requested", nil), evidence.Missing("not_requested", nil), evidence.Missing("not_requested", nil)
		if dump && row.Cells["RecordType"].String() != "diagnostic" {
			task, _ := row.Cells["Offset"].Uint()
			tid, _ := row.Cells["TID"].Uint()
			var er error
			row.Cells["FileOutput"], row.Cells["ELF"], row.Cells["ImageBase"], er = linuxMainELF(ctx, e, task, tid, row.Cells["Identity"].String(), layout, elfLimit, max)
			if er != nil {
				row.Cells["Error"] = evidence.Missing("main_elf_extraction_failed", er)
				if row.Cells["FileOutput"].Kind == "missing" {
					row.Cells["FileOutput"] = evidence.Missing("main_elf_extraction_failed", er)
				}
				failures.add(er)
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		outputErr = out(row)
		return outputErr
	}
	err = visitLinuxProcesses(ctx, e, max, pids, func(leader, tid uint64, name string, start evidence.Value) error {
		if seen[leader] {
			return fmt.Errorf("task appears in multiple task/thread groups")
		}
		if uint64(len(seen)) >= maxTasks {
			return fmt.Errorf("task traversal exceeds max-tasks")
		}
		seen[leader] = true
		tgid, err := e.Objects.Uint(ctx, leader, "task_struct", "tgid")
		if err != nil {
			return err
		}
		stamp := ""
		if start.Kind != "missing" {
			stamp = start.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), leader, tid, stamp)
		row := linuxTaskRow(ctx, e, leader, leader, tid, tgid, name, start, identity, decorate, clock)
		if decorate && row.Cells["Name"].Kind == "missing" {
			failures.add(fmt.Errorf("cannot decorate task %#x", leader))
		}
		if err := emit(row); err != nil || !threads {
			return err
		}
		err = linuxThreadAddresses(ctx, e, leader, max, func(task uint64) error {
			if task == leader {
				return nil
			}
			if seen[task] || uint64(len(seen)) >= maxTasks {
				return fmt.Errorf("duplicate task or max-tasks exceeded at %#x", task)
			}
			seen[task] = true
			owner, err := e.Objects.Uint(ctx, task, "task_struct", "tgid")
			if err != nil {
				return err
			}
			if owner != tgid {
				return fmt.Errorf("thread %#x tgid %d differs from owner %d", task, owner, tgid)
			}
			if _, err := e.Objects.Field("task_struct", "group_leader"); err == nil {
				object, err := e.Objects.Uint(ctx, task, "task_struct", "group_leader")
				if err != nil {
					return err
				}
				if object != leader {
					return fmt.Errorf("thread group_leader does not match owning object")
				}
			} else if !errors.Is(err, object.ErrFieldAbsent) {
				return err
			}
			tid, err := e.Objects.Uint(ctx, task, "task_struct", "pid")
			if err != nil {
				return err
			}
			comm, err := e.Objects.String(ctx, task, "task_struct", "comm", 64)
			if err != nil {
				return err
			}
			thread := linuxTaskRow(ctx, e, task, leader, tid, owner, comm, linuxStartTime(ctx, e, task), identity, decorate, clock)
			if decorate && thread.Cells["Name"].Kind == "missing" {
				failures.add(fmt.Errorf("cannot decorate thread %#x", task))
			}
			return emit(thread)
		})
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			failures.add(err)
			diagnostic := linuxTaskRow(ctx, e, leader, leader, tid, tgid, name, start, identity, false, clock)
			diagnostic.Cells["RecordType"], diagnostic.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("thread_enumeration_incomplete", err)
			return emit(diagnostic)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return failures.err("Linux task listing")
}
