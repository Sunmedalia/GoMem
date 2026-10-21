package plugins

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxCheckCredsPlugins() []builtin {
	var columns []evidence.Column
	for _, g := range []struct{ kind, names string }{
		{"address", "CredVAddr ProcessOffset CredPointerAddress"}, {"uint64", "PID"},
		{"string", "PIDs ProcessIdentity RecordType"}, {"bytes", "CredRaw CredPointerRaw"},
		{"structure", "Members Coverage"}, {"string", "Error"},
	} {
		for _, name := range strings.Fields(g.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: g.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.check_creds", Upstream: "linux.malware.check_creds.Check_creds", Platform: "linux", NeedsKernel: true,
		Description: "Find active task-list entries sharing a readable cred object; retain per-task pointer evidence and skipped reads",
		Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Native task traversal bound"}}, Columns: columns}, linuxCheckCreds}}
}

func linuxCheckCreds(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.check_creds requires kernel memory and symbols")
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	credField, err := e.Objects.Field("task_struct", "cred")
	if err != nil || credField.Type.Kind != "pointer" {
		return fmt.Errorf("linux.check_creds requires task_struct.cred pointer: %v", err)
	}
	pointerSize, err := e.Objects.Size(credField.Type)
	if err != nil || pointerSize != 4 && pointerSize != 8 {
		return fmt.Errorf("invalid cred pointer width %d: %v", pointerSize, err)
	}
	credType, err := e.Symbols.Type("cred")
	if err != nil || credType.Size == 0 || credType.Size > 65536 {
		return fmt.Errorf("invalid cred extent %d (native bound 65536): %v", credType.Size, err)
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
	base := func(address uint64, kind string) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
		for _, c := range linuxCheckCredsPlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		if kind != "summary" {
			r.Provenance.Offset = fmt.Sprintf("0x%x", address)
		}
		r.Cells["RecordType"] = evidence.Text(kind)
		return r
	}
	type member struct {
		pid      uint64
		task     uint64
		identity string
	}
	groups := map[uint64][]member{}
	var order []uint64
	var processes, checked, diagnostics, shared uint64
	var failures pluginFailures
	err = e.Objects.WalkList(ctx, head, links.Offset, max, func(task uint64) error {
		processes++
		r := base(task, "process")
		r.Cells["ProcessOffset"] = evidence.Address(task)
		pid, err := e.Objects.Uint(ctx, task, "task_struct", "pid")
		if err != nil {
			return err
		}
		r.Cells["PID"] = evidence.Number(pid)
		stamp := ""
		created := linuxStartTime(ctx, e, task)
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, pid, stamp)
		r.Cells["ProcessIdentity"] = evidence.Text(identity)
		fail := func(stage string, cause error) error {
			diagnostics++
			failures.add(cause)
			r.Cells["RecordType"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing(stage, cause)
			return out(r)
		}
		pointerAddress, err := memory.Add(task, credField.Offset)
		if err != nil {
			return fail("credential_pointer_address_invalid", err)
		}
		r.Cells["CredPointerAddress"] = evidence.Address(pointerAddress)
		pointerRaw := make([]byte, int(pointerSize))
		pointerGot, pointerErr := e.Kernel.ReadAt(ctx, pointerRaw, pointerAddress)
		if pointerGot < 0 || pointerGot > len(pointerRaw) {
			return fail("credential_pointer_invalid_read", fmt.Errorf("invalid pointer capture length %d", pointerGot))
		}
		r.Cells["CredPointerRaw"] = evidence.Bytes(pointerRaw[:pointerGot])
		if pointerErr != nil || pointerGot != len(pointerRaw) {
			if pointerErr == nil {
				pointerErr = io.ErrUnexpectedEOF
			}
			return fail("credential_pointer_unreadable", pointerErr)
		}
		cred, err := e.Objects.Uint(ctx, task, "task_struct", "cred")
		if err != nil {
			return fail("credential_pointer_unreadable", err)
		}
		r.Cells["CredVAddr"] = evidence.Address(cred)
		if cred == 0 {
			return fail("credential_pointer_null", fmt.Errorf("task %#x has null cred", task))
		}
		raw := make([]byte, int(credType.Size))
		got, readErr := e.Kernel.ReadAt(ctx, raw, cred)
		if got < 0 || got > len(raw) {
			return fail("credential_invalid_read", fmt.Errorf("invalid credential capture length %d", got))
		}
		r.Cells["CredRaw"] = evidence.Bytes(raw[:got])
		if readErr != nil || got != len(raw) {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			return fail("credential_extent_unreadable", readErr)
		}
		checked++
		if _, ok := groups[cred]; !ok {
			order = append(order, cred)
		}
		groups[cred] = append(groups[cred], member{pid, task, identity})
		return out(r)
	})
	if err != nil {
		return err
	}
	for _, address := range order {
		if err := ctx.Err(); err != nil {
			return err
		}
		members := groups[address]
		if len(members) < 2 {
			continue
		}
		shared++
		r := base(address, "shared")
		r.Cells["CredVAddr"] = evidence.Address(address)
		pids := make([]string, 0, len(members))
		data := make([]map[string]evidence.Value, 0, len(members))
		for _, m := range members {
			pids = append(pids, formatCount(m.pid))
			data = append(data, map[string]evidence.Value{"PID": evidence.Number(m.pid), "ProcessOffset": evidence.Address(m.task), "ProcessIdentity": evidence.Text(m.identity)})
		}
		r.Cells["PIDs"], r.Cells["Members"] = evidence.Text(strings.Join(pids, ", ")), evidence.Value{Kind: "structure", Data: data}
		if err := out(r); err != nil {
			return err
		}
	}
	r := base(0, "summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"processes": formatCount(processes), "checked": formatCount(checked), "credential_objects": formatCount(uint64(len(groups))), "shared_groups": formatCount(shared), "diagnostics": formatCount(diagnostics)})
	if err := out(r); err != nil {
		return err
	}
	return failures.err("Linux credential sharing")
}
