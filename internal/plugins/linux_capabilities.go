package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// Names and order are locked to the baseline, including obsolete capabilities.
var linuxCapabilityNames = strings.Fields("chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read perfmon bpf checkpoint_restore")

func linuxCapabilityPlugins() []builtin {
	var columns []evidence.Column
	for _, g := range []struct{ kind, names string }{
		{"string", "Name cap_inheritable cap_permitted cap_effective cap_bounding cap_ambient ProcessIdentity RecordType"},
		{"uint64", "Tid Pid PPid EUID CapLast"}, {"address", "ProcessOffset Cred RealCred"},
		{"structure", "CapabilityEvidence KernelCapabilityEvidence Error Coverage"}, {"bytes", "NameRaw"},
	} {
		for _, name := range strings.Fields(g.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: g.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.capabilities", Upstream: "linux.capabilities.Capabilities", Platform: "linux", NeedsKernel: true,
		Description: "Read process credential capability sets, preserving raw masks, kernel limits and unavailable fields",
		Parameters:  []plugin.Parameter{{Name: "pids", Kind: "string", Description: "Optional comma-separated task.pid filter (upstream pids)"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Native task traversal bound"}}, Columns: columns}, linuxCapabilities}}
}

func linuxCapabilityMask(last uint64) uint64 {
	if last >= 63 {
		return ^uint64(0)
	}
	return uint64(1)<<(last+1) - 1
}
func linuxCapabilityText(raw, last uint64) string {
	value := raw & linuxCapabilityMask(last)
	if value == 0 {
		return ""
	}
	if last <= 63 && value == linuxCapabilityMask(last) {
		return "all"
	}
	var names []string
	for bit, name := range linuxCapabilityNames {
		if value&(uint64(1)<<bit) != 0 {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

func linuxCapabilityLimit(ctx context.Context, e plugin.Environment) (uint64, evidence.Value, error) {
	details := map[string]evidence.Value{}
	last := uint64(len(linuxCapabilityNames) - 1)
	s, err := e.Symbols.Lookup("cap_last_cap")
	if err != nil {
		// Absence is the pinned pre-3.2 fallback; an existing but unreadable
		// symbol never falls back to a guessed kernel mask.
		details["Source"] = evidence.Text("baseline_name_list_fallback")
	} else {
		address, err := e.Symbol("cap_last_cap")
		if err != nil {
			return 0, evidence.Value{}, err
		}
		if s.Type == nil || s.Type.Kind != "base" {
			return 0, evidence.Value{}, fmt.Errorf("cap_last_cap lacks a scalar base type")
		}
		t, err := e.Symbols.Type(s.Type.Name)
		if err != nil || t.Kind != "int" || t.Size != 4 || t.Endian != "little" && t.Endian != "big" {
			return 0, evidence.Value{}, fmt.Errorf("unsupported cap_last_cap layout: %v", err)
		}
		raw, err := memory.Read(ctx, e.Kernel, address, 4)
		if err != nil {
			return 0, evidence.Value{}, fmt.Errorf("cap_last_cap unreadable: %w", err)
		}
		var order binary.ByteOrder = binary.LittleEndian
		if t.Endian == "big" {
			order = binary.BigEndian
		}
		last = uint64(order.Uint32(raw))
		// More than the representable set is permitted (and cannot render
		// 'all'); bound corrupt values without an unbounded integer shift.
		if last > 4095 {
			return 0, evidence.Value{}, fmt.Errorf("cap_last_cap %d exceeds native sanity bound 4095", last)
		}
		details["Source"], details["Address"], details["Raw"] = evidence.Text("cap_last_cap"), evidence.Address(address), evidence.Bytes(raw)
	}
	details["Last"] = evidence.Number(last)
	details["Mask"] = evidence.Address(linuxCapabilityMask(last))
	details["NamesComplete"] = evidence.Bool(last < uint64(len(linuxCapabilityNames)))
	return last, evidence.Value{Kind: "structure", Data: details}, nil
}

func linuxReadCapability(ctx context.Context, e plugin.Environment, cred uint64, member string, last uint64) (evidence.Value, evidence.Value, error) {
	missing := func(err error) (evidence.Value, evidence.Value, error) {
		return evidence.Missing("capability_unreadable_or_unsupported", err), evidence.Missing("not_available", err), err
	}
	f, err := e.Objects.Field("cred", member)
	if err != nil || f.Type.Kind != "struct" && f.Type.Kind != "union" {
		return missing(fmt.Errorf("%s needs an embedded capability object: %v", member, err))
	}
	path, layout := member+".val", "u64_val"
	inner, err := e.Objects.Field("cred", path)
	if errors.Is(err, object.ErrFieldAbsent) {
		path, layout = member+".cap", "u32_cap"
		inner, err = e.Objects.Field("cred", path)
	}
	if err != nil {
		return missing(err)
	}
	scalar, words, width := inner.Type, uint64(1), uint64(4)
	if layout == "u64_val" {
		width = 8
	} else if inner.Type.Kind == "array" {
		if inner.Type.Subtype == nil || inner.Type.Count < 1 || inner.Type.Count > 2 {
			return missing(fmt.Errorf("%s has unsupported cap array", member))
		}
		scalar, words = *inner.Type.Subtype, inner.Type.Count
		layout = fmt.Sprintf("u32_cap_array_%d", words)
	}
	if scalar.Kind != "base" {
		return missing(fmt.Errorf("%s has a non-integer capability layout", member))
	}
	t, err := e.Symbols.Type(scalar.Name)
	if err != nil || t.Size != width || t.Signed || t.Kind != "int" || t.Endian != "little" && t.Endian != "big" {
		return missing(fmt.Errorf("%s has unsupported capability scalar: %v", member, err))
	}
	address, err := memory.Add(cred, inner.Offset)
	if err != nil {
		return missing(err)
	}
	raw := make([]byte, int(width*words))
	got, readErr := e.Kernel.ReadAt(ctx, raw, address)
	if got < 0 || got > len(raw) {
		return missing(fmt.Errorf("invalid capability read count %d", got))
	}
	details := map[string]evidence.Value{"Address": evidence.Address(address), "Layout": evidence.Text(layout), "Raw": evidence.Bytes(raw[:got]), "RequestedBytes": evidence.Number(uint64(len(raw))), "CapturedBytes": evidence.Number(uint64(got)), "ReadComplete": evidence.Bool(readErr == nil && got == len(raw))}
	if readErr != nil || got != len(raw) {
		if readErr == nil {
			readErr = io.ErrUnexpectedEOF
		}
		details["Error"] = evidence.Missing("capability_prefix_only", readErr)
		return evidence.Missing("capability_prefix_only", readErr), evidence.Value{Kind: "structure", Data: details}, readErr
	}
	var order binary.ByteOrder = binary.LittleEndian
	if t.Endian == "big" {
		order = binary.BigEndian
	}
	var value uint64
	if width == 8 {
		value = order.Uint64(raw)
	} else {
		value = uint64(order.Uint32(raw))
		if words == 2 {
			value |= uint64(order.Uint32(raw[4:])) << 32
		}
	}
	masked := value & linuxCapabilityMask(last)
	details["Unmasked"], details["Masked"] = evidence.Address(value), evidence.Address(masked)
	details["UnknownBits"] = evidence.Address(masked & ^linuxCapabilityMask(uint64(len(linuxCapabilityNames)-1)))
	return evidence.Text(linuxCapabilityText(value, last)), evidence.Value{Kind: "structure", Data: details}, nil
}

func linuxCapabilities(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.capabilities requires kernel memory and symbols")
	}
	max, pids, err := limits(map[string]string{"max-nodes": p["max-nodes"], "pid": p["pids"]})
	if err != nil {
		return err
	}
	last, kernelEvidence, err := linuxCapabilityLimit(ctx, e)
	if err != nil {
		return err
	}
	var failures pluginFailures
	var processes, sets, absentAmbient, diagnostics uint64
	base := func(task uint64, kind string) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
		for _, c := range linuxCapabilityPlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		if kind == "process" {
			r.Provenance.Offset = fmt.Sprintf("0x%x", task)
		}
		r.Cells["RecordType"], r.Cells["CapLast"], r.Cells["KernelCapabilityEvidence"] = evidence.Text(kind), evidence.Number(last), kernelEvidence
		return r
	}
	err = visitLinuxProcesses(ctx, e, max, pids, func(task, tid uint64, _ string, created evidence.Value) error {
		processes++
		r := base(task, "process")
		var issues []evidence.Value
		issue := func(stage string, cause error) {
			diagnostics++
			failures.add(cause)
			issues = append(issues, evidence.Missing(stage, cause))
		}
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		r.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, tid, stamp))
		r.Cells["ProcessOffset"], r.Cells["Tid"] = evidence.Address(task), evidence.Number(tid)
		r.Cells["Pid"] = optionalUint(ctx, e, task, "task_struct", "tgid", false)
		if r.Cells["Pid"].Error != "" {
			issue("task_tgid_unreadable", errors.New(r.Cells["Pid"].Error))
		}
		commField, err := e.Objects.Field("task_struct", "comm")
		if err != nil {
			return err
		}
		commSize, err := e.Objects.Size(commField.Type)
		if err != nil || commSize > 4096 || commSize == 0 {
			return fmt.Errorf("invalid comm size %d: %v", commSize, err)
		}
		commAddress, err := memory.Add(task, commField.Offset)
		if err != nil {
			return err
		}
		commRaw, err := memory.Read(ctx, e.Kernel, commAddress, int(commSize))
		if err != nil {
			return err
		}
		r.Cells["Name"], r.Cells["NameRaw"] = evidence.Text(spoofDecoded(commRaw)), evidence.Bytes(commRaw)
		parent, err := e.Objects.Uint(ctx, task, "task_struct", "real_parent")
		r.Cells["PPid"] = evidence.Number(0)
		if err != nil {
			issue("parent_pointer_unreadable", err)
		} else if parent != 0 {
			if err = spoofReadable(ctx, e, parent, "task_struct"); err != nil {
				issue("parent_object_unreadable", err)
			} else {
				r.Cells["PPid"] = optionalUint(ctx, e, parent, "task_struct", "tgid", false)
				if r.Cells["PPid"].Error != "" {
					issue("parent_tgid_unreadable", errors.New(r.Cells["PPid"].Error))
				}
			}
		}
		credentials := linuxCredentials(ctx, e, task)
		r.Cells["Cred"], r.Cells["EUID"] = credentials["Cred"], credentials["EUID"]
		if r.Cells["EUID"].Kind == "missing" {
			issue("effective_uid_unavailable", fmt.Errorf("%s: %s", r.Cells["EUID"].Reason, r.Cells["EUID"].Error))
		}
		realCred, err := e.Objects.Uint(ctx, task, "task_struct", "real_cred")
		if err == nil && realCred == 0 {
			err = fmt.Errorf("real_cred is null")
		}
		if err != nil {
			r.Cells["RealCred"] = evidence.Missing("real_cred_unavailable", err)
			for _, column := range []string{"cap_inheritable", "cap_permitted", "cap_effective", "cap_bounding", "cap_ambient", "CapabilityEvidence"} {
				r.Cells[column] = evidence.Missing("real_cred_unavailable", err)
			}
			issue("real_cred_unavailable", err)
		} else {
			r.Cells["RealCred"] = evidence.Address(realCred)
			captures := map[string]evidence.Value{}
			for _, pair := range []struct{ member, column string }{{"cap_inheritable", "cap_inheritable"}, {"cap_permitted", "cap_permitted"}, {"cap_effective", "cap_effective"}, {"cap_bset", "cap_bounding"}, {"cap_ambient", "cap_ambient"}} {
				if pair.member == "cap_ambient" {
					if _, fieldErr := e.Objects.Field("cred", pair.member); errors.Is(fieldErr, object.ErrFieldAbsent) {
						r.Cells[pair.column] = evidence.Missing("not_available", nil)
						absentAmbient++
						continue
					}
				}
				text, capture, cause := linuxReadCapability(ctx, e, realCred, pair.member, last)
				r.Cells[pair.column], captures[pair.column] = text, capture
				if cause != nil {
					issue(pair.member+"_unavailable", cause)
				} else {
					sets++
				}
			}
			r.Cells["CapabilityEvidence"] = evidence.Value{Kind: "structure", Data: captures}
		}
		if len(issues) > 0 {
			r.Cells["Error"] = evidence.Value{Kind: "structure", Data: issues}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return out(r)
	})
	if err != nil {
		return err
	}
	r := base(0, "summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"processes": formatCount(processes), "sets_read": formatCount(sets), "ambient_not_available": formatCount(absentAmbient), "diagnostics": formatCount(diagnostics)})
	if err = out(r); err != nil {
		return err
	}
	return failures.err("Linux process capabilities")
}
