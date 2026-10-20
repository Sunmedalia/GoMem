package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsVadWalkPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.vadwalk", Upstream: "windows.vadwalk.VadWalk", Platform: "windows", NeedsKernel: true,
		Description: "Walk each active process VAD tree and report parent, child, and range links",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-process VAD and process traversal limit"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"},
			{Name: "Process", Kind: "string"},
			{Name: "Offset", Kind: "address"},
			{Name: "Parent", Kind: "address"},
			{Name: "Left", Kind: "address"},
			{Name: "Right", Kind: "address"},
			{Name: "Start", Kind: "address"},
			{Name: "End", Kind: "address"},
			{Name: "Tag", Kind: "string"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "ProcessIdentity", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsVadWalk}}
}

func windowsVadWalk(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.vadwalk requires a kernel layer and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	var processes, rowsOut, empty int
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		regions, err := windowsVADPaths(ctx, e, process, max)
		if err != nil {
			return fmt.Errorf("process %#x PID %d VAD walk: %w", process, pid, err)
		}
		if len(regions) == 0 {
			empty++
			return nil
		}
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		for _, region := range regions {
			rowsOut++
			row := evidence.Row{Cells: map[string]evidence.Value{
				"PID": evidence.Number(pid), "Process": evidence.Text(name),
				"Offset": evidence.Address(region.address), "Parent": evidence.Address(region.parent),
				"Left": evidence.Address(region.left), "Right": evidence.Address(region.right),
				"Start": evidence.Address(region.start), "End": evidence.Address(region.end),
				"Tag": evidence.Text(region.tag), "ProcessOffset": evidence.Address(process),
				"ProcessIdentity": evidence.Text(identity), "RecordType": evidence.Text("vad"),
				"Coverage": evidence.Missing("not_applicable", nil),
			}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", region.address)}}
			if err := out(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{
		"PID": evidence.Missing("not_applicable", nil), "Process": evidence.Missing("not_applicable", nil),
		"Offset": evidence.Missing("not_applicable", nil), "Parent": evidence.Missing("not_applicable", nil),
		"Left": evidence.Missing("not_applicable", nil), "Right": evidence.Missing("not_applicable", nil),
		"Start": evidence.Missing("not_applicable", nil), "End": evidence.Missing("not_applicable", nil),
		"Tag": evidence.Missing("not_applicable", nil), "ProcessOffset": evidence.Missing("not_applicable", nil),
		"ProcessIdentity": evidence.Missing("not_applicable", nil), "RecordType": evidence.Text("summary"),
		"Coverage": evidence.Value{Kind: "structure", Data: map[string]any{
			"processes": strconv.Itoa(processes),
			"rows":      strconv.Itoa(rowsOut),
			"empty":     strconv.Itoa(empty),
		}},
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: "0x0"}}
	return out(summary)
}
