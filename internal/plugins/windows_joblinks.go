package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsJobLinkPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.joblinks", Upstream: "windows.joblinks.JobLinks", Platform: "windows", NeedsKernel: true,
		Description: "List processes that reference a job object and the processes linked from that job",
		Parameters: []plugin.Parameter{
			{Name: "physical", Kind: "bool", Default: "false", Description: "Show physical object offsets; identity stays on the virtual address"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active-list and job-link traversal bound"},
		},
		Columns: []evidence.Column{
			{Name: "Offset", Kind: "address"},
			{Name: "Name", Kind: "string"},
			{Name: "PID", Kind: "uint64"},
			{Name: "PPID", Kind: "uint64"},
			{Name: "Sess", Kind: "uint64"},
			{Name: "JobSess", Kind: "uint64"},
			{Name: "Wow64", Kind: "bool"},
			{Name: "Total", Kind: "uint64"},
			{Name: "Active", Kind: "uint64"},
			{Name: "Term", Kind: "uint64"},
			{Name: "JobLink", Kind: "string"},
			{Name: "Process", Kind: "string"},
			{Name: "OffsetSpace", Kind: "string"},
			{Name: "Depth", Kind: "uint64"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "ProcessIdentity", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsJobLinks}}
}

func windowsJobLinks(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.joblinks requires a kernel layer and symbols")
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	physical, err := strconv.ParseBool(p["physical"])
	if err != nil {
		return err
	}
	linkOffset, err := e.Objects.Field("_EPROCESS", "JobLinks")
	if err != nil {
		return err
	}
	headOffset, err := e.Objects.Field("_EJOB", "ProcessListHead")
	if err != nil {
		return err
	}
	var owners, members, skipped int
	var token int
	err = visitWindowsProcesses(ctx, e, max, nil, func(address, pid uint64, name string, _ evidence.Value) error {
		job, ok, cause := windowsJobPointer(ctx, e, address)
		if cause != nil {
			return cause
		}
		if !ok {
			skipped++
			return nil
		}
		owner, ok, cause := windowsJobOwner(ctx, e, address, pid, name, job, physical)
		if cause != nil {
			return cause
		}
		if !ok {
			skipped++
			return nil
		}
		ownerToken := strconv.Itoa(token)
		token++
		owner.ID = ownerToken
		owners++
		if err := out(owner); err != nil {
			return err
		}
		links, err := windowsJobMembers(ctx, e, job, headOffset.Offset, linkOffset.Offset, max)
		if err != nil {
			return err
		}
		for _, memberAddress := range links {
			row, ok, cause := windowsJobMember(ctx, e, memberAddress, physical)
			if cause != nil {
				return cause
			}
			if !ok {
				break
			}
			row.ID = strconv.Itoa(token)
			token++
			row.ParentID = ownerToken
			members++
			if err = out(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := jobLinkBlank(e, e.Kernel.Name(), "0x0")
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"owners":  strconv.Itoa(owners),
		"members": strconv.Itoa(members),
		"skipped": strconv.Itoa(skipped),
	}}
	return out(summary)
}

func windowsJobPointer(ctx context.Context, e plugin.Environment, process uint64) (uint64, bool, error) {
	if _, err := e.Objects.Field("_EPROCESS", "Job"); err != nil {
		return 0, false, err
	}
	pointer, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Job")
	if err != nil || pointer == 0 {
		return 0, false, nil
	}
	return pointer, true, nil
}

func windowsJobOwner(ctx context.Context, e plugin.Environment, process, pid uint64, name string, job uint64, physical bool) (evidence.Row, bool, error) {
	total, err := e.Objects.Uint(ctx, job, "_EJOB", "TotalProcesses")
	if err != nil {
		return evidence.Row{}, false, nil
	}
	active, err := e.Objects.Uint(ctx, job, "_EJOB", "ActiveProcesses")
	if err != nil {
		return evidence.Row{}, false, nil
	}
	terminated, err := e.Objects.Uint(ctx, job, "_EJOB", "TotalTerminatedProcesses")
	if err != nil {
		return evidence.Row{}, false, nil
	}
	jobSession, err := e.Objects.Uint(ctx, job, "_EJOB", "SessionId")
	if err != nil {
		return evidence.Row{}, false, nil
	}
	ppid, err := e.Objects.Uint(ctx, process, "_EPROCESS", "InheritedFromUniqueProcessId")
	if err != nil {
		return evidence.Row{}, false, nil
	}
	wow := windowsIsWow64(ctx, e, process)
	if wow.Kind != "bool" {
		return evidence.Row{}, false, nil
	}
	offset, space, ok := jobLinkOffset(ctx, e, process, physical)
	if !ok {
		return evidence.Row{}, false, nil
	}
	row := jobLinkBlank(e, e.Kernel.Name(), fmt.Sprintf("0x%x", process))
	row.Cells["RecordType"] = evidence.Text("owner")
	row.Cells["Offset"] = offset
	row.Cells["OffsetSpace"] = evidence.Text(space)
	row.Cells["Name"] = evidence.Text(strings.ToValidUTF8(name, "\uFFFD"))
	row.Cells["PID"] = evidence.Number(pid)
	row.Cells["PPID"] = evidence.Number(ppid)
	row.Cells["Sess"] = psTreeSession(ctx, e, process)
	row.Cells["JobSess"] = evidence.Number(jobSession)
	row.Cells["Wow64"] = wow
	row.Cells["Total"] = evidence.Number(total)
	row.Cells["Active"] = evidence.Number(active)
	row.Cells["Term"] = evidence.Number(terminated)
	row.Cells["JobLink"] = evidence.Missing("not_applicable", nil)
	row.Cells["Process"] = evidence.Text("(Original Process)")
	row.Cells["Depth"] = evidence.Number(0)
	row.Cells["ProcessOffset"] = evidence.Address(process)
	row.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, ""))
	return row, true, nil
}

func windowsJobMember(ctx context.Context, e plugin.Environment, process uint64, physical bool) (evidence.Row, bool, error) {
	name, err := e.Objects.String(ctx, process, "_EPROCESS", "ImageFileName", 64)
	if err != nil {
		return evidence.Row{}, false, nil
	}
	pid, err := e.Objects.Uint(ctx, process, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		return evidence.Row{}, false, nil
	}
	ppid, err := e.Objects.Uint(ctx, process, "_EPROCESS", "InheritedFromUniqueProcessId")
	if err != nil {
		return evidence.Row{}, false, nil
	}
	wow := windowsIsWow64(ctx, e, process)
	if wow.Kind != "bool" {
		return evidence.Row{}, false, nil
	}
	path, ok := windowsJobImagePath(ctx, e, process, pid)
	if !ok {
		return evidence.Row{}, false, nil
	}
	offset, space, ok := jobLinkOffset(ctx, e, process, physical)
	if !ok {
		return evidence.Row{}, false, nil
	}
	row := jobLinkBlank(e, e.Kernel.Name(), fmt.Sprintf("0x%x", process))
	row.Cells["RecordType"] = evidence.Text("member")
	row.Cells["Offset"] = offset
	row.Cells["OffsetSpace"] = evidence.Text(space)
	row.Cells["Name"] = evidence.Text(strings.ToValidUTF8(name, "\uFFFD"))
	row.Cells["PID"] = evidence.Number(pid)
	row.Cells["PPID"] = evidence.Number(ppid)
	row.Cells["Sess"] = psTreeSession(ctx, e, process)
	row.Cells["JobSess"] = evidence.Number(0)
	row.Cells["Wow64"] = wow
	row.Cells["Total"] = evidence.Number(0)
	row.Cells["Active"] = evidence.Number(0)
	row.Cells["Term"] = evidence.Number(0)
	row.Cells["JobLink"] = evidence.Text("Yes")
	row.Cells["Process"] = evidence.Text(path)
	row.Cells["Depth"] = evidence.Number(1)
	row.Cells["ProcessOffset"] = evidence.Address(process)
	row.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, ""))
	return row, true, nil
}

func windowsJobImagePath(ctx context.Context, e plugin.Environment, process, pid uint64) (string, bool) {
	peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
	if err != nil || peb == 0 {
		return "", false
	}
	layer, err := processMemory(ctx, e, process, 0, evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, ""))
	if err != nil {
		return "", false
	}
	reader := &object.Reader{Layer: layer, Symbols: e.Symbols}
	parameters, err := reader.Uint(ctx, peb, "_PEB", "ProcessParameters")
	if err != nil || parameters == 0 {
		return "", false
	}
	path, err := volatilityObjectString(ctx, layer, reader, parameters, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName")
	if err != nil || path.Kind != "string" {
		return "", false
	}
	return path.String(), true
}

func jobLinkOffset(ctx context.Context, e plugin.Environment, process uint64, physical bool) (evidence.Value, string, bool) {
	if !physical {
		return evidence.Address(process), "kernel_virtual", true
	}
	layer, ok := e.Kernel.(*memory.Virtual)
	if !ok || layer.Translator == nil {
		return evidence.Value{}, "", false
	}
	mapping, err := layer.Translator.Translate(ctx, process)
	if err != nil {
		return evidence.Value{}, "", false
	}
	return evidence.Address(mapping.Physical), "physical", true
}

// followForwardLinks walks a sentinel list head by Flink only. An unreadable
// link or object stops the walk. That is the pinned to_list stop, not a task
// failure. seen addresses are link addresses, including the head.
func followForwardLinks(head, linkOffset uint64, max int, next func(uint64) (uint64, bool), valid func(uint64) bool) []uint64 {
	if max < 1 {
		return nil
	}
	seen := map[uint64]bool{head: true}
	link, ok := next(head)
	if !ok {
		return nil
	}
	var out []uint64
	for !seen[link] && len(out) < max {
		seen[link] = true
		if link < linkOffset {
			break
		}
		objectAddress := link - linkOffset
		if !valid(objectAddress) {
			break
		}
		out = append(out, objectAddress)
		link, ok = next(link)
		if !ok {
			break
		}
	}
	return out
}

func windowsJobMembers(ctx context.Context, e plugin.Environment, job, headOffset, linkOffset uint64, max int) ([]uint64, error) {
	head, err := memory.Add(job, headOffset)
	if err != nil {
		return nil, nil
	}
	next := func(address uint64) (uint64, bool) {
		value, err := readUintAt(ctx, e.Kernel, address, e.Symbols.PointerSize())
		if err != nil {
			return 0, false
		}
		return value, true
	}
	valid := func(address uint64) bool {
		_, err := memory.Read(ctx, e.Kernel, address, 1)
		return err == nil
	}
	return followForwardLinks(head, linkOffset, max, next, valid), nil
}

func jobLinkBlank(e plugin.Environment, layer, offset string) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: offset}}
	for _, column := range windowsJobLinkPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	return row
}
