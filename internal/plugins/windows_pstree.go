package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsPsTreePlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.pstree", Upstream: "windows.pstree.PsTree", Platform: "windows", NeedsKernel: true,
		Description: "List active processes as a parent-process tree, including ancestors and descendants of a PID filter",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Comma-separated PIDs to keep, with their ancestors and descendants"},
			{Name: "physical", Kind: "bool", Default: "false", Description: "Show physical object offsets; identity stays on the virtual address"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active-list traversal bound"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"},
			{Name: "PPID", Kind: "uint64"},
			{Name: "ImageFileName", Kind: "string"},
			{Name: "Offset", Kind: "address"},
			{Name: "OffsetSpace", Kind: "string"},
			{Name: "Threads", Kind: "uint64"},
			{Name: "Handles", Kind: "uint64"},
			{Name: "SessionId", Kind: "uint64"},
			{Name: "Wow64", Kind: "bool"},
			{Name: "CreateTime", Kind: "string"},
			{Name: "ExitTime", Kind: "string"},
			{Name: "Audit", Kind: "string"},
			{Name: "Cmd", Kind: "string"},
			{Name: "Path", Kind: "string"},
			{Name: "Depth", Kind: "uint64"},
			{Name: "AuditError", Kind: "string"},
			{Name: "CmdError", Kind: "string"},
			{Name: "PathError", Kind: "string"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "ProcessIdentity", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsPsTree}}
}

// psTreeNode is one active process after duplicate PIDs collapse.
// Included is the pstree filter: an empty PID list includes every process.
type psTreeNode struct {
	Address  uint64
	PID      uint64
	PPID     uint64
	Name     string
	Included bool
}

// psTreeEmit is one row in Volatility TreeGrid order. Parent is set from the
// depth stack, which is the same parent the JSON renderer stores.
type psTreeEmit struct {
	PID       uint64
	Depth     int
	Parent    uint64
	HasParent bool
}

func windowsPsTree(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.pstree requires a kernel layer and symbols")
	}
	max, pidFilter, err := limits(p)
	if err != nil {
		return err
	}
	physical, err := strconv.ParseBool(p["physical"])
	if err != nil {
		return err
	}
	if _, err = e.Objects.Field("_RTL_USER_PROCESS_PARAMETERS", "CommandLine"); err != nil {
		return fmt.Errorf("windows.pstree command line layout: %w", err)
	}
	if _, err = e.Objects.Field("_RTL_USER_PROCESS_PARAMETERS", "ImagePathName"); err != nil {
		return fmt.Errorf("windows.pstree image path layout: %w", err)
	}
	if _, err = e.Objects.Field("_EPROCESS", "SeAuditProcessCreationInfo.ImageFileName"); err != nil {
		return fmt.Errorf("windows.pstree audit layout: %w", err)
	}
	if _, err = e.Objects.Field("_OBJECT_NAME_INFORMATION", "Name"); err != nil {
		return fmt.Errorf("windows.pstree audit name layout: %w", err)
	}
	nodes, err := collectPsTree(ctx, e, max, pidFilter)
	if err != nil {
		return err
	}
	arranged := arrangePsTree(nodes)
	byPID := make(map[uint64]psTreeNode, len(nodes))
	for _, node := range nodes {
		byPID[node.PID] = node
	}
	unavailableCmd := 0
	for _, item := range arranged {
		if err = ctx.Err(); err != nil {
			return err
		}
		node := byPID[item.PID]
		row, unavailable, err := psTreeRow(ctx, e, node, item, physical)
		if err != nil {
			return err
		}
		if unavailable {
			unavailableCmd++
		}
		if err = out(row); err != nil {
			return err
		}
	}
	summary := psTreeBlank(e, e.Kernel.Name(), "0x0")
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"processes":       strconv.Itoa(len(nodes)),
		"rows":            strconv.Itoa(len(arranged)),
		"unavailable_cmd": strconv.Itoa(unavailableCmd),
	}}
	return out(summary)
}

func collectPsTree(ctx context.Context, e plugin.Environment, max int, pidFilter map[uint64]bool) ([]psTreeNode, error) {
	position := map[uint64]int{}
	var nodes []psTreeNode
	err := visitWindowsProcesses(ctx, e, max, nil, func(address, pid uint64, name string, _ evidence.Value) error {
		ppid, err := e.Objects.Uint(ctx, address, "_EPROCESS", "InheritedFromUniqueProcessId")
		if err != nil {
			return fmt.Errorf("windows.pstree cannot read PPID of pid %d: %w", pid, err)
		}
		name = strings.ToValidUTF8(name, "\uFFFD")
		included := pidFilter == nil || pidFilter[pid]
		if i, ok := position[pid]; ok {
			nodes[i].Address = address
			nodes[i].PPID = ppid
			nodes[i].Name = name
			nodes[i].Included = included
			return nil
		}
		position[pid] = len(nodes)
		nodes = append(nodes, psTreeNode{Address: address, PID: pid, PPID: ppid, Name: name, Included: included})
		return nil
	})
	return nodes, err
}

// arrangePsTree follows windows.pstree.PsTree. Children stay in active-list
// order. The pinned plugin stores children in a Python set, whose iteration
// order is not the list order; parent links on a well-formed tree still match.
func arrangePsTree(nodes []psTreeNode) []psTreeEmit {
	index := make(map[uint64]psTreeNode, len(nodes))
	for _, node := range nodes {
		index[node.PID] = node
	}
	children := map[uint64][]uint64{}
	seenChild := map[uint64]map[uint64]bool{}
	addChild := func(parent, child uint64) {
		if seenChild[parent] == nil {
			seenChild[parent] = map[uint64]bool{}
		}
		if seenChild[parent][child] {
			return
		}
		seenChild[parent][child] = true
		children[parent] = append(children[parent], child)
	}
	ancestors := map[uint64]bool{}
	levels := map[uint64]int{}
	for _, node := range nodes {
		seen := map[uint64]bool{node.PID: true}
		current, ok := index[node.PID]
		level := 0
		for ok && !seen[current.PPID] {
			if node.Included {
				ancestors[current.PID] = true
			}
			addChild(current.PPID, current.PID)
			seen[current.PPID] = true
			current, ok = index[current.PPID]
			level++
		}
		levels[node.PID] = level
	}
	type pending struct {
		pid   uint64
		depth int
	}
	var pendingRows []pending
	visited := map[uint64]bool{}
	var walk func(pid uint64, descendant bool)
	walk = func(pid uint64, descendant bool) {
		if visited[pid] {
			return
		}
		visited[pid] = true
		if !ancestors[pid] && !descendant {
			return
		}
		pendingRows = append(pendingRows, pending{pid: pid, depth: levels[pid] - 1})
		next := descendant || index[pid].Included
		for _, child := range children[pid] {
			walk(child, next)
		}
	}
	for _, node := range nodes {
		if levels[node.PID] == 1 {
			walk(node.PID, false)
		}
	}
	prev := make([]uint64, 0, len(pendingRows))
	out := make([]psTreeEmit, 0, len(pendingRows))
	for _, item := range pendingRows {
		// TreeGrid uses Python min(len(prev), level). A negative level keeps
		// no parent and drops that many nodes from the end of the stack.
		if item.depth < 0 {
			cut := len(prev) + item.depth
			if cut < 0 {
				cut = 0
			}
			prev = append(prev[:cut], item.pid)
			out = append(out, psTreeEmit{PID: item.pid, Depth: item.depth})
			continue
		}
		parentIndex := len(prev)
		if item.depth < parentIndex {
			parentIndex = item.depth
		}
		emit := psTreeEmit{PID: item.pid, Depth: item.depth}
		if parentIndex > 0 {
			emit.HasParent = true
			emit.Parent = prev[parentIndex-1]
		}
		prev = append(prev[:parentIndex], item.pid)
		out = append(out, emit)
	}
	return out
}

func psTreeRow(ctx context.Context, e plugin.Environment, node psTreeNode, item psTreeEmit, physical bool) (evidence.Row, bool, error) {
	row := psTreeBlank(e, e.Kernel.Name(), fmt.Sprintf("0x%x", node.Address))
	row.ID = strconv.FormatUint(node.PID, 10)
	if item.HasParent {
		row.ParentID = strconv.FormatUint(item.Parent, 10)
	}
	threads, err := e.Objects.Uint(ctx, node.Address, "_EPROCESS", "ActiveThreads")
	if err != nil {
		return evidence.Row{}, false, fmt.Errorf("windows.pstree cannot read threads of pid %d: %w", node.PID, err)
	}
	created, err := psTreeTime(ctx, e, node.Address, "CreateTime")
	if err != nil {
		return evidence.Row{}, false, fmt.Errorf("windows.pstree cannot read create time of pid %d: %w", node.PID, err)
	}
	exited, err := psTreeTime(ctx, e, node.Address, "ExitTime")
	if err != nil {
		return evidence.Row{}, false, fmt.Errorf("windows.pstree cannot read exit time of pid %d: %w", node.PID, err)
	}
	wow := windowsIsWow64(ctx, e, node.Address)
	if wow.Kind == "missing" {
		return evidence.Row{}, false, fmt.Errorf("windows.pstree cannot read Wow64Process of pid %d: %s", node.PID, wow.Error)
	}
	offset := evidence.Address(node.Address)
	space := "kernel_virtual"
	if physical {
		space = "physical"
		layer, ok := e.Kernel.(*memory.Virtual)
		if !ok || layer.Translator == nil {
			return evidence.Row{}, false, fmt.Errorf("windows.pstree requires an Intel kernel layer for physical offsets")
		}
		mapping, err := layer.Translator.Translate(ctx, node.Address)
		if err != nil {
			return evidence.Row{}, false, fmt.Errorf("windows.pstree cannot translate pid %d: %w", node.PID, err)
		}
		offset = evidence.Address(mapping.Physical)
	}
	audit, auditErr := psTreeAudit(ctx, e, node.Address)
	cmd, path, cmdErr := psTreeCommand(ctx, e, node)
	stamp := ""
	if created.Kind == "string" {
		stamp = created.String()
	}
	row.Cells["RecordType"] = evidence.Text("process")
	row.Cells["PID"] = evidence.Number(node.PID)
	row.Cells["PPID"] = evidence.Number(node.PPID)
	row.Cells["ImageFileName"] = evidence.Text(node.Name)
	row.Cells["Offset"] = offset
	row.Cells["OffsetSpace"] = evidence.Text(space)
	row.Cells["Threads"] = evidence.Number(threads)
	row.Cells["Handles"] = psTreeHandles(ctx, e, node.Address)
	row.Cells["SessionId"] = psTreeSession(ctx, e, node.Address)
	row.Cells["Wow64"] = wow
	row.Cells["CreateTime"] = created
	row.Cells["ExitTime"] = exited
	row.Cells["Audit"] = audit
	row.Cells["Cmd"] = cmd
	row.Cells["Path"] = path
	if item.Depth < 0 {
		row.Cells["Depth"] = evidence.Missing("not_applicable", nil)
	} else {
		row.Cells["Depth"] = evidence.Number(uint64(item.Depth))
	}
	row.Cells["AuditError"] = auditErr
	row.Cells["CmdError"] = cmdErr
	row.Cells["PathError"] = cmdErr
	row.Cells["ProcessOffset"] = evidence.Address(node.Address)
	row.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID(e.ImageHash, e.Kernel.Name(), node.Address, node.PID, stamp))
	return row, cmd.Kind == "missing", nil
}

func psTreeTime(ctx context.Context, e plugin.Environment, process uint64, field string) (evidence.Value, error) {
	raw, err := windowsRawTime(ctx, e, process, "_EPROCESS", field)
	if err != nil {
		return evidence.Value{}, err
	}
	signed, err := quadSigned(e.Objects, "_EPROCESS", field)
	if err != nil {
		return evidence.Value{}, err
	}
	ticks, ok := interpretedTicks(raw, signed)
	if !ok {
		return evidence.Missing("unparsable", nil), nil
	}
	when, ok := volatilityFiletime(ticks)
	if !ok {
		if floorDivInt64(ticks, 10000000) == 0 {
			return evidence.Missing("not_applicable", nil), nil
		}
		return evidence.Missing("unparsable", nil), nil
	}
	return evidence.Text(when.UTC().Format("2006-01-02T15:04:05Z07:00")), nil
}

func psTreeHandles(ctx context.Context, e plugin.Environment, process uint64) evidence.Value {
	if _, err := e.Objects.Field("_EPROCESS", "ObjectTable"); err != nil {
		return evidence.Missing("unreadable", nil)
	}
	pointer, err := e.Objects.Uint(ctx, process, "_EPROCESS", "ObjectTable")
	if err != nil || pointer == 0 {
		return evidence.Missing("unreadable", nil)
	}
	if _, err = e.Objects.Field("_HANDLE_TABLE", "HandleCount"); err != nil {
		return evidence.Missing("unreadable", nil)
	}
	value, err := e.Objects.Uint(ctx, pointer, "_HANDLE_TABLE", "HandleCount")
	if err != nil {
		return evidence.Missing("unreadable", nil)
	}
	return evidence.Number(value)
}

func psTreeSession(ctx context.Context, e plugin.Environment, process uint64) evidence.Value {
	if _, err := e.Objects.Field("_EPROCESS", "Session"); err != nil {
		return evidence.Missing("unreadable", nil)
	}
	pointer, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Session")
	if err != nil {
		return evidence.Missing("unreadable", nil)
	}
	if pointer == 0 {
		return evidence.Missing("not_applicable", nil)
	}
	if _, err = e.Objects.Field("_MM_SESSION_SPACE", "SessionId"); err != nil {
		if !errors.Is(err, object.ErrFieldAbsent) {
			return evidence.Missing("unreadable", nil)
		}
		// Windows 11 24H2 exposes SessionId as an unsigned long at offset 8
		// when _MM_SESSION_SPACE.SessionId is absent from the PDB.
		value, readErr := readUintAt(ctx, e.Kernel, pointer+8, 4)
		if readErr != nil {
			return evidence.Missing("unreadable", nil)
		}
		return evidence.Number(value)
	}
	value, err := e.Objects.Uint(ctx, pointer, "_MM_SESSION_SPACE", "SessionId")
	if err != nil {
		return evidence.Missing("unreadable", nil)
	}
	return evidence.Number(value)
}

func psTreeAudit(ctx context.Context, e plugin.Environment, process uint64) (evidence.Value, evidence.Value) {
	pointer, err := e.Objects.Uint(ctx, process, "_EPROCESS", "SeAuditProcessCreationInfo.ImageFileName")
	if err != nil || pointer == 0 {
		return evidence.Missing("not_available", nil), evidence.Missing("not_available", err)
	}
	text, err := volatilityObjectString(ctx, e.Kernel, e.Objects, pointer, "_OBJECT_NAME_INFORMATION", "Name")
	if err != nil || text.Kind != "string" || text.String() == "" {
		reason := evidence.Missing("not_available", nil)
		detail := evidence.Missing("not_available", err)
		return reason, detail
	}
	if !utf8.ValidString(text.String()) {
		text = evidence.Text(strings.ToValidUTF8(text.String(), "\uFFFD"))
	}
	return text, evidence.Missing("not_applicable", nil)
}

func psTreeCommand(ctx context.Context, e plugin.Environment, node psTreeNode) (evidence.Value, evidence.Value, evidence.Value) {
	unavailable := evidence.Missing("not_available", nil)
	fail := func(err error) (evidence.Value, evidence.Value, evidence.Value) {
		return unavailable, unavailable, evidence.Missing("not_available", err)
	}
	peb, err := e.Objects.Uint(ctx, node.Address, "_EPROCESS", "Peb")
	if err != nil || peb == 0 {
		return fail(err)
	}
	stamp := ""
	layer, err := processMemory(ctx, e, node.Address, 0, evidence.ProcessID(e.ImageHash, e.Kernel.Name(), node.Address, node.PID, stamp))
	if err != nil {
		return fail(err)
	}
	reader := &object.Reader{Layer: layer, Symbols: e.Symbols}
	parameters, err := reader.Uint(ctx, peb, "_PEB", "ProcessParameters")
	if err != nil || parameters == 0 {
		return fail(err)
	}
	cmd, cmdErr := volatilityObjectString(ctx, layer, reader, parameters, "_RTL_USER_PROCESS_PARAMETERS", "CommandLine")
	path, pathErr := volatilityObjectString(ctx, layer, reader, parameters, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName")
	if cmdErr != nil || pathErr != nil || cmd.Kind != "string" || path.Kind != "string" {
		cause := cmdErr
		if cause == nil {
			cause = pathErr
		}
		return fail(cause)
	}
	return cmd, path, evidence.Missing("not_applicable", nil)
}

func psTreeBlank(e plugin.Environment, layer, offset string) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: offset}}
	for _, column := range windowsPsTreePlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	return row
}
