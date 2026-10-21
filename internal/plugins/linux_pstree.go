package plugins

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxPsTreePlugins() []builtin {
	var columns []evidence.Column
	for _, name := range []string{"OFFSET (V)", "Offset", "ProcessOffset"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "address"})
	}
	for _, name := range []string{"PID", "TID", "PPID", "HierarchyParentTID", "Depth"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "uint64"})
	}
	columns = append(columns, evidence.Column{Name: "GeneratorDepth", Kind: "int64"})
	for _, name := range []string{"COMM", "TaskIdentity", "RecordType", "HierarchyState", "Error"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "string"})
	}
	columns = append(columns, evidence.Column{Name: "FieldEvidence", Kind: "structure"}, evidence.Column{Name: "Coverage", Kind: "structure"})
	return []builtin{{plugin.Spec{Name: "linux.pstree", Upstream: "linux.pstree.PsTree", Platform: "linux", NeedsKernel: true,
		Description: "Build the Linux parent PID hierarchy, with explicit thread ownership and retained task observations",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Comma-separated task-list PIDs to include before hierarchy construction; selected groups include threads when requested"}, {Name: "threads", Kind: "bool", Default: "false", Description: "Include selected groups' user threads"}, {Name: "decorate-comm", Kind: "bool", Default: "false", Description: "Bracket kernel names and brace user-thread names"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-list traversal bound, 1..1000000"}, {Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total candidate task bound, 1..1000000"}, {Name: "max-work", Kind: "uint", Default: "10000000", Description: "Total ancestor/child processing bound, 1..100000000"}}, Columns: columns}, linuxPsTree}}
}

type linuxTreeNode struct{ TID, TGID, PPID, Address uint64 }
type linuxTreeItem struct {
	TID, Depth     uint64
	GeneratorDepth int
	Parent         uint64
	HasParent      bool
}

// Mirror the pinned PID dictionary (last value, first insertion order), parent
// maps and sorted children. Work is bounded and traversal is iterative. Global
// seen rows stop each root's generator at its first duplicate, as upstream does.
func arrangeLinuxTree(ctx context.Context, input []linuxTreeNode, maxWork uint64) ([]linuxTreeItem, map[uint64]int, error) {
	nodes := map[uint64]linuxTreeNode{}
	var order []uint64
	for _, n := range input {
		if _, ok := nodes[n.TID]; !ok {
			order = append(order, n.TID)
		}
		nodes[n.TID] = n
	}
	levels := map[uint64]int{}
	children := map[uint64]map[uint64]bool{}
	var work uint64
	step := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if work >= maxWork {
			return fmt.Errorf("Linux hierarchy exceeds max-work %d", maxWork)
		}
		work++
		return nil
	}
	for _, tid := range order {
		seenParents, seenOffsets := map[uint64]bool{}, map[uint64]bool{}
		n, ok := nodes[tid]
		level := 0
		for ok {
			if err := step(); err != nil {
				return nil, levels, err
			}
			if n.TID == 0 {
				break
			}
			parent := n.PPID
			if n.TID != n.TGID {
				parent = n.TGID
			}
			if seenParents[parent] || seenOffsets[n.Address] || parent == 0 && n.TID > 2 {
				break
			}
			seenParents[parent], seenOffsets[n.Address] = true, true
			if children[parent] == nil {
				children[parent] = map[uint64]bool{}
			}
			children[parent][n.TID] = true
			n, ok = nodes[parent]
			level++
		}
		levels[tid] = level
	}
	sorted := map[uint64][]uint64{}
	for parent, entries := range children {
		for child := range entries {
			sorted[parent] = append(sorted[parent], child)
		}
		sort.Slice(sorted[parent], func(i, j int) bool { return sorted[parent][i] < sorted[parent][j] })
	}
	seen := map[uint64]bool{}
	var result []linuxTreeItem
	var previous []int
	for _, root := range order {
		if levels[root] != 1 {
			continue
		}
		stack := []uint64{root}
		for len(stack) > 0 {
			if err := step(); err != nil {
				return result, levels, err
			}
			tid := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[tid] {
				break
			}
			seen[tid] = true
			rawDepth := levels[tid] - 1
			item := linuxTreeItem{TID: tid, GeneratorDepth: rawDepth}
			index := min(len(previous), rawDepth)
			if index > 0 {
				parent := result[previous[index-1]]
				item.Parent, item.HasParent, item.Depth = parent.TID, true, parent.Depth+1
			}
			result = append(result, item)
			cut := index
			if cut < 0 {
				cut = max(0, len(previous)+cut)
			}
			previous = append(previous[:cut], len(result)-1)
			list := sorted[tid]
			for i := len(list) - 1; i >= 0; i-- {
				stack = append(stack, list[i])
			}
		}
	}
	return result, levels, nil
}

func linuxPsTree(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.pstree requires kernel memory and symbols")
	}
	maxNodes, pids, err := limits(p)
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
	maxWork, err := strconv.ParseUint(p["max-work"], 0, 64)
	if err != nil || maxWork == 0 || maxWork > 100000000 {
		return fmt.Errorf("max-work must be 1..100000000")
	}
	for _, member := range []string{"tasks", "pid", "tgid", "comm", "real_parent"} {
		if _, err := e.Objects.Field("task_struct", member); err != nil {
			return err
		}
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
	var candidates, diagnostics uint64
	var failures pluginFailures
	var outputErr error
	emit := func(r evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = out(r)
		return outputErr
	}
	base := func(address, leader uint64) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
		for _, c := range linuxPsTreePlugins()[0].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		r.Cells["OFFSET (V)"], r.Cells["Offset"], r.Cells["ProcessOffset"], r.Cells["RecordType"] = evidence.Address(address), evidence.Address(address), evidence.Address(leader), evidence.Text("observation")
		return r
	}
	var nodes []linuxTreeNode
	var observations []evidence.Row
	position := map[uint64]int{}
	seen := map[uint64]bool{}
	inspect := func(address, leader uint64) error {
		if seen[address] {
			return fmt.Errorf("task %#x appears in multiple groups", address)
		}
		if candidates >= maxTasks {
			return fmt.Errorf("task enumeration exceeds max-tasks %d", maxTasks)
		}
		seen[address] = true
		candidates++
		r := base(address, leader)
		fields := map[string]evidence.Value{}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		var first error
		issue := func(label string, cause error) {
			if cause == nil {
				return
			}
			failures.add(cause)
			if first == nil {
				first = cause
			}
			fields[label] = evidence.Missing(label, cause)
		}
		read := func(at uint64, member, label string) (uint64, error) {
			_, capture, err := linuxCaptureField(ctx, e, at, "task_struct", member)
			fields[label] = capture
			if err != nil {
				return 0, err
			}
			v, err := e.Objects.Uint(ctx, at, "task_struct", member)
			if err == nil {
				capture.Data.(map[string]evidence.Value)["Value"] = evidence.Number(v)
			}
			return v, err
		}
		tid, tidErr := read(address, "pid", "pid")
		tgid, tgidErr := read(address, "tgid", "tgid")
		if tidErr != nil || tgidErr != nil {
			issue("pid_unreadable", tidErr)
			issue("tgid_unreadable", tgidErr)
			r.Cells["RecordType"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("task_identity_unreadable", first)
			diagnostics++
			return emit(r)
		}
		r.Cells["TID"], r.Cells["PID"] = evidence.Number(tid), evidence.Number(tgid)
		if address != leader {
			owner, cause := read(leader, "tgid", "leader.tgid")
			if cause == nil && owner != tgid {
				cause = fmt.Errorf("thread %#x tgid %d differs from owner %d", address, tgid, owner)
			}
			if cause == nil {
				if _, lookupErr := e.Objects.Field("task_struct", "group_leader"); lookupErr == nil {
					var actual uint64
					actual, cause = read(address, "group_leader", "group_leader")
					if cause == nil && actual != leader {
						cause = fmt.Errorf("thread %#x has a different group leader", address)
					}
				}
			}
			if cause != nil {
				issue("thread_owner_invalid", cause)
				diagnostics++
				r.Cells["RecordType"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("thread_owner_invalid", cause)
				return emit(r)
			}
		}

		stamp := ""
		created := linuxStartTime(ctx, e, address)
		if created.Kind != "missing" {
			stamp = created.String()
		}
		r.Cells["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), address, tid, stamp))
		raw, capture, cause := linuxCaptureField(ctx, e, address, "task_struct", "comm")
		fields["comm"] = capture
		name := spoofDecoded(raw)
		r.Cells["COMM"] = evidence.Text(name)
		if cause != nil {
			issue("comm_unreadable", cause)
			if len(raw) == 0 {
				r.Cells["COMM"] = evidence.Missing("comm_unreadable", cause)
			}
		}
		parent, parentErr := read(address, "real_parent", "real_parent")
		var ppid uint64
		if parentErr != nil {
			issue("parent_pointer_unreadable", parentErr)
		} else if parent != 0 {
			cause = spoofReadable(ctx, e, parent, "task_struct")
			if cause != nil {
				issue("parent_extent_unreadable", cause)
			} else {
				ppid, cause = read(parent, "tgid", "real_parent.tgid")
				issue("parent_pid_unreadable", cause)
			}
		}
		r.Cells["PPID"] = evidence.Number(ppid)
		hierarchyParent := ppid
		if tid != tgid {
			hierarchyParent = tgid
		}
		r.Cells["HierarchyParentTID"] = evidence.Number(hierarchyParent)
		if decorate {
			flags, cause := read(address, "flags", "flags")
			if cause != nil {
				issue("flags_unreadable", cause)
				r.Cells["COMM"] = evidence.Missing("decoration_unavailable", cause)
			} else if flags&0x200000 != 0 && r.Cells["COMM"].Kind != "missing" {
				r.Cells["COMM"] = evidence.Text("[" + name + "]")
			} else if tid != tgid && r.Cells["COMM"].Kind != "missing" {
				r.Cells["COMM"] = evidence.Text("{" + name + "}")
			}
		}
		if first != nil {
			diagnostics++
			r.Cells["Error"] = evidence.Missing("tree_observation_incomplete", first)
		}
		if i, exists := position[tid]; exists {
			observations[i].Cells["HierarchyState"] = evidence.Text("replaced_duplicate_tid")
		}
		r.Cells["HierarchyState"] = evidence.Text("candidate")
		snapshot := r
		snapshot.Cells = copyEvidenceCells(r.Cells)
		if err := emit(snapshot); err != nil {
			return err
		}
		r.Cells["HierarchyState"] = evidence.Missing("not_applicable", nil)
		position[tid] = len(observations)
		nodes = append(nodes, linuxTreeNode{tid, tgid, ppid, address})
		observations = append(observations, r)
		return nil
	}
	err = e.Objects.WalkList(ctx, head, links.Offset, maxNodes, func(leader uint64) error {
		tid, err := e.Objects.Uint(ctx, leader, "task_struct", "pid")
		if err != nil {
			return err
		}
		if pids != nil && !pids[tid] {
			return nil
		}
		if err := inspect(leader, leader); err != nil {
			return err
		}
		if !threads {
			return nil
		}
		cause := linuxThreadAddresses(ctx, e, leader, maxNodes, func(task uint64) error {
			if task == leader {
				return nil
			}
			return inspect(task, leader)
		})
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if cause != nil {
			failures.add(cause)
			diagnostics++
			r := base(leader, leader)
			r.Cells["RecordType"], r.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("thread_enumeration_incomplete", cause)
			return emit(r)
		}
		return nil
	})
	// Observations were streamed before graph construction, so failed or
	// cancelled traversals retain the completed reads.
	if err != nil {
		return err
	}
	items, levels, arrangeErr := arrangeLinuxTree(ctx, nodes, maxWork)
	emitted := map[uint64]bool{}
	for _, item := range items {
		emitted[item.TID] = true
	}
	for i := range observations {
		r := observations[i]
		tid, _ := r.Cells["TID"].Uint()
		if r.Cells["HierarchyState"].Kind == "missing" {
			state := "not_root_reachable"
			if emitted[tid] {
				state = "included"
			}
			if arrangeErr != nil {
				state = "hierarchy_incomplete"
			}
			r.Cells["HierarchyState"] = evidence.Text(state)
		}
		selection := base(nodes[i].Address, 0)
		for _, name := range []string{"PID", "TID", "PPID", "TaskIdentity", "ProcessOffset", "HierarchyParentTID", "HierarchyState"} {
			selection.Cells[name] = r.Cells[name]
		}
		selection.Cells["RecordType"] = evidence.Text("selection")
		if err := emit(selection); err != nil {
			return err
		}
	}
	if arrangeErr != nil {
		return arrangeErr
	}
	for _, item := range items {
		r := observations[position[item.TID]]
		r.Cells = copyEvidenceCells(r.Cells)
		r.ID = fmt.Sprintf("linux-tree:%d", item.TID)
		if item.HasParent {
			r.ParentID = fmt.Sprintf("linux-tree:%d", item.Parent)
		}
		r.Cells["RecordType"], r.Cells["Depth"], r.Cells["GeneratorDepth"] = evidence.Text("process"), evidence.Number(item.Depth), evidence.Value{Kind: "int64", Data: strconv.Itoa(item.GeneratorDepth)}
		if err := emit(r); err != nil {
			return err
		}
	}
	r := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": poolCoverage(map[string]string{"candidates": formatCount(candidates), "distinct_tids": formatCount(uint64(len(position))), "tree_rows": formatCount(uint64(len(items))), "excluded_tids": formatCount(uint64(len(position) - len(items))), "duplicates": formatCount(uint64(len(nodes) - len(position))), "diagnostics": formatCount(diagnostics), "zero_level_tids": formatCount(countZeroLinuxLevels(levels))})}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}}
	if err := emit(r); err != nil {
		return err
	}
	return failures.err("Linux process hierarchy")
}

func countZeroLinuxLevels(levels map[uint64]int) uint64 {
	var count uint64
	for _, level := range levels {
		if level == 0 {
			count++
		}
	}
	return count
}
func copyEvidenceCells(source map[string]evidence.Value) map[string]evidence.Value {
	cells := make(map[string]evidence.Value, len(source))
	for k, v := range source {
		cells[k] = v
	}
	return cells
}
