package plugins

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxScanPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.psscan", Upstream: "linux.psscan.PsScan", Platform: "linux", NeedsKernel: true,
		Description: "Scan physical memory for scheduler-pointer task candidates, retaining explicit heuristic and scan coverage",
		Parameters:  []plugin.Parameter{{Name: "max-candidates", Kind: "uint", Default: "1000000", Description: "Maximum scheduler pointer hits (1..1000000)"}, {Name: "max-results", Kind: "uint", Default: "1000000", Description: "Maximum accepted task candidates (1..1000000)"}, {Name: "max-pid", Kind: "uint", Default: "65534", Description: "Largest accepted task.pid (1..4294967295); default matches the reference's pid < 65535 filter"}},
		Columns:     []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "PID", Kind: "uint64"}, {Name: "TID", Kind: "uint64"}, {Name: "Name", Kind: "string"}, {Name: "PPID", Kind: "uint64"}, {Name: "ExitState", Kind: "string"}, {Name: "ExitStateRaw", Kind: "uint64"}, {Name: "CommRaw", Kind: "bytes"}, {Name: "Parent", Kind: "address"}, {Name: "SchedClass", Kind: "address"}, {Name: "SchedClassNames", Kind: "structure"}, {Name: "StartTimeNS", Kind: "uint64"}, {Name: "TaskIdentity", Kind: "string"}, {Name: "PhysicalOffset", Kind: "address"}, {Name: "PhysicalLayer", Kind: "string"}, {Name: "OffsetSpace", Kind: "string"}, {Name: "HeuristicOnly", Kind: "bool"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "Scan", Kind: "structure"}}}, linuxPSScan}}
}

func linuxSchedClasses(e plugin.Environment) (map[uint64][]string, error) {
	width := e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return nil, fmt.Errorf("scheduler scan requires 32/64 bit pointers")
	}
	pointer, err := e.Symbols.Type("pointer")
	if err != nil || pointer.Endian != "" && pointer.Endian != "little" {
		return nil, fmt.Errorf("scheduler scan requires declared little-endian pointer symbols")
	}
	classes := map[uint64][]string{}
	matched := 0
	for _, name := range e.Symbols.Names() {
		if !strings.Contains(name, "_sched_class") {
			continue
		}
		matched++
		if matched > 4096 {
			return nil, fmt.Errorf("too many scheduler symbols, including aliases")
		}
		address, err := e.Symbol(name)
		if err != nil {
			return nil, err
		}
		// The pinned Intel64 symbol address space uses 48-bit addresses. Some
		// ISFs omit the sign extension; canonicalize only representable values.
		if width == 8 {
			upper := address >> 48
			if upper != 0 && (upper != 0xffff || address&(1<<47) == 0) {
				return nil, fmt.Errorf("noncanonical scheduling symbol %s", name)
			}
			address &= 0xffffffffffff
			if address&(1<<47) != 0 {
				address |= 0xffff000000000000
			}
		} else if address > 0xffffffff {
			return nil, fmt.Errorf("32-bit scheduling symbol %s exceeds address width", name)
		}
		if address == 0 {
			return nil, fmt.Errorf("zero scheduling symbol %s", name)
		}
		classes[address] = append(classes[address], name)
		if len(classes) > 4096 {
			return nil, fmt.Errorf("too many scheduler scan pointers")
		}
	}
	if len(classes) == 0 {
		return nil, fmt.Errorf("no _sched_class symbols; a scheduler-pointer scan cannot run")
	}
	return classes, nil
}

func linuxPSScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	bound := func(key string, maximum uint64) (uint64, error) {
		n, err := strconv.ParseUint(p[key], 0, 64)
		if err != nil || n == 0 || n > maximum {
			return 0, fmt.Errorf("%s must be 1..%d", key, maximum)
		}
		return n, nil
	}
	maxCandidates, err := bound("max-candidates", 1000000)
	if err != nil {
		return err
	}
	maxResults, err := bound("max-results", 1000000)
	if err != nil {
		return err
	}
	maxPID, err := bound("max-pid", 0xffffffff)
	if err != nil {
		return err
	}
	classes, err := linuxSchedClasses(e)
	if err != nil {
		return err
	}
	taskType, err := e.Symbols.Type("task_struct")
	if err != nil || taskType.Size == 0 || taskType.Size > memory.MaxRead {
		return fmt.Errorf("invalid or excessive task_struct size")
	}
	sched, err := e.Objects.Field("task_struct", "sched_class")
	if err != nil {
		return err
	}
	if sched.Type.Kind != "pointer" {
		return fmt.Errorf("task_struct.sched_class must be a pointer")
	}
	width, err := e.Objects.Size(sched.Type)
	if err != nil || width != uint64(e.Symbols.PointerSize()) {
		return fmt.Errorf("sched_class width differs from the symbol pointer width")
	}
	for _, field := range []string{"pid", "tgid", "exit_state", "comm", "real_parent"} {
		if _, err = e.Objects.Field("task_struct", field); err != nil {
			return err
		}
	}
	comm, err := e.Objects.Field("task_struct", "comm")
	if err != nil {
		return err
	}
	commSize, err := e.Objects.Size(comm.Type)
	if err != nil || comm.Type.Kind != "array" || commSize == 0 || commSize > 4096 {
		return fmt.Errorf("invalid task comm array")
	}
	reader := &object.Reader{Layer: e.Physical, Symbols: e.Symbols}
	physical := e
	physical.Objects = reader
	values := make([]uint64, 0, len(classes))
	for address := range classes {
		values = append(values, address)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	needles := make([]map[string]any, 0, len(values))
	for _, v := range values {
		needles = append(needles, map[string]any{"address": fmt.Sprintf("0x%x", v), "symbols": classes[v]})
	}
	var hits, accepted, rejectedState, rejectedPID, rejectedUnderflow, readFailures uint64
	var failures pluginFailures
	var outputErr error
	emit := func(row evidence.Row) error { outputErr = out(row); return outputErr }
	rowAt := func(address, value uint64) evidence.Row {
		row := evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(address), "PhysicalOffset": evidence.Address(address), "PhysicalLayer": evidence.Text(e.Physical.Name()), "OffsetSpace": evidence.Text("physical"), "SchedClass": evidence.Address(value), "SchedClassNames": {Kind: "structure", Data: classes[value]}, "HeuristicOnly": {Kind: "bool", Data: true}, "RecordType": evidence.Text("task"), "Error": evidence.Missing("not_applicable", nil), "Scan": evidence.Missing("summary_only", nil)}, Provenance: evidence.Provenance{Layer: e.Physical.Name(), Offset: fmt.Sprintf("0x%x", address)}}
		for _, key := range []string{"PID", "TID", "PPID", "Name", "ExitState", "ExitStateRaw", "CommRaw", "Parent", "StartTimeNS", "TaskIdentity"} {
			row.Cells[key] = evidence.Missing("not_reached", nil)
		}
		return row
	}
	err = memory.ScanPointers(ctx, e.Physical, values, e.Symbols.PointerSize(), func(hit, value uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		hits++
		if hits > maxCandidates {
			return fmt.Errorf("scheduler pointer scan exceeds max-candidates")
		}
		if hit < sched.Offset {
			rejectedUnderflow++
			return nil
		}
		address := hit - sched.Offset
		row := rowAt(address, value)
		diagnostic := func(cause error) error {
			readFailures++
			failures.add(cause)
			row.Cells["RecordType"], row.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("scan_candidate_unreadable", cause)
			return emit(row)
		}
		state, err := reader.Uint(ctx, address, "task_struct", "exit_state")
		if err != nil {
			return diagnostic(err)
		}
		names := map[uint64]string{0: "TASK_RUNNING", 16: "EXIT_DEAD", 32: "EXIT_ZOMBIE", 48: "EXIT_TRACE"}
		stateName, valid := names[state]
		if !valid {
			rejectedState++
			return nil
		}
		row.Cells["ExitState"], row.Cells["ExitStateRaw"] = evidence.Text(stateName), evidence.Number(state)
		tid, err := reader.Uint(ctx, address, "task_struct", "pid")
		if err != nil {
			return diagnostic(err)
		}
		if tid == 0 || tid > maxPID {
			rejectedPID++
			return nil
		}
		if accepted >= maxResults {
			return fmt.Errorf("task scan exceeds max-results")
		}
		accepted++
		row.Cells["TID"] = evidence.Number(tid)
		tgid, err := reader.Uint(ctx, address, "task_struct", "tgid")
		if err != nil {
			return diagnostic(err)
		}
		row.Cells["PID"] = evidence.Number(tgid)
		name, err := reader.String(ctx, address, "task_struct", "comm", int(commSize))
		if err != nil {
			return diagnostic(err)
		}
		row.Cells["Name"] = evidence.Text(name)
		location, err := memory.Add(address, comm.Offset)
		if err != nil {
			return diagnostic(err)
		}
		raw, err := memory.Read(ctx, e.Physical, location, int(commSize))
		if err != nil {
			return diagnostic(err)
		}
		row.Cells["CommRaw"] = evidence.Bytes(raw)
		parent, err := reader.Uint(ctx, address, "task_struct", "real_parent")
		if err != nil {
			return diagnostic(err)
		}
		row.Cells["Parent"], row.Cells["PPID"] = evidence.Address(parent), evidence.Number(0)
		if parent != 0 {
			ppid, err := e.Objects.Uint(ctx, parent, "task_struct", "tgid")
			if err != nil {
				readFailures++
				row.Cells["PPID"] = evidence.Missing("parent_unreadable", err)
				row.Cells["Error"] = row.Cells["PPID"]
				failures.add(err)
			} else {
				row.Cells["PPID"] = evidence.Number(ppid)
			}
		}
		start := linuxStartTime(ctx, physical, address)
		row.Cells["StartTimeNS"] = start
		stamp := ""
		if start.Kind != "missing" {
			stamp = start.String()
		}
		row.Cells["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Physical.Name(), address, tid, stamp))
		return emit(row)
	})
	if outputErr != nil {
		return outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	failures.add(err)
	summary := rowAt(0, 0)
	for key := range summary.Cells {
		summary.Cells[key] = evidence.Missing("summary_only", nil)
	}
	summary.Cells["RecordType"], summary.Cells["PhysicalLayer"] = evidence.Text("scan_summary"), evidence.Text(e.Physical.Name())
	coverage := []map[string]string{}
	for _, r := range e.Physical.Ranges() {
		coverage = append(coverage, map[string]string{"start": fmt.Sprintf("0x%x", r.Start), "length": strconv.FormatUint(r.Length, 10)})
	}
	summary.Cells["Scan"] = evidence.Value{Kind: "structure", Data: map[string]any{"complete": err == nil, "ranges": coverage, "needles": needles, "pointer_hits": strconv.FormatUint(hits, 10), "accepted_candidates": strconv.FormatUint(accepted, 10), "rejected_exit_state": strconv.FormatUint(rejectedState, 10), "rejected_pid": strconv.FormatUint(rejectedPID, 10), "rejected_underflow": strconv.FormatUint(rejectedUnderflow, 10), "candidate_read_failures": strconv.FormatUint(readFailures, 10), "assumption": "task_struct inline fields are physically contiguous; signature and PID/exit-state checks are heuristic"}}
	if err != nil {
		summary.Cells["Error"] = evidence.Missing("scan_incomplete", err)
	}
	summary.Provenance.Offset = ""
	if err := emit(summary); err != nil {
		return err
	}
	return failures.err("Linux physical task scan")
}
