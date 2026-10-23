package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxPIDHashPlugins() []builtin {
	var columns []evidence.Column
	for _, group := range []struct{ kind, names string }{
		{"address", "OFFSET PIDObject IndexObject Slot Parent"}, {"uint64", "PID TID PPID Index CreationCounterNS"},
		{"string", "COMM Layout TaskIdentity RecordType Status"}, {"bool", "Selected"},
		{"structure", "FieldEvidence Coverage"}, {"missing", "Error"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.pidhashtable", Upstream: "linux.pidhashtable.PIDHashTable", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate tasks through legacy PID hash buckets or namespace IDR with raw read evidence",
		Parameters: []plugin.Parameter{{Name: "decorate-comm", Kind: "bool", Default: "false", Description: "Decorate user/kernel thread names"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Total index node bound, 1..1000000"},
			{Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total PID candidate bound, 1..1000000"},
			{Name: "max-buckets", Kind: "uint", Default: "65536", Description: "Legacy hash bucket bound, 1..1000000"}}, Columns: columns}, linuxPIDHash}}
}

type linuxPIDIndex struct{ pid, object, slot, index uint64 }

func linuxPIDNamespaceIDR(e plugin.Environment) (symbols.Field, bool, error) {
	if _, err := e.Symbols.Type("pid_namespace"); err != nil {
		return symbols.Field{}, false, nil
	}
	field, err := e.Objects.Field("pid_namespace", "idr")
	if errors.Is(err, object.ErrFieldAbsent) {
		return field, false, nil
	}
	return field, err == nil, err
}

// The legacy reference subtracts numbers itself, even for nonzero namespace
// levels, and subtracts the task link field without a PIDTYPE_PID array stride.
// Keep these coordinates visible rather than guessing an alternate container.
func linuxPIDHashWalk(ctx context.Context, e plugin.Environment, maxNodes, maxTasks, maxBuckets uint64, emit func(linuxPIDIndex) error) (layout string, err error) {
	if field, modern, er := linuxPIDNamespaceIDR(e); er == nil && modern {
		layout = "namespace-idr"
		if field.Type.Kind != "struct" {
			return layout, fmt.Errorf("pid_namespace.idr is not embedded")
		}
		base, er := e.Symbol("init_pid_ns")
		if er != nil {
			return layout, er
		}
		root, er := memory.Add(base, field.Offset)
		if er != nil {
			return layout, er
		}
		_, er = walkLinuxIDR(ctx, e.Objects, root, maxNodes, maxTasks, func(entry linuxIDREntry) error {
			if entry.kind != "page" {
				return fmt.Errorf("tagged PID IDR entry %s at %#x", entry.kind, entry.slot)
			}
			return emit(linuxPIDIndex{entry.address, root, entry.slot, entry.id})
		})
		return layout, er
	} else if er != nil {
		return "", er
	}
	layout = "legacy-hash"
	chain, err := e.Objects.Field("upid", "pid_chain")
	if err != nil || chain.Type.Kind != "struct" {
		return layout, fmt.Errorf("unsupported upid.pid_chain layout: %v", err)
	}
	numbers, err := e.Objects.Field("pid", "numbers")
	if err != nil || numbers.Type.Kind != "array" || numbers.Type.Underlying() == nil || numbers.Type.Underlying().Kind != "struct" || numbers.Type.Underlying().Name != "upid" {
		return layout, fmt.Errorf("unsupported pid.numbers layout: %v", err)
	}
	shiftSym, err := e.Symbols.Lookup("pidhash_shift")
	if err != nil || shiftSym.Type == nil || shiftSym.Type.Kind != "base" {
		return layout, fmt.Errorf("pidhash_shift lacks scalar type: %v", err)
	}
	at, err := e.Symbol("pidhash_shift")
	if err != nil {
		return layout, err
	}
	shift, err := e.Objects.Scalar(ctx, at, *shiftSym.Type)
	if err != nil || shift > 20 || uint64(1)<<shift > maxBuckets {
		return layout, fmt.Errorf("invalid/excessive pidhash_shift %d: %v", shift, err)
	}
	hashSym, err := e.Symbols.Lookup("pid_hash")
	if err != nil || hashSym.Type == nil || hashSym.Type.Kind != "pointer" {
		return layout, fmt.Errorf("pid_hash lacks pointer type: %v", err)
	}
	at, err = e.Symbol("pid_hash")
	if err != nil {
		return layout, err
	}
	buckets, err := e.Objects.Scalar(ctx, at, *hashSym.Type)
	if err != nil || buckets == 0 {
		return layout, fmt.Errorf("pid_hash unavailable: %v", err)
	}
	headSize, err := e.Objects.Size(symbols.TypeRef{Kind: "struct", Name: "hlist_head"})
	if err != nil || headSize == 0 || headSize > 4096 {
		return layout, fmt.Errorf("invalid hash bucket extent: %v", err)
	}
	seen := map[uint64]bool{}
	var nodes, candidates uint64
	var failures pluginFailures
	var emitErr error
	for bucket := uint64(0); bucket < uint64(1)<<shift; bucket++ {
		if err := ctx.Err(); err != nil {
			return layout, err
		}
		head, er := memory.Add(buckets, bucket*headSize)
		if er != nil {
			return layout, er
		}
		er = e.Objects.WalkHList(ctx, head, chain.Offset, int(maxNodes), func(upid uint64) error {
			if seen[upid] {
				return fmt.Errorf("repeated upid across PID hash buckets at %#x", upid)
			}
			if nodes >= maxNodes || candidates >= maxTasks {
				return fmt.Errorf("PID index traversal bound exhausted")
			}
			seen[upid] = true
			nodes++
			candidates++
			if upid < numbers.Offset {
				return fmt.Errorf("PID container underflow")
			}
			slot, er := memory.Add(upid, chain.Offset)
			if er != nil {
				return er
			}
			emitErr = emit(linuxPIDIndex{upid - numbers.Offset, upid, slot, bucket})
			return emitErr
		})
		if emitErr != nil {
			return layout, emitErr
		}
		if er != nil {
			failures.add(er)
			if nodes >= maxNodes || candidates >= maxTasks {
				break
			}
		}
	}
	return layout, failures.err("PID hash traversal")
}

func linuxPIDHash(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	bound := func(name string) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 32)
		if err != nil || n == 0 || n > 1000000 {
			return 0, fmt.Errorf("%s must be 1..1000000", name)
		}
		return n, nil
	}
	maxNodes, err := bound("max-nodes")
	if err != nil {
		return err
	}
	maxTasks, err := bound("max-tasks")
	if err != nil {
		return err
	}
	maxBuckets, err := bound("max-buckets")
	if err != nil {
		return err
	}
	decorate, err := strconv.ParseBool(p["decorate-comm"])
	if err != nil {
		return err
	}
	choices, err := linuxEnumChoices(e, "pid_type", nil)
	if err != nil {
		return err
	}
	pidType, ok := choices["PIDTYPE_PID"]
	if !ok {
		return fmt.Errorf("PIDTYPE_PID enum unavailable")
	}
	tasks, err := e.Objects.Field("pid", "tasks")
	if err != nil || tasks.Type.Kind != "array" || tasks.Type.Underlying() == nil || tasks.Type.Underlying().Kind != "struct" || tasks.Type.Underlying().Name != "hlist_head" || pidType >= tasks.Type.Count {
		return fmt.Errorf("invalid pid.tasks/PIDTYPE_PID layout: %v", err)
	}
	stride, err := e.Objects.Size(*tasks.Type.Underlying())
	if err != nil || stride == 0 || stride > 4096 {
		return fmt.Errorf("invalid PID tasks stride: %v", err)
	}
	link, err := e.Objects.Field("task_struct", "pids")
	if errors.Is(err, object.ErrFieldAbsent) {
		link, err = e.Objects.Field("task_struct", "pid_links")
	}
	if err != nil {
		return err
	}
	if _, modern, er := linuxPIDNamespaceIDR(e); er != nil {
		return er
	} else if !modern {
		link, err = e.Objects.Field("task_struct", "pids")
		if err != nil {
			return err
		}
	}
	if link.Type.Kind != "array" || link.Type.Count <= pidType || link.Type.Underlying() == nil || link.Type.Underlying().Kind != "struct" {
		return fmt.Errorf("invalid task PID link array")
	}
	linkName := link.Type.Underlying().Name
	if linkName != "pid_link" && linkName != "hlist_node" {
		return fmt.Errorf("unsupported task PID link type %s", linkName)
	}
	taskType, err := e.Symbols.Type("task_struct")
	if err != nil || taskType.Size == 0 || taskType.Size > 1<<20 {
		return fmt.Errorf("invalid task extent: %v", err)
	}
	nodeType, err := e.Symbols.Type("hlist_node")
	if err != nil || nodeType.Size == 0 || nodeType.Size > 4096 {
		return fmt.Errorf("invalid hlist node extent: %v", err)
	}
	base := func(kind string, at uint64) evidence.Row {
		return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "OFFSET": evidence.Address(at), "Selected": evidence.Bool(false), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", at)}}
	}
	var reads, candidates, accepted, rejected uint64
	var outputErr error
	send := func(row evidence.Row) error {
		if outputErr != nil {
			return outputErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = out(row)
		return outputErr
	}
	trace := &linuxIDRLayer{MemoryLayer: e.Kernel}
	trace.observe = func(at uint64, raw []byte, want int, readErr error) error {
		reads++
		row := base("index_read", at)
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(readErr == nil)}
		if readErr != nil {
			proof["Error"] = evidence.Missing("read_failed", readErr)
			row.Cells["Error"] = proof["Error"]
		}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return send(row)
	}
	e.Kernel = trace
	e.Objects = &object.Reader{Layer: trace, Symbols: e.Symbols}
	var rows []evidence.Row
	var failures pluginFailures
	layout, walkErr := linuxPIDHashWalk(ctx, e, maxNodes, maxTasks, maxBuckets, func(index linuxPIDIndex) error {
		candidates++
		row := base("task_candidate", index.pid)
		row.Cells["PIDObject"], row.Cells["IndexObject"], row.Cells["Slot"], row.Cells["Index"] = evidence.Address(index.pid), evidence.Address(index.object), evidence.Address(index.slot), evidence.Number(index.index)
		fail := func(cause error) error {
			failures.add(cause)
			rejected++
			row.Cells["Error"] = evidence.Missing("candidate_incomplete", cause)
			return send(row)
		}
		at, er := memory.Add(index.pid, tasks.Offset+pidType*stride)
		if er != nil {
			return fail(er)
		}
		first, er := e.Objects.Uint(ctx, at, "hlist_head", "first")
		if er != nil {
			return fail(er)
		}
		if first == 0 {
			rejected++
			row.Cells["Status"] = evidence.Text("no_pid_task")
			return send(row)
		}
		if _, er = memory.Read(ctx, trace, first, int(nodeType.Size)); er != nil {
			return fail(er)
		}
		if first < link.Offset {
			return fail(fmt.Errorf("task container underflow"))
		}
		task := first - link.Offset
		row.Cells["OFFSET"] = evidence.Address(task)
		row.Provenance.Offset = fmt.Sprintf("0x%x", task)
		tid, er := e.Objects.Uint(ctx, task, "task_struct", "pid")
		if er != nil {
			return fail(er)
		}
		row.Cells["TID"] = evidence.Number(tid)
		if tid == 0 || tid > 1<<31-1 {
			rejected++
			row.Cells["Status"] = evidence.Text("invalid_tid")
			return send(row)
		}
		parent, er := e.Objects.Uint(ctx, task, "task_struct", "parent")
		if er != nil {
			return fail(er)
		}
		row.Cells["Parent"] = evidence.Address(parent)
		if _, er = memory.Read(ctx, trace, parent, int(taskType.Size)); er != nil {
			return fail(er)
		}
		tgid, er := e.Objects.Uint(ctx, task, "task_struct", "tgid")
		if er != nil {
			return fail(er)
		}
		row.Cells["PID"] = evidence.Number(tgid)
		rp, er := e.Objects.Uint(ctx, task, "task_struct", "real_parent")
		if er != nil {
			return fail(er)
		}
		ppid := uint64(0)
		if rp != 0 {
			if _, er = memory.Read(ctx, trace, rp, int(taskType.Size)); er != nil {
				return fail(er)
			}
			ppid, er = e.Objects.Uint(ctx, rp, "task_struct", "tgid")
			if er != nil {
				return fail(er)
			}
		}
		row.Cells["PPID"] = evidence.Number(ppid)
		name, er := e.Objects.String(ctx, task, "task_struct", "comm", 256)
		if er != nil {
			return fail(er)
		}
		decoded, _ := replaceInvalidUTF8([]byte(name))
		name, _, _ = strings.Cut(decoded, "\uFFFD")
		if decorate {
			flags, er := e.Objects.Uint(ctx, task, "task_struct", "flags")
			if er != nil {
				return fail(er)
			}
			if flags&0x00200000 != 0 {
				name = "[" + name + "]"
			} else if tid != tgid {
				name = "{" + name + "}"
			}
		}
		row.Cells["COMM"] = evidence.Text(name)
		stamp := evidence.Missing("field_not_available", nil)
		if _, er := e.Objects.Field("task_struct", "start_time"); er == nil {
			stamp = linuxStartTime(ctx, e, task)
			if stamp.Kind == "missing" {
				cause := fmt.Errorf("task creation counter unavailable: %s", stamp.String())
				failures.add(cause)
				row.Cells["Error"] = evidence.Missing("creation_counter_incomplete", cause)
			}
		} else if !errors.Is(er, object.ErrFieldAbsent) {
			return fail(er)
		}
		row.Cells["CreationCounterNS"] = stamp
		identityStamp := ""
		if stamp.Kind != "missing" {
			identityStamp = stamp.String()
		}
		row.Cells["TaskIdentity"] = evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), task, tid, identityStamp))
		accepted++
		rows = append(rows, row)
		return nil
	})
	if outputErr != nil {
		return outputErr
	}
	if trace.outputErr != nil {
		return trace.outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Stable tie order retains duplicate task objects reached through distinct
	// upids. The reference sorts by tgid/pid rather than deduplicating tasks.
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := rows[i].Cells["PID"].Uint()
		b, _ := rows[j].Cells["PID"].Uint()
		if a != b {
			return a < b
		}
		a, _ = rows[i].Cells["TID"].Uint()
		b, _ = rows[j].Cells["TID"].Uint()
		return a < b
	})
	for _, row := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		row.Cells["RecordType"], row.Cells["Selected"], row.Cells["Layout"] = evidence.Text("task"), evidence.Bool(true), evidence.Text(layout)
		if err := send(row); err != nil {
			return err
		}
	}
	runErr := errors.Join(walkErr, failures.err("PID candidates"))
	summary := base("index_summary", 0)
	summary.Cells["Layout"] = evidence.Text(layout)
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Reads": evidence.Number(reads), "Candidates": evidence.Number(candidates), "Tasks": evidence.Number(accepted), "Rejected": evidence.Number(rejected), "Completed": evidence.Bool(runErr == nil)}}
	if runErr != nil {
		summary.Cells["Error"] = evidence.Missing("index_incomplete", runErr)
	}
	return errors.Join(runErr, send(summary))
}
