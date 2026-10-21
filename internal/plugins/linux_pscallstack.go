package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/kallsyms"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxPsCallStackPlugins() []builtin {
	columns := []evidence.Column{}
	for _, c := range []struct{ name, kind string }{{"TID", "uint64"}, {"Comm", "string"}, {"Position", "uint64"}, {"Address", "address"}, {"Value", "address"}, {"Name", "string"}, {"Type", "string"}, {"Module", "string"}, {"Task", "address"}, {"TaskIdentity", "string"}, {"RecordType", "string"}, {"FieldEvidence", "structure"}, {"Coverage", "structure"}, {"Error", "missing"}} {
		columns = append(columns, evidence.Column{Name: c.name, Kind: c.kind})
	}
	return []builtin{{plugin.Spec{Name: "linux.pscallstack", Upstream: "linux.pscallstack.PsCallStack", Platform: "linux", NeedsKernel: true, Description: "Scan task stack words for resident symbol addresses; not a frame unwinder", Columns: columns, Parameters: []plugin.Parameter{
		{Name: "pid", Kind: "string", Description: "Comma-separated leader task.pid filter; selected leaders include their threads"},
		{Name: "unresolved", Kind: "bool", Default: "false", Description: "Include nonzero unresolved stack words"},
		{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-list/source traversal and retained module object bound, 1..1000000"},
		{Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total selected task bound, 1..1000000"},
		{Name: "max-symbols", Kind: "uint", Default: "1000000", Description: "Core and retained module symbol bound, 1..10000000"},
		{Name: "max-words", Kind: "uint", Default: "1000000", Description: "Global scanned stack word bound, 1..100000000"},
		{Name: "max-bytes", Kind: "uint", Default: "536870912", Description: "Global virtual acquisition byte bound, 1..1073741824"},
	}}, linuxPsCallStack}}
}

type linuxCallStack struct {
	failures                                                         pluginFailures
	ctx                                                              context.Context
	e                                                                plugin.Environment
	out                                                              plugin.Emit
	resolver                                                         *kallsyms.Resolver
	mask, maxBytes, acquired, reads, words, maxWords, tasks, entries uint64
	outputErr                                                        error
}

func (s *linuxCallStack) emit(row evidence.Row) error {
	if s.outputErr != nil {
		return s.outputErr
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.outputErr = s.out(row)
	if s.outputErr == nil {
		s.outputErr = s.ctx.Err()
	}
	return s.outputErr
}
func (s *linuxCallStack) row(layer memory.MemoryLayer, at uint64, kind string) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind)}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", at)}}
}
func (s *linuxCallStack) trace(layer memory.MemoryLayer) *linuxIDRLayer {
	return &linuxIDRLayer{MemoryLayer: &kallsymsReadBudget{MemoryLayer: layer, remaining: func() uint64 { return s.maxBytes - s.acquired }}, observe: func(at uint64, raw []byte, want int, cause error) error {
		s.reads++
		s.acquired += uint64(len(raw))
		row := s.row(layer, at, "stack_read")
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(cause == nil), "ReadIndex": evidence.Number(s.reads)}
		if cause != nil {
			s.failures.add(cause)
			row.Cells["Error"] = evidence.Missing("read_failed", cause)
		}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return s.emit(row)
	}}
}
func linuxPsCallStack(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil || e.Physical == nil {
		return fmt.Errorf("pscallstack requires kernel, symbols and physical memory")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	unresolved, err := strconv.ParseBool(p["unresolved"])
	if err != nil {
		return err
	}
	vals := map[string]uint64{}
	for name, limit := range map[string]uint64{"max-tasks": 1000000, "max-symbols": 10000000, "max-words": 100000000, "max-bytes": 1 << 30} {
		n, er := strconv.ParseUint(p[name], 0, 64)
		if er != nil || n == 0 || n > limit {
			return fmt.Errorf("%s must be 1..%d", name, limit)
		}
		vals[name] = n
	}
	s := &linuxCallStack{ctx: ctx, e: e, out: out, mask: mask, maxBytes: vals["max-bytes"], maxWords: vals["max-words"]}
	// Keep e.Kernel's concrete translator available for per-process PGD translation.
	e.Objects = &object.Reader{Layer: s.trace(e.Kernel), Symbols: e.Symbols}
	s.e = e
	s.resolver, err = kallsyms.OpenResolver(ctx, e.Objects, e.KernelSlide, mask, kallsyms.ResolverLimits{Core: kallsyms.Limits{Symbols: vals["max-symbols"], Bytes: s.maxBytes, TokenBytes: 65536, NameBytes: 1 << 20}, NodesPerSource: max, ModuleSymbols: int(vals["max-symbols"])})
	if err != nil {
		return err
	}
	seen := map[uint64]bool{}
	task := func(at uint64) error {
		if seen[at] {
			return fmt.Errorf("task repeated across thread groups at %#x", at)
		}
		if s.tasks >= vals["max-tasks"] {
			return fmt.Errorf("task bound exhausted")
		}
		seen[at] = true
		s.tasks++
		er := s.task(at, unresolved)
		if s.outputErr != nil {
			return s.outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if er != nil {
			s.failures.add(er)
			row := s.row(e.Kernel, at, "diagnostic")
			row.Cells["Task"] = evidence.Address(at)
			row.Cells["Error"] = evidence.Missing("callstack_incomplete", er)
			return s.emit(row)
		}
		return nil
	}
	err = visitLinuxProcesses(ctx, e, max, pids, func(leader, _ uint64, _ string, _ evidence.Value) error {
		if er := task(leader); er != nil {
			return er
		}
		return linuxThreadAddresses(ctx, e, leader, max, func(at uint64) error {
			if at == leader {
				return nil
			}
			return task(at)
		})
	})
	if s.outputErr != nil {
		return s.outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		s.failures.add(err)
	}
	row := s.row(e.Kernel, 0, "stack_summary")
	row.Cells["Coverage"] = poolCoverage(map[string]string{"tasks": formatCount(s.tasks), "words": formatCount(s.words), "entries": formatCount(s.entries), "reads": formatCount(s.reads), "acquired_bytes": formatCount(s.acquired), "errors": strconv.Itoa(s.failures.count), "scope": "fixed 4-page stack word scan; not frame unwinding or complete task discovery"})
	failure := s.failures.err("Linux call stacks")
	if failure != nil {
		row.Cells["Error"] = evidence.Missing("callstacks_incomplete", failure)
	}
	if er := s.emit(row); er != nil {
		return er
	}
	return failure
}
func (s *linuxCallStack) task(at uint64, unresolved bool) (taskErr error) {
	e := s.e
	r := e.Objects
	typ, err := e.Symbols.Type("task_struct")
	if err != nil {
		return err
	}
	if typ.Size == 0 || typ.Size > memory.MaxRead {
		return fmt.Errorf("invalid task object extent")
	}
	if _, err = memory.Read(s.ctx, r.Layer, at, int(typ.Size)); err != nil {
		return err
	}
	tid, err := r.Uint(s.ctx, at, "task_struct", "pid")
	if err != nil {
		return err
	}
	if tid > 0x7fffffff {
		return fmt.Errorf("invalid signed task PID")
	}
	tgid, err := r.Uint(s.ctx, at, "task_struct", "tgid")
	if err != nil {
		return err
	}
	if tgid > 0x7fffffff {
		return fmt.Errorf("invalid signed task TGID")
	}
	name, err := r.String(s.ctx, at, "task_struct", "comm", 64)
	if err != nil {
		return err
	}
	counter, counterField := linuxCreationCounter(s.ctx, e, at)
	if counter.Kind == "missing" && counterField != "" {
		return fmt.Errorf("task creation counter: %s", counter.String())
	}
	stamp := ""
	if counter.Kind != "missing" {
		stamp = counter.String()
	}
	identity := evidence.ThreadID(e.ImageHash, e.Kernel.Name(), at, tid, stamp)
	firstWord, firstEntry := s.words, s.entries
	defer func() {
		if s.outputErr != nil || s.ctx.Err() != nil {
			return
		}
		row := s.row(e.Kernel, at, "task_stack_summary")
		row.Cells["Task"], row.Cells["TaskIdentity"], row.Cells["TID"], row.Cells["Comm"] = evidence.Address(at), evidence.Text(identity), evidence.Number(tid), evidence.Text(name)
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"CreationCounter": counter, "CreationCounterField": evidence.Text(counterField), "Completed": evidence.Bool(taskErr == nil), "WordsScanned": evidence.Number(s.words - firstWord), "Entries": evidence.Number(s.entries - firstEntry), "AcquisitionThrough": evidence.Number(s.reads)}}
		if taskErr != nil {
			row.Cells["Error"] = evidence.Missing("callstack_incomplete", taskErr)
		}
		taskErr = errors.Join(taskErr, s.emit(row))
	}()

	flags, err := r.Uint(s.ctx, at, "task_struct", "flags")
	if err != nil {
		return err
	}
	var layer memory.MemoryLayer = e.Kernel
	if flags&0x00200000 == 0 {
		mm, er := r.Uint(s.ctx, at, "task_struct", "mm")
		if er != nil {
			return er
		}
		if mm == 0 {
			return fmt.Errorf("user task has no address space")
		}
		layer, er = processMemory(s.ctx, e, at, mm, identity)
		if er != nil {
			return er
		}
	}
	// Intel baseline uses page_size << 2, independently of CONFIG_KASAN.
	base, err := r.Uint(s.ctx, at, "task_struct", "stack")
	if err != nil {
		return err
	}
	if e.Architecture == "x64" {
		base &= s.mask
		if base&(1<<47) != 0 {
			base |= ^s.mask
		}
	}
	top, err := memory.Add(base, 16384)
	if err != nil {
		return err
	}
	sp, err := r.Uint(s.ctx, at, "task_struct", "thread.sp")
	if err != nil {
		return err
	}
	if sp < base || sp >= top {
		return fmt.Errorf("invalid stack pointer %#x outside [%#x,%#x)", sp, base, top)
	}
	width := e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return fmt.Errorf("unsupported stack pointer width")
	}
	field, err := r.Field("task_struct", "files")
	if err != nil {
		return err
	}
	if field.Type.Kind != "pointer" {
		return fmt.Errorf("task files field is not a pointer")
	}
	// Only little-endian Intel is supported; symbols must agree with that ABI.
	pointer, err := e.Symbols.Type("pointer")
	if err != nil {
		return err
	}
	if pointer.Endian != "little" {
		return fmt.Errorf("unsupported stack pointer byte order %q", pointer.Endian)
	}
	trace := s.trace(layer)
	for index := uint64(0); sp < top; index++ {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if s.words >= s.maxWords {
			return fmt.Errorf("global stack word bound exhausted")
		}
		s.words++
		raw, er := memory.Read(s.ctx, trace, sp, width)
		if er != nil {
			return er
		}
		value := uint64(binary.LittleEndian.Uint32(raw))
		if width == 8 {
			value = binary.LittleEndian.Uint64(raw)
		}
		if value != 0 {
			resolution, er := s.resolver.Lookup(s.ctx, value)
			row := s.row(layer, sp, "stack_entry")
			row.Cells["Task"], row.Cells["TaskIdentity"] = evidence.Address(at), evidence.Text(identity)
			row.Cells["TID"], row.Cells["Comm"], row.Cells["Position"] = evidence.Number(tid), evidence.Text(name), evidence.Number(index)
			row.Cells["Address"], row.Cells["Value"] = evidence.Address(sp&s.mask), evidence.Address(value&s.mask)
			for _, k := range []string{"Name", "Type", "Module"} {
				row.Cells[k] = evidence.Missing("unresolved", nil)
			}
			if resolution.Symbol != nil {
				row.Cells["Name"] = evidence.Text(resolution.Symbol.Name)
				row.Cells["Type"] = evidence.Text(resolution.Symbol.Type)
				if resolution.Module != "" {
					row.Cells["Module"] = evidence.Text(resolution.Module)
				}
			}
			proof := map[string]evidence.Value{"Raw": evidence.Bytes(raw), "RawValue": evidence.Address(value), "StackBase": evidence.Address(base), "StackTop": evidence.Address(top), "InitialSP": evidence.Address(sp - index*uint64(width)), "Source": evidence.Text(resolution.Source), "Attempted": evidence.Text(strings.Join(resolution.Attempted, ",")), "AcquisitionThrough": evidence.Number(s.reads), "EvidenceScope": evidence.Text("all preceding task, stack and resident resolver acquisitions in this task")}
			proof["Resolution"] = callStackResolutionProof(resolution)
			row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
			if er != nil {
				row.Cells["RecordType"] = evidence.Text("stack_error")
				row.Cells["Error"] = evidence.Missing("symbol_resolution_failed", er)
				if outErr := s.emit(row); outErr != nil {
					return outErr
				}
				return er
			}
			if resolution.Symbol != nil || unresolved {
				if er := s.emit(row); er != nil {
					return er
				}
				s.entries++
			}
		}
		next, er := memory.Add(sp, uint64(width))
		if er != nil {
			return er
		}
		sp = next
	}
	return nil
}

func callStackResolutionProof(v kallsyms.Resolution) evidence.Value {
	fields := map[string]evidence.Value{"Source": evidence.Text(v.Source), "Attempted": evidence.Text(strings.Join(v.Attempted, ","))}
	unavailable := map[string]evidence.Value{}
	for k, cause := range v.Unavailable {
		unavailable[k] = evidence.Text(cause)
	}
	fields["Unavailable"] = evidence.Value{Kind: "structure", Data: unavailable}
	if m := v.ModuleSearch; m != nil {
		ranges := []evidence.Value{}
		for _, r := range m.Ranges {
			ranges = append(ranges, evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Object": evidence.Address(r.Object), "Start": evidence.Address(r.Start), "End": evidence.Address(r.End), "Available": evidence.Bool(r.Available), "Reversed": evidence.Bool(r.Reversed), "FirstRawValue": evidence.Address(r.FirstRawValue), "LastRawValue": evidence.Address(r.LastRawValue), "LastRawSize": evidence.Number(r.LastRawSize)}})
		}
		f := map[string]evidence.Value{"GlobalMin": evidence.Address(m.GlobalMin), "GlobalMax": evidence.Address(m.GlobalMax), "ListReused": evidence.Bool(m.ListReused), "TablesReused": evidence.Number(m.TablesReused), "SymbolsRead": evidence.Number(m.SymbolsRead), "ListVisited": evidence.Number(m.ListVisited), "Ranges": {Kind: "list", Data: ranges}, "Search": callStackTreeProof(m.Search)}
		if m.TreeModule != nil {
			f["TreeModule"] = evidence.Address(*m.TreeModule)
		}
		if match := m.Match; match != nil {
			for k, at := range map[string]uint64{"Object": match.Object, "Entry": match.Entry, "SymbolTable": match.SymbolTable, "StringTable": match.StringTable, "NameAddress": match.NameAddress, "RawABIValue": match.RawABIValue} {
				f[k] = evidence.Address(at)
			}
			f["Index"] = evidence.Number(match.Index)
			f["RawABISize"] = evidence.Number(match.RawABISize)
		}
		fields["ModuleSearch"] = evidence.Value{Kind: "structure", Data: f}
	}
	if b := v.BPF; b != nil {
		fields["BPF"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Object": evidence.Address(b.Object), "Program": evidence.Address(b.Program), "Aux": evidence.Address(b.Aux), "RegionStart": evidence.Address(b.RegionStart), "RegionEnd": evidence.Address(b.RegionEnd), "Layout": evidence.Text(b.Layout), "NameAvailable": evidence.Bool(b.NameAvailable), "Search": callStackTreeProof(b.Search)}}
	}
	if f := v.Ftrace; f != nil {
		fields["Ftrace"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Object": evidence.Address(f.Object), "Map": evidence.Address(f.Map), "ModuleObject": evidence.Address(f.ModuleObject), "NameAddress": evidence.Address(f.NameAddress), "Visited": evidence.Number(f.Visited), "Kind": evidence.Text(f.Kind)}}
	}
	if sym := v.Symbol; sym != nil {
		fields["Symbol"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Index": evidence.Number(sym.Index), "Address": evidence.Address(sym.Address), "Size": evidence.Number(sym.Size), "SizeAvailable": evidence.Bool(sym.SizeAvailable), "SizeStart": evidence.Address(sym.SizeStart), "SizeEnd": evidence.Address(sym.SizeEnd), "NameOffset": evidence.Number(sym.NameOffset), "NextOffset": evidence.Number(sym.NextOffset)}}
	}
	return evidence.Value{Kind: "structure", Data: fields}
}
func callStackTreeProof(v object.LatchMatch) evidence.Value {
	return evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Found": evidence.Bool(v.Found), "Node": evidence.Address(v.Node), "RBNode": evidence.Address(v.RBNode), "Sequence": evidence.Number(v.Sequence), "Index": evidence.Number(v.Index), "Visited": evidence.Number(v.Visited)}}
}
