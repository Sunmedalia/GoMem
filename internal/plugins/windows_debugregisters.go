package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsDebugRegisterPlugins() []builtin {
	spec := windowsSuspendedThreadPlugins()[0].spec
	spec.Name = "windows.debugregisters"
	spec.Upstream = "windows.debugregisters.DebugRegisters"
	spec.Description = "Enumerate saved nonzero debug registers with owner VADs, exact symbols and raw acquisition evidence"
	spec.Columns = nil
	for _, name := range []string{"Process", "Identity", "ProcessIdentity", "RecordType", "Error"} {
		spec.Columns = append(spec.Columns, evidence.Column{Name: name, Kind: "string"})
	}
	for _, name := range []string{"PID", "TID", "State", "Requested", "Captured"} {
		spec.Columns = append(spec.Columns, evidence.Column{Name: name, Kind: "uint64"})
	}
	for _, name := range []string{"Offset", "ProcessOffset", "TrapFrame", "Dr7", "Dr0", "Dr1", "Dr2", "Dr3"} {
		spec.Columns = append(spec.Columns, evidence.Column{Name: name, Kind: "address"})
	}
	for i := 0; i < 4; i++ {
		spec.Columns = append(spec.Columns, evidence.Column{Name: fmt.Sprintf("Range%d", i), Kind: "string"}, evidence.Column{Name: fmt.Sprintf("Symbol%d", i), Kind: "string"})
	}
	spec.Columns = append(spec.Columns, evidence.Column{Name: "Coverage", Kind: "structure"}, evidence.Column{Name: "Resolution", Kind: "structure"}, evidence.Column{Name: "Raw", Kind: "bytes"})
	return []builtin{{spec, windowsDebugRegisters}}
}

func windowsDebugRegisters(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
	bound := func(key string, max uint64) (uint64, error) {
		n, err := strconv.ParseUint(p[key], 0, 64)
		if err != nil || n == 0 || n > max {
			return 0, fmt.Errorf("%s must be 1..%d", key, max)
		}
		return n, nil
	}
	nodes, err := bound("max-nodes", 1000000)
	if err != nil {
		return err
	}
	threads, err := bound("max-threads", 1000000)
	if err != nil {
		return err
	}
	regions, err := bound("max-regions", 1000000)
	if err != nil {
		return err
	}
	bytes, err := bound("max-read-bytes", 1<<30)
	if err != nil {
		return err
	}
	symbols, err := bound("max-symbols", 10000000)
	if err != nil {
		return err
	}
	a := &windowsSymbolAnalysis{ctx: ctx, env: e, out: out, maxNodes: int(nodes), maxThreads: int(threads), maxRegions: int(regions), maxBytes: bytes, maxSymbols: symbols, vads: map[uint64][]windowsVADPath{}, modules: map[string][]pesymbols.Module{}, resolvers: map[string]*pesymbols.Resolver{}}
	a.env.Kernel = windowsSymbolLayer{MemoryLayer: e.Kernel, analysis: a, metadata: true}
	a.env.Objects = &object.Reader{Layer: a.env.Kernel, Symbols: e.Symbols}
	defer func() {
		err = errors.Join(err, errors.Join(a.failures...))
		if a.stop != nil || ctx.Err() != nil {
			err = errors.Join(err, a.stop, ctx.Err())
			return
		}
		a.coverage.Complete = err == nil
		err = errors.Join(err, a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": {Kind: "structure", Data: a.coverage}}}))
	}()
	headField, err := a.env.Objects.Field("_EPROCESS", "ThreadListHead")
	if err != nil {
		return err
	}
	link, err := a.env.Objects.Field("_ETHREAD", "ThreadListEntry")
	if err != nil {
		return err
	}
	trapField, err := a.env.Objects.Field("_ETHREAD", "Tcb.TrapFrame")
	if err != nil {
		return err
	}
	if trapField.Type.Kind != "pointer" || trapField.Type.Subtype == nil || trapField.Type.Subtype.Name == "" {
		return fmt.Errorf("Tcb.TrapFrame requires a typed pointer")
	}
	trapType := trapField.Type.Subtype.Name
	return visitWindowsProcesses(ctx, a.env, a.maxNodes, nil, func(process, pid uint64, name string, created evidence.Value) error {
		head, err := memory.Add(process, headField.Offset)
		if err != nil {
			return err
		}
		return a.env.Objects.WalkList(ctx, head, link.Offset, a.maxThreads, func(thread uint64) error {
			if a.coverage.Threads >= uint64(a.maxThreads) {
				return fmt.Errorf("total thread limit exhausted")
			}
			a.coverage.Threads++
			cause := a.debugThread(thread, trapType)
			if cause != nil {
				if a.stop != nil || ctx.Err() != nil {
					return errors.Join(cause, a.stop, ctx.Err())
				}
				a.failure(fmt.Errorf("thread %#x: %w", thread, cause))
			}
			return nil
		})
	})
}

func (a *windowsSymbolAnalysis) debugThread(thread uint64, trapType string) error {

	trap, err := a.env.Objects.Uint(a.ctx, thread, "_ETHREAD", "Tcb.TrapFrame")
	if err != nil {
		return err
	}
	dr7, err := a.env.Objects.Uint(a.ctx, trap, trapType, "Dr7")
	if err != nil {
		return err
	}
	state, err := a.env.Objects.Uint(a.ctx, thread, "_ETHREAD", "Tcb.State")
	if err != nil {
		return err
	}
	if state == 4 {
		a.coverage.Terminated++
		return nil
	}
	if dr7 == 0 {
		return nil
	}
	owner, err := threadOwnerAddress(a.ctx, a.env.Objects, thread)
	if err != nil {
		return err
	}
	var regs [4]uint64
	for i := range regs {
		regs[i], err = a.env.Objects.Uint(a.ctx, trap, trapType, fmt.Sprintf("Dr%d", i))
		if err != nil {
			return err
		}
	}
	if regs == [4]uint64{} {
		return nil
	}
	files, err := a.processVADs(owner)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		a.coverage.NoFileVADs++
		return nil
	}
	mapped := false
	for _, address := range regs {
		if suspendedFileAt(files, address).Kind == "string" {
			mapped = true
		}
	}
	if !mapped {
		return nil
	}
	ownerName, err := a.env.Objects.String(a.ctx, owner, "_EPROCESS", "ImageFileName", 64)
	if err != nil {
		return err
	}
	ownerPID, err := a.env.Objects.Uint(a.ctx, owner, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		return err
	}
	tid, err := a.env.Objects.Uint(a.ctx, thread, "_ETHREAD", "Cid.UniqueThread")
	if err != nil {
		return err
	}
	ownerCreated, _ := windowsTime(a.ctx, a.env, owner, "_EPROCESS", "CreateTime")
	_, threadCreated := windowsTime(a.ctx, a.env, thread, "_ETHREAD", "CreateTime")
	cells := map[string]evidence.Value{
		"RecordType": evidence.Text("thread"), "Process": evidence.Text(ownerName), "PID": evidence.Number(ownerPID), "TID": evidence.Number(tid), "State": evidence.Number(state),
		"Dr7": evidence.Address(dr7), "TrapFrame": evidence.Address(trap), "Offset": evidence.Address(thread), "ProcessOffset": evidence.Address(owner),
		"ProcessIdentity": evidence.Text(evidence.ProcessID(a.env.ImageHash, a.env.Kernel.Name(), owner, ownerPID, identityTime(ownerCreated))),
		"Identity":        evidence.Text(evidence.ThreadID(a.env.ImageHash, a.env.Kernel.Name(), thread, tid, identityTime(threadCreated))),
	}
	resolutions := map[string]evidence.Value{}
	var resolutionErr error
	for i, address := range regs {
		path, symbol, detail, cause := a.resolve(files, address)
		resolutionErr = errors.Join(resolutionErr, cause)
		cells[fmt.Sprintf("Dr%d", i)] = evidence.Address(address)
		cells[fmt.Sprintf("Range%d", i)] = path
		cells[fmt.Sprintf("Symbol%d", i)] = symbol
		resolutions[fmt.Sprintf("Dr%d", i)] = detail
		if a.stop != nil {
			return a.stop
		}
	}
	cells["Resolution"] = evidence.Value{Kind: "structure", Data: resolutions}
	cells["Error"] = evidence.Missing("no_error", nil)
	if resolutionErr != nil {
		a.failure(resolutionErr)
		cells["Error"] = evidence.Text(resolutionErr.Error())
	}
	if err := a.emit(evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: a.env.Kernel.Name(), Offset: fmt.Sprintf("0x%x", thread)}}); err != nil {
		return err
	}
	a.coverage.Reported++
	return nil
}
