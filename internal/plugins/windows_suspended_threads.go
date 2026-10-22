package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/winpath"
)

func windowsSuspendedThreadPlugins() []builtin {
	columns := []evidence.Column{}
	for _, name := range []string{"Process", "StartFile", "StartSymbol", "Win32StartFile", "Win32StartSymbol", "Identity", "ProcessIdentity", "RecordType", "Error"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "string"})
	}
	for _, name := range []string{"PID", "TID", "SuspendCount", "State", "Requested", "Captured"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "uint64"})
	}
	for _, name := range []string{"Offset", "ProcessOffset", "StartAddress", "Win32StartAddress"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "address"})
	}
	for _, name := range []string{"Coverage", "Resolution"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "structure"})
	}
	columns = append(columns, evidence.Column{Name: "Raw", Kind: "bytes"})
	return []builtin{{plugin.Spec{Name: "windows.suspended_threads", Upstream: "windows.suspended_threads.SuspendedThreads", Platform: "windows", NeedsKernel: true, ExternalSymbols: true,
		Description: "Enumerate suspended nonterminated threads with PDB-first mapped-file symbols and raw acquisition evidence",
		Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-process list/VAD bound, 1..1000000"}, {Name: "max-threads", Kind: "uint", Default: "1000000", Description: "Total thread bound, 1..1000000"}, {Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total indexed VAD bound, 1..1000000"}, {Name: "max-read-bytes", Kind: "uint", Default: "67108864", Description: "Cumulative captured metadata/symbol bytes, 1..1073741824"}, {Name: "max-symbols", Kind: "uint", Default: "1000000", Description: "Total PDB symbols indexed, 1..10000000"}}, Columns: columns}, windowsSuspendedThreads}}
}

type suspendedCoverage struct {
	Threads, Suspended, Terminated, NoFileVADs, Excluded, Reported, Regions, Modules, Reads, Bytes uint64
	Errors                                                                                         uint64
	Complete                                                                                       bool
}
type suspendedAnalysis struct {
	ctx                              context.Context
	env                              plugin.Environment
	out                              plugin.Emit
	maxNodes, maxThreads, maxRegions int
	maxBytes, maxSymbols             uint64
	coverage                         suspendedCoverage
	failures                         []error
	stop                             error
	vads                             map[uint64][]windowsVADPath
	modules                          map[string][]pesymbols.Module
	resolvers                        map[string]*pesymbols.Resolver
	modulesBuilt                     bool
	symbols                          uint64
}

// All instance and VAD orders are the active-list/preorder orders, as in the
// locked helper. Empty, relative-only and non-file VAD names are not modules.
func suspendedFileVADs(regions []windowsVADPath) ([]windowsVADPath, error) {
	var result []windowsVADPath
	for _, region := range regions {
		if region.file.Error != "" {
			return nil, fmt.Errorf("VAD %#x file: %s", region.address, region.file.Error)
		}
		if region.file.Kind != "string" || !strings.Contains(region.file.String(), `\`) {
			continue
		}
		if region.end < region.start || region.end-region.start == ^uint64(0) {
			return nil, fmt.Errorf("invalid file VAD extent")
		}
		result = append(result, region)
	}
	return result, nil
}
func suspendedFileAt(regions []windowsVADPath, address uint64) evidence.Value {
	if address == 0 {
		return evidence.Missing("not_set", nil)
	}
	for _, region := range regions {
		if address >= region.start && address <= region.end {
			return region.file
		}
	}
	return evidence.Missing("not_mapped_in_file_vad", nil)
}
func suspendedModuleName(path string) string { return winpath.ModuleName(path) }
func suspendedPDBNames(name string) []string { return winpath.PDBCandidates(name) }

func (a *suspendedAnalysis) failure(err error) {
	if err == nil {
		return
	}
	a.coverage.Errors++
	if len(a.failures) < 64 {
		a.failures = append(a.failures, err)
	} else if len(a.failures) == 64 {
		a.failures = append(a.failures, fmt.Errorf("additional failures retained in raw evidence; see summary count"))
	}
}

func (a *suspendedAnalysis) emit(row evidence.Row) error {
	if a.stop != nil {
		return a.stop
	}
	if err := a.ctx.Err(); err != nil {
		a.stop = err
		return err
	}
	a.stop = a.out(row)
	return a.stop
}
func (a *suspendedAnalysis) capture(layer, scope string, r pe.ExportRead) error {
	a.coverage.Reads++
	errorCell := evidence.Missing("no_error", nil)
	if r.Err != nil {
		a.failure(r.Err)
		errorCell = evidence.Text(r.Err.Error())
	}
	return a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("memory_read"), "Offset": evidence.Address(r.Address), "Requested": evidence.Number(uint64(r.Requested)), "Captured": evidence.Number(uint64(len(r.Raw))), "Raw": evidence.Bytes(r.Raw), "Error": errorCell, "Resolution": {Kind: "structure", Data: map[string]any{"method": scope}}}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", r.Address)}})
}

type suspendedLayer struct {
	memory.MemoryLayer
	analysis *suspendedAnalysis
	metadata bool
}

func (l suspendedLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	a := l.analysis
	if a.stop != nil {
		return 0, a.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > a.maxBytes-a.coverage.Bytes {
		err := fmt.Errorf("suspended-thread acquisition byte limit exhausted")
		a.failure(err)
		return 0, err
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n = 0
		err = fmt.Errorf("invalid suspended-thread read count")
	}
	if err == nil && n != len(p) {
		err = fmt.Errorf("short suspended-thread read: %d/%d", n, len(p))
	}
	a.coverage.Bytes += uint64(n)
	if l.metadata {
		if cause := a.capture(l.Name(), "metadata", pe.ExportRead{Address: at, Requested: len(p), Raw: append([]byte(nil), p[:n]...), Err: err}); cause != nil {
			return n, cause
		}
	}
	return n, err
}
func (a *suspendedAnalysis) processVADs(process uint64) ([]windowsVADPath, error) {
	if regions, ok := a.vads[process]; ok {
		return regions, nil
	}
	remaining := a.maxRegions - int(a.coverage.Regions)
	if remaining < 0 {
		return nil, fmt.Errorf("total VAD limit exhausted")
	}
	regions, err := windowsVADRegions(a.ctx, a.env, process, min(a.maxNodes, remaining))
	if err != nil {
		return nil, err
	}
	a.coverage.Regions += uint64(len(regions))
	files, err := suspendedFileVADs(regions)
	if err != nil {
		return nil, err
	}
	a.vads[process] = files
	return files, nil
}
func (a *suspendedAnalysis) collectModules() error {
	if a.modulesBuilt {
		return nil
	}
	a.modulesBuilt = true
	return visitWindowsProcesses(a.ctx, a.env, a.maxNodes, nil, func(process, pid uint64, name string, created evidence.Value) error {
		files, err := a.processVADs(process)
		if err != nil {
			return fmt.Errorf("module VADs for process %#x: %w", process, err)
		}
		if len(files) == 0 {
			return nil
		}
		identity := evidence.ProcessID(a.env.ImageHash, a.env.Kernel.Name(), process, pid, identityTime(created))
		space, err := processMemory(a.ctx, a.env, process, 0, identity)
		if err != nil {
			return fmt.Errorf("module address space for process %#x: %w", process, err)
		}
		for _, file := range files {
			if a.coverage.Modules >= 10000 {
				return fmt.Errorf("module instance limit exhausted")
			}
			name := suspendedModuleName(file.file.String())
			a.modules[name] = append(a.modules[name], pesymbols.Module{Layer: suspendedLayer{MemoryLayer: space, analysis: a}, Base: file.start, Size: file.end - file.start + 1, PDBNames: suspendedPDBNames(name)})
			a.coverage.Modules++
		}
		return nil
	})
}
func identityTime(created evidence.Value) string {
	if created.Kind == "missing" {
		return ""
	}
	return created.String()
}
func (a *suspendedAnalysis) resolve(files []windowsVADPath, address uint64) (evidence.Value, evidence.Value, evidence.Value, error) {
	path := suspendedFileAt(files, address)
	missing := evidence.Missing("symbol_not_found", nil)
	if path.Kind != "string" {
		return path, missing, evidence.Missing("no_file_mapping", nil), nil
	}
	if err := a.collectModules(); err != nil {
		return path, missing, evidence.Missing("module_collection_failed", err), err
	}
	name := suspendedModuleName(path.String())
	resolver := a.resolvers[name]
	if resolver == nil {
		opts := pesymbols.Options{PDB: a.env.ModulePDB, Limits: pe.DefaultExportLimits(), MaxSymbols: a.maxSymbols}
		opts.Observe = func(r pesymbols.Read) error {
			return a.capture(a.modules[name][r.Module].Layer.Name(), r.Method, r.ExportRead)
		}
		// A shared provider counts each newly acquired table once per module
		// resolver; all query reuse happens inside that resolver.
		if opts.PDB != nil {
			provider := opts.PDB
			opts.PDB = func(ctx context.Context, m pesymbols.Module) (pesymbols.PDB, error) {
				table, err := provider(ctx, m)
				if err == nil && table.Table != nil {
					count := uint64(len(table.Table.Names()))
					if count > a.maxSymbols-a.symbols {
						return table, fmt.Errorf("total module PDB symbol limit exhausted")
					}
					a.symbols += count
				}
				return table, err
			}
		}
		var err error
		resolver, err = pesymbols.New(a.modules[name], opts)
		if err != nil {
			return path, missing, evidence.Missing("resolver_unavailable", err), err
		}
		a.resolvers[name] = resolver
	}
	result, err := resolver.Resolve(a.ctx, pesymbols.Request{Addresses: []uint64{address}})
	attempts := []map[string]any{}
	for _, attempt := range result.Attempts {
		item := map[string]any{"module": attempt.Module, "method": attempt.Method, "unavailable": attempt.Unavailable, "symbols_sha256": attempt.SymbolsSHA256, "source_sha256": attempt.SourceSHA256}
		if attempt.Err != nil {
			item["error"] = attempt.Err.Error()
		}
		if attempt.Module < len(a.modules[name]) {
			m := a.modules[name][attempt.Module]
			item["layer"] = m.Layer.Name()
			item["base"] = evidence.Address(m.Base)
			item["size"] = evidence.Number(m.Size)
		}
		attempts = append(attempts, item)
	}
	details := evidence.Value{Kind: "structure", Data: attempts}
	if len(result.Found) > 0 {
		return path, evidence.Text(result.Found[0].Name), details, err
	}
	if err != nil {
		missing = evidence.Missing("symbol_acquisition_failed", err)
	}
	return path, missing, details, err
}

func windowsSuspendedThreads(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
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
	a := &suspendedAnalysis{ctx: ctx, env: e, out: out, maxNodes: int(nodes), maxThreads: int(threads), maxRegions: int(regions), maxBytes: bytes, maxSymbols: symbols, vads: map[uint64][]windowsVADPath{}, modules: map[string][]pesymbols.Module{}, resolvers: map[string]*pesymbols.Resolver{}}
	a.env.Kernel = suspendedLayer{MemoryLayer: e.Kernel, analysis: a, metadata: true}
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
			suspend, err := a.env.Objects.Uint(ctx, thread, "_ETHREAD", "Tcb.SuspendCount")
			if err != nil {
				return err
			}
			if suspend == 0 {
				return nil
			}
			a.coverage.Suspended++
			state, err := a.env.Objects.Uint(ctx, thread, "_ETHREAD", "Tcb.State")
			if err != nil {
				return err
			}
			if state == 4 {
				a.coverage.Terminated++
				return nil
			}
			owner, err := threadOwnerAddress(ctx, a.env.Objects, thread)
			if err != nil {
				return err
			}
			ownerName, err := a.env.Objects.String(ctx, owner, "_EPROCESS", "ImageFileName", 64)
			if err != nil {
				return err
			}
			ownerPID, err := a.env.Objects.Uint(ctx, thread, "_ETHREAD", "Cid.UniqueProcess")
			if err != nil {
				return err
			}
			tid, err := a.env.Objects.Uint(ctx, thread, "_ETHREAD", "Cid.UniqueThread")
			if err != nil {
				return err
			}
			start, err := a.env.Objects.Uint(ctx, thread, "_ETHREAD", "StartAddress")
			if err != nil {
				return err
			}
			win32, err := a.env.Objects.Uint(ctx, thread, "_ETHREAD", "Win32StartAddress")
			if err != nil {
				return err
			}
			files, err := a.processVADs(owner)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				a.coverage.NoFileVADs++
				return nil
			}
			startFile, startSym, startResolution, firstErr := a.resolve(files, start)
			win32File, win32Sym, win32Resolution, secondErr := a.resolve(files, win32)
			if a.stop != nil {
				return a.stop
			}
			resolutionErr := errors.Join(firstErr, secondErr)
			if resolutionErr != nil {
				a.failure(resolutionErr)
			}
			// Match the baseline's case-sensitive exception after both lookups.
			if startFile.Kind == "string" && strings.HasSuffix(startFile.String(), `\WorkFoldersShell.dll`) || win32File.Kind == "string" && strings.HasSuffix(win32File.String(), `\WorkFoldersShell.dll`) {
				a.coverage.Excluded++
				return nil
			}
			// Owner object, rather than displayed CID PID, defines process identity.
			realPID, err := a.env.Objects.Uint(ctx, owner, "_EPROCESS", "UniqueProcessId")
			if err != nil {
				return err
			}
			ownerCreated, _ := windowsTime(ctx, a.env, owner, "_EPROCESS", "CreateTime")
			_, threadCreated := windowsTime(ctx, a.env, thread, "_ETHREAD", "CreateTime")
			processID := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), owner, realPID, identityTime(ownerCreated))
			errorCell := evidence.Missing("no_error", nil)
			if resolutionErr != nil {
				errorCell = evidence.Text(resolutionErr.Error())
			}
			row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("thread"), "Process": evidence.Text(ownerName), "PID": evidence.Number(ownerPID), "TID": evidence.Number(tid), "Offset": evidence.Address(thread), "ProcessOffset": evidence.Address(owner), "StartAddress": evidence.Address(start), "Win32StartAddress": evidence.Address(win32), "StartFile": startFile, "StartSymbol": startSym, "Win32StartFile": win32File, "Win32StartSymbol": win32Sym, "SuspendCount": evidence.Number(suspend), "State": evidence.Number(state), "ProcessIdentity": evidence.Text(processID), "Identity": evidence.Text(evidence.ThreadID(e.ImageHash, e.Kernel.Name(), thread, tid, identityTime(threadCreated))), "Resolution": {Kind: "structure", Data: map[string]evidence.Value{"start": startResolution, "win32": win32Resolution}}, "Error": errorCell}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", thread)}}
			if err := a.emit(row); err != nil {
				return err
			}
			a.coverage.Reported++
			return nil
		})
	})
}
