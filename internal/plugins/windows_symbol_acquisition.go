package plugins

import (
	"context"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/winpath"
)

// Shared per-run acquisition state for PE-symbol commands and thread attribution.
// It owns raw captures, cumulative limits, failures and module resolver caches.
type windowsSymbolCoverage struct {
	Threads, Suspended, Terminated, NoFileVADs, Excluded, Reported, Regions, Modules, Reads, Bytes uint64
	Errors                                                                                         uint64
	Complete                                                                                       bool
}
type windowsSymbolAnalysis struct {
	ctx                              context.Context
	env                              plugin.Environment
	out                              plugin.Emit
	maxNodes, maxThreads, maxRegions int
	maxBytes, maxSymbols             uint64
	coverage                         windowsSymbolCoverage
	failures                         []error
	stop                             error
	vads                             map[uint64][]windowsVADPath
	modules                          map[string][]pesymbols.Module
	resolvers                        map[string]*pesymbols.Resolver
	modulesBuilt                     bool
	symbols                          uint64
}

func windowsFileVADs(regions []windowsVADPath) ([]windowsVADPath, error) {
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

func windowsModuleName(path string) string { return winpath.ModuleName(path) }
func windowsPDBNames(name string) []string { return winpath.PDBCandidates(name) }

func (a *windowsSymbolAnalysis) failure(err error) {
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

func (a *windowsSymbolAnalysis) emit(row evidence.Row) error {
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
func (a *windowsSymbolAnalysis) capture(layer, scope string, r pe.ExportRead) error {
	a.coverage.Reads++
	errorCell := evidence.Missing("no_error", nil)
	if r.Err != nil {
		a.failure(r.Err)
		errorCell = evidence.Text(r.Err.Error())
	}
	return a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("memory_read"), "Offset": evidence.Address(r.Address), "Requested": evidence.Number(uint64(r.Requested)), "Captured": evidence.Number(uint64(len(r.Raw))), "Raw": evidence.Bytes(r.Raw), "Error": errorCell, "Resolution": {Kind: "structure", Data: map[string]any{"method": scope}}}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", r.Address)}})
}

type windowsSymbolLayer struct {
	memory.MemoryLayer
	analysis *windowsSymbolAnalysis
	metadata bool
}

func (l windowsSymbolLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	a := l.analysis
	if a.stop != nil {
		return 0, a.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > a.maxBytes-a.coverage.Bytes {
		err := fmt.Errorf("Windows symbol acquisition byte limit exhausted")
		a.failure(err)
		return 0, err
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if n < 0 || n > len(p) {
		n = 0
		err = fmt.Errorf("invalid Windows symbol read count")
	}
	if err == nil && n != len(p) {
		err = fmt.Errorf("short Windows symbol read: %d/%d", n, len(p))
	}
	a.coverage.Bytes += uint64(n)
	if l.metadata {
		if cause := a.capture(l.Name(), "metadata", pe.ExportRead{Address: at, Requested: len(p), Raw: append([]byte(nil), p[:n]...), Err: err}); cause != nil {
			return n, cause
		}
	}
	return n, err
}
func (a *windowsSymbolAnalysis) processVADs(process uint64) ([]windowsVADPath, error) {
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
	files, err := windowsFileVADs(regions)
	if err != nil {
		return nil, err
	}
	a.vads[process] = files
	return files, nil
}
func (a *windowsSymbolAnalysis) collectModules() error {
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
			name := windowsModuleName(file.file.String())
			a.modules[name] = append(a.modules[name], pesymbols.Module{Layer: windowsSymbolLayer{MemoryLayer: space, analysis: a}, Base: file.start, Size: file.end - file.start + 1, PDBNames: windowsPDBNames(name)})
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

func (a *windowsSymbolAnalysis) moduleResolver(name string) (*pesymbols.Resolver, error) {
	resolver := a.resolvers[name]
	if resolver == nil {
		opts := pesymbols.Options{PDB: a.env.ModulePDB, Limits: pe.DefaultExportLimits(), MaxSymbols: a.maxSymbols}
		// The analysis owns the cumulative budget. Honor its declared override
		// across all instances instead of silently retaining a smaller per-
		// resolver default that can prevent even attempted export fallback.
		opts.Limits.MaxBytes = a.maxBytes
		opts.Observe = func(r pesymbols.Read) error {
			return a.capture(a.modules[name][r.Module].Layer.Name(), r.Method, r.ExportRead)
		}
		// A shared provider counts each newly acquired table once per module
		// resolver; all query reuse happens inside that resolver.
		if opts.PDB != nil {
			provider := opts.PDB
			opts.PDB = func(ctx context.Context, m pesymbols.Module) (pesymbols.PDB, error) {
				table, err := provider(ctx, m)
				if table.Table != nil {
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
			return nil, err
		}
		a.resolvers[name] = resolver
	}
	return resolver, nil
}
func (a *windowsSymbolAnalysis) resolutionDetails(name string, result pesymbols.Result) evidence.Value {
	attempts := []map[string]any{}
	for _, attempt := range result.Attempts {
		item := map[string]any{"module": attempt.Module, "method": attempt.Method, "unavailable": attempt.Unavailable, "symbols_sha256": attempt.SymbolsSHA256, "source_sha256": attempt.SourceSHA256}
		if attempt.Err != nil {
			item["error"] = attempt.Err.Error()
		}
		if attempt.Module >= 0 && attempt.Module < len(a.modules[name]) {
			m := a.modules[name][attempt.Module]
			item["layer"] = m.Layer.Name()
			item["base"] = evidence.Address(m.Base)
			item["size"] = evidence.Number(m.Size)
		}
		attempts = append(attempts, item)
	}
	return evidence.Value{Kind: "structure", Data: attempts}
}
