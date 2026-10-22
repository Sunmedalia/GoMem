package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsETWPatchPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.etwpatch", Upstream: "windows.etwpatch.EtwPatch", Platform: "windows", NeedsKernel: true, ExternalSymbols: true,
		Description: "Inspect ETW function first bytes in each process with global PDB-first symbol attribution and raw read evidence",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated PID filter; module symbol collection remains global"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-list/VAD bound, 1..1000000"},
			{Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total indexed VAD bound, 1..1000000"},
			{Name: "max-modules", Kind: "uint", Default: "10000", Description: "Total matching module instances, 1..10000"},
			{Name: "max-read-bytes", Kind: "uint", Default: "67108864", Description: "Total captured metadata/symbol/opcode bytes, 1..1073741824"},
			{Name: "max-symbols", Kind: "uint", Default: "1000000", Description: "Total acquired PDB symbols, 1..10000000"},
			{Name: "max-probes", Kind: "uint", Default: "1000000", Description: "Total process/function opcode probes, 1..10000000"},
		}, Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "DLL", Kind: "string"}, {Name: "Function", Kind: "string"}, {Name: "Offset", Kind: "address"}, {Name: "Opcode", Kind: "string"},
			{Name: "RecordType", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "Resolution", Kind: "structure"}, {Name: "Coverage", Kind: "structure"},
			{Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "Raw", Kind: "bytes"}, {Name: "Error", Kind: "string"},
		}}, windowsETWPatch}}
}

var etwWanted = []struct {
	module string
	names  []string
}{
	{"ntdll.dll", []string{"EtwEventWrite", "EtwEventWriteFull", "NtTraceEvent", "ZwTraceEvent", "NtTraceControl", "ZwTraceControl", "EtwpEventWriteFull"}},
	{"advapi32.dll", []string{"EventWrite", "TraceEvent"}},
}

func windowsETWPatch(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
	budget := map[string]uint64{}
	for key, max := range map[string]uint64{"max-nodes": 1000000, "max-regions": 1000000, "max-modules": 10000, "max-read-bytes": 1 << 30, "max-symbols": 10000000, "max-probes": 10000000} {
		n, cause := strconv.ParseUint(p[key], 0, 64)
		if cause != nil || n == 0 || n > max {
			return fmt.Errorf("%s must be 1..%d", key, max)
		}
		budget[key] = n
	}
	_, wantedPIDs, err := limits(p)
	if err != nil {
		return err
	}
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("windows.etwpatch requires kernel memory and symbols")
	}
	spans := &windowsReadSpans{out: out}
	a := &windowsSymbolAnalysis{ctx: ctx, env: e, out: spans.emit, maxNodes: int(budget["max-nodes"]), maxRegions: int(budget["max-regions"]), maxBytes: budget["max-read-bytes"], maxSymbols: budget["max-symbols"], vads: map[uint64][]windowsVADPath{}, modules: map[string][]pesymbols.Module{}, resolvers: map[string]*pesymbols.Resolver{}}
	a.env.Kernel = windowsSymbolLayer{MemoryLayer: e.Kernel, analysis: a, metadata: true}
	a.env.Objects = &object.Reader{Layer: a.env.Kernel, Symbols: e.Symbols}
	var processes, probes, findings, resolved uint64
	var resolutions []map[string]any
	defer func() {
		err = errors.Join(err, errors.Join(a.failures...))
		if a.stop != nil || ctx.Err() != nil {
			err = errors.Join(err, a.stop, ctx.Err())
			return
		}
		a.coverage.Complete = err == nil
		err = errors.Join(err, a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": {Kind: "structure", Data: map[string]any{"acquisition": a.coverage, "processes": processes, "probes": probes, "findings": findings, "resolved_functions": resolved, "symbols": resolutions}}}}))
	}()
	// One global VAD pass, independent of the later PID filter.
	cause := visitWindowsProcesses(ctx, a.env, a.maxNodes, nil, func(process, pid uint64, name string, created evidence.Value) error {
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, identityTime(created))
		space, cause := processMemory(ctx, a.env, process, 0, identity)
		if cause != nil {
			a.failure(cause)
			return nil
		}
		files, cause := a.peProcessVADs(process)
		if cause != nil {
			return cause
		}
		if len(files) == 0 {
			return nil
		}
		for _, file := range files {
			name := windowsModuleName(file.file.String())
			if !strings.HasSuffix(name, "ntdll.dll") && !strings.HasSuffix(name, "advapi32.dll") {
				continue
			}
			if cause := a.addPEModule(name, space, file.start, file.end-file.start+1, budget["max-modules"]); cause != nil {
				return cause
			}
		}
		return nil
	})
	if cause != nil {
		if a.stop != nil || ctx.Err() != nil {
			return cause
		}
		a.failure(cause)
	}
	type foundGroup struct {
		module string
		result pesymbols.Result
		detail evidence.Value
	}
	var groups []foundGroup
	for _, wanted := range etwWanted {
		if len(a.modules[wanted.module]) == 0 {
			continue
		}
		resolver, cause := a.moduleResolver(wanted.module)
		if cause != nil {
			a.failure(cause)
			continue
		}
		result, cause := resolver.Resolve(ctx, pesymbols.Request{Names: wanted.names})
		if cause != nil {
			a.failure(cause)
		}
		if a.stop != nil || ctx.Err() != nil {
			return errors.Join(a.stop, ctx.Err())
		}
		resolved += uint64(len(result.Found))
		resolutions = append(resolutions, map[string]any{"module": wanted.module, "found": len(result.Found), "missing": result.Missing.Names, "attempts": a.resolutionDetails(wanted.module, result)})
		groups = append(groups, foundGroup{wanted.module, result, a.resolutionDetails(wanted.module, result)})
	}
	return visitWindowsProcesses(ctx, a.env, a.maxNodes, wantedPIDs, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, identityTime(created))
		space, cause := processMemory(ctx, a.env, process, 0, identity)
		if cause != nil {
			a.failure(cause)
			return nil
		}
		layer := windowsSymbolLayer{MemoryLayer: space, analysis: a}
		for _, group := range groups {
			for _, match := range group.result.Found {
				if probes >= budget["max-probes"] {
					return fmt.Errorf("ETW opcode probe limit exhausted")
				}
				if a.coverage.Bytes >= a.maxBytes {
					return fmt.Errorf("ETW opcode byte limit exhausted")
				}
				probes++
				raw := make([]byte, 1)
				n, readErr := layer.ReadAt(ctx, raw, match.Address)
				if captureErr := a.capture(layer.Name(), "opcode", pe.ExportRead{Address: match.Address, Requested: 1, Raw: raw[:n], Err: readErr}); captureErr != nil {
					return captureErr
				}
				if readErr != nil || n != 1 {
					continue
				}
				instruction := ""
				switch raw[0] {
				case 0xc3:
					instruction = "RET"
				case 0xe9:
					instruction = "JMP"
				default:
					continue
				}
				row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("finding"), "PID": evidence.Number(pid), "Process": evidence.Text(name), "DLL": evidence.Text(group.module), "Function": evidence.Text(match.Name), "Offset": evidence.Address(match.Address), "Opcode": evidence.Text(fmt.Sprintf("%02x (%s)", raw[0], instruction)), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity), "Resolution": etwMatchDetails(a, group.module, match, group.detail), "Raw": evidence.Bytes(raw)}, Provenance: evidence.Provenance{Layer: space.Name(), Offset: fmt.Sprintf("0x%x", match.Address)}}
				if cause := a.emit(row); cause != nil {
					return cause
				}
				findings++
			}
		}
		return nil
	})
}

func etwMatchDetails(a *windowsSymbolAnalysis, name string, match pesymbols.Match, attempts evidence.Value) evidence.Value {
	details := map[string]any{"method": match.Method, "module": match.Module, "symbols_sha256": match.SymbolsSHA256, "source_sha256": match.SourceSHA256, "attempts": attempts}
	if match.Module >= 0 && match.Module < len(a.modules[name]) {
		m := a.modules[name][match.Module]
		details["layer"] = m.Layer.Name()
		details["base"] = evidence.Address(m.Base)
		details["size"] = evidence.Number(m.Size)
	}
	return evidence.Value{Kind: "structure", Data: details}
}
