package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/winpath"
)

func windowsPESymbolPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.pe_symbols", Upstream: "windows.pe_symbols.PESymbols", Platform: "windows", NeedsKernel: true, ExternalSymbols: true,
		Description: "Resolve exact PE symbols across ordered process or kernel module instances, PDB before exports",
		Parameters: []plugin.Parameter{
			{Name: "source", Kind: "string", Description: "Required: kernel or processes"},
			{Name: "module", Kind: "string", Description: "Required module grouping name, e.g. ntdll.dll or ntoskrnl.exe"},
			{Name: "symbols", Kind: "string", Default: "[]", Description: "JSON array of exact symbol names; a nonempty array takes precedence over addresses"},
			{Name: "addresses", Kind: "string", Default: "[]", Description: "JSON array of lossless address strings (0x... or decimal); JSON integers also accepted"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-list/VAD traversal bound, 1..1000000"},
			{Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total indexed VAD bound, 1..1000000"},
			{Name: "max-modules", Kind: "uint", Default: "10000", Description: "Matching module instance bound, 1..10000"},
			{Name: "max-read-bytes", Kind: "uint", Default: "67108864", Description: "Total captured metadata and symbol bytes, 1..1073741824"},
			{Name: "max-symbols", Kind: "uint", Default: "1000000", Description: "Total PDB symbols indexed, 1..10000000"},
		}, Columns: []evidence.Column{
			{Name: "Module", Kind: "string"}, {Name: "Symbol", Kind: "string"}, {Name: "Address", Kind: "address"},
			{Name: "RecordType", Kind: "string"}, {Name: "Resolution", Kind: "structure"}, {Name: "Coverage", Kind: "structure"}, {Name: "Missing", Kind: "structure"},
			{Name: "Offset", Kind: "address"}, {Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "Raw", Kind: "bytes"}, {Name: "Error", Kind: "string"},
		}}, windowsPESymbols}}
}

func peSymbolRequest(p map[string]string) (pesymbols.Request, error) {
	var request pesymbols.Request
	if len(p["symbols"]) > 16<<20 || len(p["addresses"]) > 16<<20 {
		return request, fmt.Errorf("encoded symbol/address arrays must each fit 16 MiB")
	}
	if err := json.Unmarshal([]byte(p["symbols"]), &request.Names); err != nil {
		return request, fmt.Errorf("symbols must be a JSON string array: %w", err)
	}
	if len(request.Names) > 1000000 {
		return request, fmt.Errorf("too many requested symbols")
	}
	for _, name := range request.Names {
		if name == "" || len(name) > 65536 {
			return request, fmt.Errorf("symbol names must contain 1..65536 bytes")
		}
	}
	// The upstream command ignores addresses entirely when names are supplied.
	if len(request.Names) > 0 {
		return request, nil
	}
	var values []json.RawMessage
	if err := json.Unmarshal([]byte(p["addresses"]), &values); err != nil {
		return request, fmt.Errorf("addresses must be a JSON array: %w", err)
	}
	if len(values) > 1000000 {
		return request, fmt.Errorf("too many requested addresses")
	}
	for _, raw := range values {
		text := string(raw)
		base := 10
		if len(raw) > 0 && raw[0] == '"' {
			if err := json.Unmarshal(raw, &text); err != nil {
				return request, err
			}
			if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
				base = 16
				text = text[2:]
			}
		}
		value, err := strconv.ParseUint(text, base, 64)
		if err != nil {
			return request, fmt.Errorf("address must be an unsigned 64-bit integer: %w", err)
		}
		request.Addresses = append(request.Addresses, value)
	}
	return request, nil
}

func windowsPESymbols(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
	if p["source"] != "kernel" && p["source"] != "processes" {
		return fmt.Errorf("source must be kernel or processes")
	}
	if p["module"] == "" || len(p["module"]) > 65536 {
		return fmt.Errorf("module must contain 1..65536 bytes")
	}
	request, err := peSymbolRequest(p)
	if err != nil {
		return err
	}
	limits := map[string]uint64{}
	for key, max := range map[string]uint64{"max-nodes": 1000000, "max-regions": 1000000, "max-modules": 10000, "max-read-bytes": 1 << 30, "max-symbols": 10000000} {
		n, cause := strconv.ParseUint(p[key], 0, 64)
		if cause != nil || n == 0 || n > max {
			return fmt.Errorf("%s must be 1..%d", key, max)
		}
		limits[key] = n
	}
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.pe_symbols requires kernel memory and symbols")
	}
	a := &windowsSymbolAnalysis{ctx: ctx, env: e, out: out, maxNodes: int(limits["max-nodes"]), maxRegions: int(limits["max-regions"]), maxBytes: limits["max-read-bytes"], maxSymbols: limits["max-symbols"], vads: map[uint64][]windowsVADPath{}, modules: map[string][]pesymbols.Module{}, resolvers: map[string]*pesymbols.Resolver{}}
	a.env.Kernel = windowsSymbolLayer{MemoryLayer: e.Kernel, analysis: a, metadata: true}
	a.env.Objects = &object.Reader{Layer: a.env.Kernel, Symbols: e.Symbols}
	name := winpath.Lower(p["module"])
	result := pesymbols.Result{Missing: request}
	status := "complete"
	defer func() {
		err = errors.Join(err, errors.Join(a.failures...))
		if a.stop != nil || ctx.Err() != nil {
			err = errors.Join(err, a.stop, ctx.Err())
			return
		}
		if err != nil {
			status = "failed"
		}
		missing := map[string]any{"names": result.Missing.Names, "addresses": []evidence.Value{}}
		for _, at := range result.Missing.Addresses {
			missing["addresses"] = append(missing["addresses"].([]evidence.Value), evidence.Address(at))
		}
		coverage := map[string]any{"status": status, "source": p["source"], "regions": a.coverage.Regions, "modules": a.coverage.Modules, "reads": a.coverage.Reads, "bytes": a.coverage.Bytes, "errors": a.coverage.Errors, "reported": len(result.Found), "complete": err == nil, "stopped_on_group": result.StoppedOnGroup}
		err = errors.Join(err, a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Module": evidence.Text(name), "Missing": {Kind: "structure", Data: missing}, "Coverage": {Kind: "structure", Data: coverage}, "Resolution": a.resolutionDetails(name, result)}}))
	}()
	if len(request.Names)+len(request.Addresses) == 0 {
		status = "no_query"
		return nil
	}
	if p["source"] == "processes" {
		err = a.collectPEProcessModules(name, limits["max-modules"])
	} else {
		err = a.collectPEKernelModules(name, limits["max-modules"])
	}
	if err != nil {
		a.failure(err)
		if a.stop != nil || ctx.Err() != nil {
			return err
		}
	}
	if len(a.modules[name]) == 0 {
		status = "module_not_collected"
		return err
	}
	resolver, err := a.moduleResolver(name)
	if err != nil {
		return err
	}
	result, err = resolver.Resolve(ctx, request)
	if err != nil {
		a.failure(err)
	}
	for _, found := range result.Found {
		m := a.modules[name][found.Module]
		if cause := a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("symbol"), "Module": evidence.Text(name), "Symbol": evidence.Text(found.Name), "Address": evidence.Address(found.Address), "Resolution": {Kind: "structure", Data: map[string]any{"method": found.Method, "module": found.Module, "base": evidence.Address(m.Base), "size": evidence.Number(m.Size), "layer": m.Layer.Name(), "symbols_sha256": found.SymbolsSHA256, "source_sha256": found.SourceSHA256}}}, Provenance: evidence.Provenance{Layer: m.Layer.Name(), Offset: fmt.Sprintf("0x%x", found.Address)}}); cause != nil {
			return cause
		}
	}
	return err
}

func (a *windowsSymbolAnalysis) addPEModule(name string, layer memory.MemoryLayer, base, size, max uint64) error {
	if a.coverage.Modules >= max {
		return fmt.Errorf("PE module instance limit exhausted")
	}
	a.modules[name] = append(a.modules[name], pesymbols.Module{Layer: windowsSymbolLayer{MemoryLayer: layer, analysis: a}, Base: base, Size: size, PDBNames: winpath.PDBCandidates(name)})
	a.coverage.Modules++
	return nil
}

func (a *windowsSymbolAnalysis) collectPEProcessModules(wanted string, max uint64) error {
	return visitWindowsProcesses(a.ctx, a.env, a.maxNodes, nil, func(process, pid uint64, _ string, created evidence.Value) error {
		identity := evidence.ProcessID(a.env.ImageHash, a.env.Kernel.Name(), process, pid, identityTime(created))
		space, err := processMemory(a.ctx, a.env, process, 0, identity)
		if err != nil {
			a.failure(err)
			return nil
		}
		files, err := a.peProcessVADs(process)
		if err != nil {
			return err
		}
		for _, file := range files {
			name := winpath.ModuleName(file.file.String())
			if !strings.HasSuffix(name, wanted) {
				continue
			}
			if err := a.addPEModule(name, space, file.start, file.end-file.start+1, max); err != nil {
				return err
			}
		}
		return nil
	})
}

// A corrupt filename excludes that VAD, not other readable modules. Every
// failed field read already has a raw acquisition record; failure() ensures
// the final task cannot be described as a complete normal result.
func (a *windowsSymbolAnalysis) peProcessVADs(process uint64) ([]windowsVADPath, error) {
	remaining := a.maxRegions - int(a.coverage.Regions)
	if remaining < 0 {
		return nil, fmt.Errorf("total VAD limit exhausted")
	}
	regions, err := windowsVADRegions(a.ctx, a.env, process, min(a.maxNodes, remaining))
	if err != nil {
		return nil, err
	}
	a.coverage.Regions += uint64(len(regions))
	var files []windowsVADPath
	for _, region := range regions {
		if region.file.Error != "" {
			a.failure(fmt.Errorf("VAD %#x file: %s", region.address, region.file.Error))
			continue
		}
		selected, cause := windowsFileVADs([]windowsVADPath{region})
		if cause != nil {
			return files, cause
		}
		files = append(files, selected...)
	}
	return files, nil
}

func (a *windowsSymbolAnalysis) collectPEKernelModules(wanted string, max uint64) error {
	var layers []memory.MemoryLayer
	seen := map[uint64]bool{}
	if err := visitWindowsProcesses(a.ctx, a.env, a.maxNodes, nil, func(process, pid uint64, _ string, created evidence.Value) error {
		identity := evidence.ProcessID(a.env.ImageHash, a.env.Kernel.Name(), process, pid, identityTime(created))
		space, err := processMemory(a.ctx, a.env, process, 0, identity)
		if err != nil {
			a.failure(err)
			return nil
		}
		pointer, err := a.env.Objects.Uint(a.ctx, process, "_EPROCESS", "Session")
		if err != nil {
			a.failure(err)
			return nil
		}
		// A null Session is the upstream not-applicable case; do not invent
		// a session structure at address zero or read its fallback field.
		if pointer == 0 {
			return nil
		}
		var id uint64
		if _, fieldErr := a.env.Objects.Field("_MM_SESSION_SPACE", "SessionId"); fieldErr == nil {
			id, err = a.env.Objects.Uint(a.ctx, pointer, "_MM_SESSION_SPACE", "SessionId")
		} else {
			at, cause := memory.Add(pointer, 8)
			if cause != nil {
				return cause
			}
			var raw []byte
			raw, err = memory.Read(a.ctx, a.env.Kernel, at, 4)
			if err == nil {
				id = uint64(raw[0]) | uint64(raw[1])<<8 | uint64(raw[2])<<16 | uint64(raw[3])<<24
			}
		}
		if err != nil {
			a.failure(err)
			return nil
		}
		if !seen[id] {
			seen[id] = true
			layers = append(layers, space)
		}
		return nil
	}); err != nil {
		return err
	}
	head, err := a.env.Symbol("PsLoadedModuleList")
	if err != nil {
		return err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	if _, typeErr := a.env.Symbols.Type(typ); typeErr != nil {
		typ = "_LDR_DATA_TABLE_ENTRY"
	}
	link, err := a.env.Objects.Field(typ, "InLoadOrderLinks")
	if err != nil {
		return err
	}
	index := 0
	return a.env.Objects.WalkList(a.ctx, head, link.Offset, a.maxNodes, func(at uint64) error {
		ordinal := index
		index++
		name, err := unicodeString(a.ctx, a.env, at, typ, "BaseDllName")
		if err != nil {
			return err
		}
		name = winpath.Lower(name)
		if wanted == "ntoskrnl.exe" && ordinal == 0 {
			name = "ntoskrnl.exe"
		} else if !strings.HasSuffix(name, wanted) {
			return nil
		}
		base, err := a.env.Objects.Uint(a.ctx, at, typ, "DllBase")
		if err != nil {
			return err
		}
		size, err := a.env.Objects.Uint(a.ctx, at, typ, "SizeOfImage")
		if err != nil {
			return err
		}
		for _, layer := range layers {
			// Volatility's Intel layer accepts pointer-masked addresses. Native
			// x64 translation requires canonical coordinates, so retain the
			// original DllBase here and in all persisted acquisition records.
			if _, err := memory.Read(a.ctx, windowsSymbolLayer{MemoryLayer: layer, analysis: a, metadata: true}, base, 1); err != nil {
				if a.stop != nil || a.ctx.Err() != nil {
					return errors.Join(err, a.stop, a.ctx.Err())
				}
				continue
			}
			return a.addPEModule(name, layer, base, size, max)
		}
		return nil
	})
}
