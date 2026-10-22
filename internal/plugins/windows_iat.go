package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsIATPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.iat", Upstream: "windows.iat.IAT", Platform: "windows", NeedsKernel: true,
		Description: "Read main-image PE imports with original acquisition evidence and separate actual IAT slot/pointer coordinates",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated active process PID filter"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active process list bound, 1..1000000"},
			{Name: "max-descriptors", Kind: "uint", Default: "4096", Description: "Total nonempty import descriptor bound, 1..65536"},
			{Name: "max-imports", Kind: "uint", Default: "100000", Description: "Total emitted imports, 1..1000000"},
			{Name: "max-thunks", Kind: "uint", Default: "2000000", Description: "Total acquired ILT/IAT slots including terminators, 1..4000000"},
			{Name: "max-read-bytes", Kind: "uint", Default: "67108864", Description: "Total captured process/PE bytes, 1..1073741824"},
		}, Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Name", Kind: "string"}, {Name: "Library", Kind: "string"}, {Name: "Bound", Kind: "bool"}, {Name: "Function", Kind: "string"}, {Name: "Address", Kind: "address"},
			{Name: "RecordType", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "ImageBase", Kind: "address"}, {Name: "DescriptorRVA", Kind: "address"}, {Name: "LookupRVA", Kind: "address"}, {Name: "IATSlot", Kind: "address"}, {Name: "ResolvedPointer", Kind: "address"}, {Name: "NameTruncated", Kind: "bool"}, {Name: "LibraryTruncated", Kind: "bool"}, {Name: "Ordinal", Kind: "uint64"}, {Name: "Hint", Kind: "uint64"},
			{Name: "Offset", Kind: "address"}, {Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "Raw", Kind: "bytes"}, {Name: "Resolution", Kind: "structure"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
		}}, windowsIAT}}
}

func windowsIAT(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
	budget := map[string]uint64{}
	for key, max := range map[string]uint64{"max-nodes": 1000000, "max-descriptors": 65536, "max-imports": 1000000, "max-thunks": 4000000, "max-read-bytes": 1 << 30} {
		n, cause := strconv.ParseUint(p[key], 0, 64)
		if cause != nil || n == 0 || n > max {
			return fmt.Errorf("%s must be 1..%d", key, max)
		}
		budget[key] = n
	}
	_, pids, err := limits(p)
	if err != nil {
		return err
	}
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("windows.iat requires kernel memory and symbols")
	}
	if e.Architecture != "x64" && e.Architecture != "x86" && e.Architecture != "pae" {
		return fmt.Errorf("windows.iat requires Intel process translation")
	}
	for _, field := range []struct{ typ, path string }{{"_EPROCESS", "Peb"}, {"_PEB", "ImageBaseAddress"}} {
		if _, cause := e.Objects.Field(field.typ, field.path); cause != nil {
			return cause
		}
	}
	a := &windowsSymbolAnalysis{ctx: ctx, env: e, out: out, maxNodes: int(budget["max-nodes"]), maxBytes: budget["max-read-bytes"]}
	a.env.Kernel = windowsSymbolLayer{MemoryLayer: e.Kernel, analysis: a, metadata: true}
	a.env.Objects = &object.Reader{Layer: a.env.Kernel, Symbols: e.Symbols}
	var processes, images, imports, descriptors, thunks, noPEB uint64
	defer func() {
		err = errors.Join(err, errors.Join(a.failures...))
		if a.stop != nil || ctx.Err() != nil {
			err = errors.Join(err, a.stop, ctx.Err())
			return
		}
		a.coverage.Complete = err == nil
		err = errors.Join(err, a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": {Kind: "structure", Data: map[string]any{"acquisition": a.coverage, "processes": processes, "images": images, "imports": imports, "descriptors": descriptors, "thunks": thunks, "no_peb": noPEB}}}}))
	}()
	return visitWindowsProcesses(ctx, a.env, a.maxNodes, pids, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, identityTime(created))
		cells := func(kind string) map[string]evidence.Value {
			return map[string]evidence.Value{"RecordType": evidence.Text(kind), "PID": evidence.Number(pid), "Name": evidence.Text(name), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity)}
		}
		diagnostic := func(reason string, cause error, layer string, at uint64) error {
			a.failure(cause)
			row := evidence.Row{Cells: cells("diagnostic"), Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", at)}}
			row.Cells["Error"] = evidence.Missing(reason, cause)
			return a.emit(row)
		}
		peb, cause := a.env.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
		if cause != nil {
			return diagnostic("peb_pointer_unreadable", cause, e.Kernel.Name(), process)
		}
		if peb == 0 {
			noPEB++
			return diagnostic("no_process_peb", nil, e.Kernel.Name(), process)
		}
		space, cause := processMemory(ctx, a.env, process, 0, identity)
		if cause != nil {
			return diagnostic("process_address_space_unavailable", cause, e.Kernel.Name(), process)
		}
		user := &object.Reader{Layer: windowsSymbolLayer{MemoryLayer: space, analysis: a, metadata: true}, Symbols: e.Symbols}
		base, cause := user.Uint(ctx, peb, "_PEB", "ImageBaseAddress")
		if cause != nil {
			return diagnostic("image_base_unreadable", cause, space.Name(), peb)
		}
		if base == 0 {
			return diagnostic("no_image_base", fmt.Errorf("null PEB ImageBaseAddress"), space.Name(), peb)
		}
		if descriptors >= budget["max-descriptors"] || imports >= budget["max-imports"] || thunks >= budget["max-thunks"] || a.coverage.Bytes >= a.maxBytes {
			return fmt.Errorf("IAT task resource limit exhausted")
		}
		images++
		bound := pe.DefaultImportLimits()
		bound.MaxDescriptors = budget["max-descriptors"] - descriptors
		bound.MaxImports = budget["max-imports"] - imports
		bound.MaxThunks = budget["max-thunks"] - thunks
		bound.MaxBytes = a.maxBytes - a.coverage.Bytes
		bound.Observe = func(r pe.ExportRead) error { return a.capture(space.Name(), "imports", r) }
		bound.Emit = func(entry pe.Import) error {
			row := evidence.Row{Cells: cells("import"), Provenance: evidence.Provenance{Layer: space.Name(), Offset: fmt.Sprintf("0x%x", entry.Slot)}}
			row.Cells["Library"] = evidence.Text(string(entry.Library))
			row.Cells["NameTruncated"] = evidence.Bool(entry.NameTruncated)
			row.Cells["LibraryTruncated"] = evidence.Bool(entry.LibraryTruncated)
			row.Cells["Bound"] = evidence.Bool(entry.Bound)
			row.Cells["Function"] = evidence.Missing("ordinal_unresolved", nil)
			if entry.Name != nil {
				row.Cells["Function"] = evidence.Text(string(entry.Name))
			}
			row.Cells["Address"] = evidence.Address(entry.Address)
			row.Cells["ImageBase"] = evidence.Address(base)
			row.Cells["DescriptorRVA"] = evidence.Address(entry.DescriptorRVA)
			row.Cells["LookupRVA"] = evidence.Address(entry.LookupRVA)
			row.Cells["IATSlot"] = evidence.Address(entry.Slot)
			row.Cells["ResolvedPointer"] = evidence.Missing("iat_entry_unavailable", nil)
			if entry.ValueAvailable {
				row.Cells["ResolvedPointer"] = evidence.Address(entry.Value)
			}
			row.Cells["Ordinal"] = evidence.Missing("import_by_name", nil)
			row.Cells["Hint"] = evidence.Missing("import_by_ordinal", nil)
			if entry.ByOrdinal {
				row.Cells["Ordinal"] = evidence.Number(uint64(entry.Ordinal))
			} else {
				row.Cells["Hint"] = evidence.Number(uint64(entry.Hint))
			}
			if cause := a.emit(row); cause != nil {
				return cause
			}
			imports++
			return nil
		}
		table, cause := pe.ReadImports(ctx, windowsSymbolLayer{MemoryLayer: space, analysis: a}, base, bound)
		descriptors += table.Descriptors
		thunks += table.Thunks
		if cause != nil {
			if a.stop != nil || ctx.Err() != nil {
				return errors.Join(cause, a.stop, ctx.Err())
			}
			return diagnostic("imports_incomplete", cause, space.Name(), base)
		}
		return nil
	})
}
