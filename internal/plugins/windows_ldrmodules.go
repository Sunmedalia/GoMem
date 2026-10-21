package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsLdrModulesPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.ldrmodules", Upstream: "windows.malware.ldrmodules.LdrModules", Platform: "windows", NeedsKernel: true,
		Description: "Compare MZ-backed VADs with the three PEB loader lists",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active-process, VAD and loader-list bound; not an upstream parameter"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Base", Kind: "address"},
			{Name: "InLoad", Kind: "bool"}, {Name: "InInit", Kind: "bool"}, {Name: "InMem", Kind: "bool"},
			{Name: "MappedPath", Kind: "string"}, {Name: "PathError", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
		},
	}, windowsLdrModules}}
}

type ldrBaseSets struct {
	load, init, mem map[uint64]bool
}

type ldrStats struct {
	processes, mz, inLoad, inInit, inMem, pathsUnavailable uint64
}

func windowsLdrModules(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.ldrmodules requires a kernel layer and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	var stats ldrStats
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		stats.processes++
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		layer, err := processMemory(ctx, e, process, 0, identity)
		if err != nil {
			return fmt.Errorf("windows.ldrmodules: process %#x layer: %w", process, err)
		}
		sets, err := collectLDRBases(ctx, e, process, layer, max)
		if err != nil {
			return err
		}
		regions, err := windowsVADPaths(ctx, e, process, max)
		if err != nil {
			return fmt.Errorf("windows.ldrmodules: process %#x VAD: %w", process, err)
		}
		for _, region := range regions {
			mz, err := vadHasMZ(ctx, layer, region.start)
			if err != nil {
				return err
			}
			if !mz {
				continue
			}
			stats.mz++
			inLoad := sets.load[region.start]
			inInit := sets.init[region.start]
			inMem := sets.mem[region.start]
			if inLoad {
				stats.inLoad++
			}
			if inInit {
				stats.inInit++
			}
			if inMem {
				stats.inMem++
			}
			path, pathError := ldrPath(region.file)
			if path.Kind == "missing" {
				stats.pathsUnavailable++
			}
			row := evidence.Row{Cells: map[string]evidence.Value{
				"PID": evidence.Number(pid), "Process": evidence.Text(name), "Base": evidence.Address(region.start),
				"InLoad": evidence.Bool(inLoad), "InInit": evidence.Bool(inInit), "InMem": evidence.Bool(inMem),
				"MappedPath": path, "PathError": pathError, "RecordType": evidence.Text("module"),
			}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", region.address)}}
			if err = out(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{
		"PID": evidence.Missing("not_applicable", nil), "Process": evidence.Missing("not_applicable", nil),
		"Base":   evidence.Missing("not_applicable", nil),
		"InLoad": evidence.Missing("not_applicable", nil), "InInit": evidence.Missing("not_applicable", nil), "InMem": evidence.Missing("not_applicable", nil),
		"MappedPath": evidence.Missing("not_applicable", nil), "PathError": evidence.Missing("not_applicable", nil),
		"RecordType": evidence.Text("summary"),
		"Coverage": poolCoverage(map[string]string{
			"processes": formatCount(stats.processes), "mz_vads": formatCount(stats.mz),
			"in_load": formatCount(stats.inLoad), "in_init": formatCount(stats.inInit), "in_mem": formatCount(stats.inMem),
			"paths_unavailable": formatCount(stats.pathsUnavailable),
		}),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}})
}

func ldrPath(file evidence.Value) (evidence.Value, evidence.Value) {
	if file.Kind != "missing" {
		return file, evidence.Missing("not_applicable", nil)
	}
	reason := file.Reason
	if reason == "" {
		reason = "not_file_backed"
	}
	return evidence.Missing(reason, nil), file
}

func vadHasMZ(ctx context.Context, layer memory.MemoryLayer, start uint64) (bool, error) {
	raw, err := memory.Read(ctx, layer, start, 2)
	if err != nil {
		if err = ctx.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	return binary.LittleEndian.Uint16(raw) == 0x5A4D, nil
}

func collectLDRBases(ctx context.Context, e plugin.Environment, process uint64, layer memory.MemoryLayer, max int) (ldrBaseSets, error) {
	sets := ldrBaseSets{load: map[uint64]bool{}, init: map[uint64]bool{}, mem: map[uint64]bool{}}
	peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
	if err != nil {
		peb = 0
	}
	var wow uint64
	if e.Symbols.PointerSize() == 8 {
		for _, path := range []string{"WoW64Process", "Wow64Process"} {
			if _, fieldErr := e.Objects.Field("_EPROCESS", path); fieldErr != nil {
				if errors.Is(fieldErr, object.ErrFieldAbsent) {
					continue
				}
				wow = 0
				break
			}
			value, readErr := e.Objects.Uint(ctx, process, "_EPROCESS", path)
			if readErr != nil {
				wow = 0
				break
			}
			wow = value
			break
		}
	}
	type target struct {
		peb uint64
		env plugin.Environment
	}
	native := e
	native.Kernel = layer
	native.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
	var targets []target
	if peb != 0 {
		targets = append(targets, target{peb, native})
	}
	if wow != 0 {
		peb32 := wow
		readable := true
		for _, candidate := range []struct{ typ, path string }{{"_EWOW64PROCESS", "Peb"}, {"_WOW64_PROCESS", "Wow64"}} {
			if _, typeErr := e.Symbols.Type(candidate.typ); typeErr != nil {
				continue
			}
			value, readErr := e.Objects.Uint(ctx, wow, candidate.typ, candidate.path)
			if readErr != nil {
				readable = false
			} else {
				peb32 = value
			}
			break
		}
		if readable && peb32 != 0 {
			table, err := wowLoaderSymbols()
			if err != nil {
				return sets, err
			}
			user32 := native
			user32.Symbols = table
			user32.Objects = &object.Reader{Layer: layer, Symbols: table}
			targets = append(targets, target{peb32, user32})
		}
	}
	for _, target := range targets {
		if err = addLDRList(ctx, target.env, target.peb, "InLoadOrderModuleList", "InLoadOrderLinks", max, sets.load); err != nil {
			return sets, err
		}
		if err = addLDRList(ctx, target.env, target.peb, "InMemoryOrderModuleList", "InMemoryOrderLinks", max, sets.mem); err != nil {
			return sets, err
		}
		if err = addLDRList(ctx, target.env, target.peb, "InInitializationOrderModuleList", "InInitializationOrderLinks", max, sets.init); err != nil {
			return sets, err
		}
	}
	return sets, nil
}

func addLDRList(ctx context.Context, user plugin.Environment, peb uint64, listName, linkName string, max int, into map[uint64]bool) error {
	if peb == 0 {
		return nil
	}
	ldr, err := user.Objects.Uint(ctx, peb, "_PEB", "Ldr")
	if err != nil || ldr == 0 {
		return nil
	}
	head, err := user.Objects.Field("_PEB_LDR_DATA", listName)
	if err != nil {
		return err
	}
	list, err := memory.Add(ldr, head.Offset)
	if err != nil {
		return err
	}
	link, err := user.Objects.Field("_LDR_DATA_TABLE_ENTRY", linkName)
	if err != nil {
		return err
	}
	return walkVerForwardList(ctx, user, list, link.Offset, max, func(address uint64) error {
		base, baseErr := user.Objects.Uint(ctx, address, "_LDR_DATA_TABLE_ENTRY", "DllBase")
		if baseErr != nil {
			return nil
		}
		into[base] = true
		return nil
	}, nil)
}
