package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsHollowProcessPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.hollowprocesses", Upstream: "windows.malware.hollowprocesses.HollowProcesses", Platform: "windows", NeedsKernel: true,
		Description: "Compare PEB image base and load-order DLLs with executable VAD mappings",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process, VAD and per-PEB loader-list bound; not an upstream parameter"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Notes", Kind: "string"}, {Name: "Rule", Kind: "string"}, {Name: "Base", Kind: "address"}, {Name: "ImageBase", Kind: "address"}, {Name: "SectionBase", Kind: "address"}, {Name: "Protection", Kind: "string"}, {Name: "Path", Kind: "string"}, {Name: "PathError", Kind: "string"}, {Name: "VADOffset", Kind: "address"}, {Name: "LoaderOffset", Kind: "address"}, {Name: "LoaderLayer", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"}, {Name: "Error", Kind: "string"}},
	}, windowsHollowProcesses}}
}

type hollowDLL struct {
	base, address uint64
	path          evidence.Value
	layer         string
}
type hollowFinding struct {
	rule, note string
	base       uint64
	region     *analysisVADRange
	dll        *hollowDLL
}

func hollowPath(value evidence.Value) string {
	if value.Kind != "string" || value.String() == "" {
		return "<Non-File Backed Region>"
	}
	return value.String()
}

// Both dictionaries in the pinned plugin keep the last value at a duplicate
// base, but retain the insertion order of the first appearance of that base.
func hollowDLLMap(entries []hollowDLL) []hollowDLL {
	var result []hollowDLL
	indexes := map[uint64]int{}
	for _, entry := range entries {
		if i, ok := indexes[entry.base]; ok {
			result[i] = entry
		} else {
			indexes[entry.base] = len(result)
			result = append(result, entry)
		}
	}
	return result
}
func hollowVADMap(ranges []analysisVADRange) map[uint64]analysisVADRange {
	result := make(map[uint64]analysisVADRange, len(ranges))
	for _, region := range ranges {
		result[region.start] = region
	}
	return result
}

func hollowProcessNotes(section uint64, image *uint64, vads map[uint64]analysisVADRange, dlls []hollowDLL) []hollowFinding {
	var findings []hollowFinding
	if image != nil && *image != section {
		findings = append(findings, hollowFinding{rule: "image_base_mismatch", base: section, note: fmt.Sprintf("The ImageBaseAddress reported from the PEB (%#x) does not match the process SectionBaseAddress (%#x)", *image, section)})
	}
	if region, ok := vads[section]; !ok {
		findings = append(findings, hollowFinding{rule: "executable_vad_missing", base: section, note: fmt.Sprintf("There is no VAD starting at the base address of the process executable (%#x)", section)})
	} else if region.protection != "PAGE_EXECUTE_WRITECOPY" {
		findings = append(findings, hollowFinding{rule: "executable_protection", base: section, region: &region, note: fmt.Sprintf("Unexpected protection (%s) for VAD hosting the process executable (%#x) with path %s", region.protection, section, hollowPath(region.file))})
	}
	for _, dll := range dlls {
		region, ok := vads[dll.base]
		if !ok || region.protection == "PAGE_EXECUTE_WRITECOPY" {
			continue
		}
		path := "-" // UnreadableValue.__str__ in the pinned renderer.
		if dll.path.Kind == "string" {
			path = dll.path.String()
		}
		findings = append(findings, hollowFinding{rule: "dll_protection", base: dll.base, region: &region, dll: &dll, note: fmt.Sprintf("Unexpected protection (%s) for DLL in the PEB's load order list (%#x) with path %s", region.protection, dll.base, path)})
	}
	return findings
}

type hollowLoaderTarget struct {
	peb uint64
	env plugin.Environment
}

// Native PEB first, followed by the separate WoW64 PEB, like load_order_modules.
// Unreadable pointers are retained through issue instead of silently omitted.
func hollowLoaderTargets(ctx context.Context, e plugin.Environment, process uint64, layer memory.MemoryLayer, issue func(string, error) error) ([]hollowLoaderTarget, error) {
	native := e
	native.Kernel = layer
	native.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
	var targets []hollowLoaderTarget
	peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
	if err != nil {
		if err = issue("peb_pointer_unreadable", err); err != nil {
			return nil, err
		}
	} else if peb != 0 {
		targets = append(targets, hollowLoaderTarget{peb, native})
	}
	if e.Symbols.PointerSize() != 8 {
		return targets, nil
	}
	var wow uint64
	for _, path := range []string{"WoW64Process", "Wow64Process"} {
		if _, err = e.Objects.Field("_EPROCESS", path); err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				continue
			}
			return nil, err
		}
		wow, err = e.Objects.Uint(ctx, process, "_EPROCESS", path)
		if err != nil {
			if err = issue("wow64_pointer_unreadable", err); err != nil {
				return nil, err
			}
			return targets, nil
		}
		break
	}
	if wow == 0 {
		return targets, nil
	}
	peb32 := wow
	for _, candidate := range []struct{ typ, path string }{{"_EWOW64PROCESS", "Peb"}, {"_WOW64_PROCESS", "Wow64"}} {
		if _, err := e.Symbols.Type(candidate.typ); err != nil {
			continue
		}
		peb32, err = e.Objects.Uint(ctx, wow, candidate.typ, candidate.path)
		if err != nil {
			if err = issue("wow64_peb_unreadable", err); err != nil {
				return nil, err
			}
			return targets, nil
		}
		break
	}
	if peb32 != 0 {
		table, err := wowLoaderSymbols()
		if err != nil {
			return nil, err
		}
		native.Symbols = table
		native.Objects = &object.Reader{Layer: layer, Symbols: table}
		targets = append(targets, hollowLoaderTarget{peb32, native})
	}
	return targets, nil
}

func hollowLoadDLLs(ctx context.Context, targets []hollowLoaderTarget, max int, issue func(string, error) error) ([]hollowDLL, error) {
	var entries []hollowDLL
	for _, target := range targets {
		user := target.env
		ldr, err := user.Objects.Uint(ctx, target.peb, "_PEB", "Ldr")
		if err != nil {
			if err = issue("peb_loader_unreadable", err); err != nil {
				return nil, err
			}
			continue
		}
		head, err := user.Objects.Field("_PEB_LDR_DATA", "InLoadOrderModuleList")
		if err != nil {
			return nil, err
		}
		list, err := memory.Add(ldr, head.Offset)
		if err != nil {
			return nil, err
		}
		link, err := user.Objects.Field("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")
		if err != nil {
			return nil, err
		}
		var stopped uint64
		err = walkVerForwardList(ctx, user, list, link.Offset, max, func(address uint64) error {
			base, err := user.Objects.Uint(ctx, address, "_LDR_DATA_TABLE_ENTRY", "DllBase")
			if err != nil {
				return issue("dll_base_unreadable", err)
			}
			value, readErr := volatilityObjectString(ctx, user.Kernel, user.Objects, address, "_LDR_DATA_TABLE_ENTRY", "FullDllName")
			if readErr != nil {
				value = evidence.Missing("dll_path_unreadable", readErr)
				if err = issue("dll_path_unreadable", readErr); err != nil {
					return err
				}
			}
			entries = append(entries, hollowDLL{base, address, value, user.Kernel.Name()})
			return nil
		}, &stopped)
		if err != nil {
			return nil, err
		}
		if stopped != 0 {
			if err = issue("loader_list_stopped", fmt.Errorf("loader list at %#x ended at an unreadable or invalid entry", list)); err != nil {
				return nil, err
			}
		}
	}
	return hollowDLLMap(entries), nil
}

func hollowProcessRow(layer string, process uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", process)}}
	for _, column := range windowsHollowProcessPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	return row
}

func windowsHollowProcesses(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.hollowprocesses requires a kernel layer and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	for _, check := range []struct{ typ, path string }{{"_EPROCESS", "Peb"}, {"_EPROCESS", "SectionBaseAddress"}, {"_PEB", "ImageBaseAddress"}} {
		if _, err = e.Objects.Field(check.typ, check.path); err != nil {
			return err
		}
	}
	var processes, shortDLLs, shortVADs, checked, findings, diagnostics uint64
	protect := vadProtectionCache{env: e}
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		newRow := func(kind string) evidence.Row {
			row := hollowProcessRow(e.Kernel.Name(), process)
			row.Cells["PID"] = evidence.Number(pid)
			row.Cells["Process"] = evidence.Text(name)
			row.Cells["ProcessOffset"] = evidence.Address(process)
			row.Cells["ProcessIdentity"] = evidence.Text(identity)
			row.Cells["RecordType"] = evidence.Text(kind)
			return row
		}
		issue := func(stage string, cause error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			diagnostics++
			row := newRow("diagnostic")
			row.Cells["Error"] = evidence.Missing(stage, cause)
			return out(row)
		}
		layer, err := processMemory(ctx, e, process, 0, identity)
		if err != nil {
			return issue("process_space_unavailable", err)
		}
		targets, err := hollowLoaderTargets(ctx, e, process, layer, issue)
		if err != nil {
			return err
		}
		dlls, err := hollowLoadDLLs(ctx, targets, max, issue)
		if err != nil {
			return err
		}
		if len(dlls) < 3 {
			shortDLLs++
			return nil
		}
		ranges, err := analysisVADRanges(ctx, e, process, max, &protect)
		if err != nil {
			return err
		}
		vads := hollowVADMap(ranges)
		if len(vads) < 5 {
			shortVADs++
			return nil
		}
		checked++
		section, err := e.Objects.Uint(ctx, process, "_EPROCESS", "SectionBaseAddress")
		if err != nil {
			return err
		}
		var image *uint64
		peb, readErr := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
		if readErr == nil {
			user := &object.Reader{Layer: layer, Symbols: e.Symbols}
			base, err := user.Uint(ctx, peb, "_PEB", "ImageBaseAddress")
			readErr = err
			if readErr == nil {
				image = &base
			}
		}
		if readErr != nil {
			if err = issue("image_base_unreadable", readErr); err != nil {
				return err
			}
		}
		for _, finding := range hollowProcessNotes(section, image, vads, dlls) {
			findings++
			row := newRow("finding")
			row.Cells["Notes"] = evidence.Text(finding.note)
			row.Cells["Rule"] = evidence.Text(finding.rule)
			row.Cells["Base"] = evidence.Address(finding.base)
			row.Cells["SectionBase"] = evidence.Address(section)
			if image != nil {
				row.Cells["ImageBase"] = evidence.Address(*image)
			} else {
				row.Cells["ImageBase"] = evidence.Missing("image_base_unreadable", readErr)
			}
			if finding.region != nil {
				row.Cells["VADOffset"] = evidence.Address(finding.region.address)
				row.Cells["Protection"] = evidence.Text(finding.region.protection)
				row.Cells["Path"] = evidence.Text(hollowPath(finding.region.file))
				if finding.region.file.Error != "" {
					row.Cells["PathError"] = finding.region.file
				}
			}
			if finding.dll != nil {
				row.Cells["LoaderOffset"] = evidence.Address(finding.dll.address)
				row.Cells["LoaderLayer"] = evidence.Text(finding.dll.layer)
				row.Cells["Path"] = finding.dll.path
				if finding.dll.path.Error != "" {
					row.Cells["PathError"] = finding.dll.path
				}
			}
			if err = out(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	row := hollowProcessRow(e.Kernel.Name(), 0)
	row.Provenance.Offset = ""
	row.Cells["RecordType"] = evidence.Text("summary")
	row.Cells["Coverage"] = poolCoverage(map[string]string{"processes": formatCount(processes), "short_dll_sets": formatCount(shortDLLs), "short_vad_sets": formatCount(shortVADs), "checked": formatCount(checked), "findings": formatCount(findings), "diagnostics": formatCount(diagnostics)})
	return out(row)
}
