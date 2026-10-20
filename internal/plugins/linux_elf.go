package plugins

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/elfimage"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxELFParameters() []plugin.Parameter {
	return []plugin.Parameter{{Name: "dump", Kind: "bool", Default: "false", Description: "Extract page-rounded ELF load segments into the case"}, {Name: "elf-layout", Kind: "string", Default: "mapped", Description: "mapped uses runtime load addresses; reference reproduces the pinned baseline's base-plus-p_vaddr layout"}, {Name: "max-elf-size", Kind: "uint", Default: "1073741824", Description: "Maximum total ELF extraction bytes (1..4294967295)"}}
}

func linuxELFPlugins() []builtin {
	parameters := []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated task PID filter"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-process/task traversal bound"}, {Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total VMA traversal bound (1..1000000)"}}
	parameters = append(parameters, linuxELFParameters()...)
	return []builtin{{plugin.Spec{Name: "linux.elfs", Upstream: "linux.elfs.Elfs", Platform: "linux", NeedsKernel: true, Description: "Enumerate VMA-start ELF signatures and extract mapped or reference load-segment layouts", Parameters: parameters,
		Columns: []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Start", Kind: "address"}, {Name: "End", Kind: "address"}, {Name: "Path", Kind: "string"}, {Name: "PathRaw", Kind: "bytes"}, {Name: "PathScope", Kind: "string"}, {Name: "Offset", Kind: "address"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "ELF", Kind: "structure"}, {Name: "FileOutput", Kind: "artifact"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "string"}}}, linuxELFs}}
}

func linuxELFOptions(p map[string]string) (bool, string, uint64, error) {
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return false, "", 0, err
	}
	layout := p["elf-layout"]
	if layout != elfimage.Mapped && layout != elfimage.Reference {
		return false, "", 0, fmt.Errorf("elf-layout must be mapped or reference")
	}
	limit, err := strconv.ParseUint(p["max-elf-size"], 0, 64)
	if err != nil || limit == 0 || limit > elfimage.MaxSize {
		return false, "", 0, fmt.Errorf("max-elf-size must be 1..4294967295")
	}
	return dump, layout, limit, nil
}

type linuxELFRegion struct{ object, start, end uint64 }

func linuxELFRegions(ctx context.Context, e plugin.Environment, mm uint64, max int) ([]linuxELFRegion, uint64, error) {
	addresses, err := linuxVMAAddresses(ctx, e, mm, max)
	if err != nil {
		return nil, uint64(max), err
	}
	visited := uint64(len(addresses))
	regions := make([]linuxELFRegion, 0, len(addresses))
	for _, address := range addresses {
		start, err := e.Objects.Uint(ctx, address, "vm_area_struct", "vm_start")
		if err != nil {
			return nil, visited, err
		}
		end, err := e.Objects.Uint(ctx, address, "vm_area_struct", "vm_end")
		if err != nil {
			return nil, visited, err
		}
		owner, err := e.Objects.Uint(ctx, address, "vm_area_struct", "vm_mm")
		if err != nil {
			return nil, visited, err
		}
		if owner != mm || start >= end || start&4095 != 0 || end&4095 != 0 {
			return nil, visited, fmt.Errorf("invalid ELF VMA owner/interval at %#x", address)
		}
		regions = append(regions, linuxELFRegion{address, start, end})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
	for i := 1; i < len(regions); i++ {
		if regions[i].start < regions[i-1].end {
			return nil, visited, fmt.Errorf("overlapping ELF VMAs at %#x", regions[i].object)
		}
	}
	return regions, visited, nil
}

func dumpLinuxELF(ctx context.Context, e plugin.Environment, space memory.MemoryLayer, pid, base uint64, layout string, limit uint64) (evidence.Value, evidence.Value, error) {
	image, err := elfimage.Parse(ctx, space, base)
	if err != nil {
		return evidence.Missing("invalid_or_unreadable_elf", err), evidence.Missing("invalid_or_unreadable_elf", err), err
	}
	plan, err := image.Plan(layout, limit)
	if err != nil {
		return evidence.Missing("elf_layout_unavailable", err), evidence.Missing("elf_layout_unavailable", err), err
	}
	ranges := make([]extractionRange, 0, len(plan.Spans))
	for _, span := range plan.Spans {
		ranges = append(ranges, extractionRange{span.Source, span.Size})
	}
	output, err := extractRanges(ctx, e, space, fmt.Sprintf("pid.%d.elf.%#x.%s.dmp", pid, base, layout), base, ranges)
	return output, evidence.Value{Kind: "structure", Data: plan.Evidence()}, err
}

func linuxELFs(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	dump, layout, limit, err := linuxELFOptions(p)
	if err != nil {
		return err
	}
	maxRegions, err := strconv.ParseUint(p["max-regions"], 0, 32)
	if err != nil || maxRegions == 0 || maxRegions > 1000000 {
		return fmt.Errorf("max-regions must be 1..1000000")
	}
	var traversed uint64
	var failures pluginFailures
	err = visitLinuxProcesses(ctx, e, max, pids, func(task, pid uint64, name string, start evidence.Value) error {
		stamp := ""
		if start.Kind != "missing" {
			stamp = start.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, pid, stamp)
		baseRow := func() evidence.Row {
			row := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "ProcessOffset": evidence.Address(task), "ProcessIdentity": evidence.Text(identity), "RecordType": evidence.Text("elf"), "Error": evidence.Missing("not_applicable", nil), "ELF": evidence.Missing("not_requested", nil), "FileOutput": evidence.Missing("not_requested", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", task)}}
			for _, key := range []string{"Start", "End", "Path", "PathRaw", "PathScope", "Offset"} {
				row.Cells[key] = evidence.Missing("not_reached", nil)
			}
			return row
		}
		diagnostic := func(err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures.add(err)
			row := baseRow()
			row.Cells["RecordType"], row.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("elf_enumeration_incomplete", err)
			return out(row)
		}
		mm, err := e.Objects.Uint(ctx, task, "task_struct", "mm")
		if err != nil {
			return diagnostic(err)
		}
		if mm == 0 {
			return nil
		}
		regions, visited, err := linuxELFRegions(ctx, e, mm, int(min(uint64(max), maxRegions-traversed)))
		traversed += visited
		if err != nil {
			return diagnostic(err)
		}
		space, err := processMemory(ctx, e, task, mm, identity)
		if err != nil {
			return diagnostic(err)
		}
		for _, r := range regions {
			magic, readErr := memory.Read(ctx, space, r.start, 4)
			if readErr == nil && string(magic) != "\x7fELF" {
				continue
			}
			row := baseRow()
			row.Cells["Start"], row.Cells["End"], row.Cells["Offset"] = evidence.Address(r.start), evidence.Address(r.end), evidence.Address(r.object)
			row.Provenance.Offset = fmt.Sprintf("0x%x", r.object)
			if readErr != nil {
				row.Cells["RecordType"], row.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing("elf_signature_unreadable", readErr)
				failures.add(readErr)
			} else {
				file, er := e.Objects.Uint(ctx, r.object, "vm_area_struct", "vm_file")
				if er != nil {
					row.Cells["Path"], row.Cells["PathRaw"], row.Cells["PathScope"] = evidence.Missing("file_pointer_unreadable", er), evidence.Missing("file_pointer_unreadable", er), evidence.Missing("file_pointer_unreadable", er)
				} else {
					row.Cells["Path"], row.Cells["PathRaw"], _, _, _, _, _, row.Cells["PathScope"] = linuxVMAFile(ctx, e, task, mm, r.start, r.end, file)
				}
				if dump {
					var er error
					row.Cells["FileOutput"], row.Cells["ELF"], er = dumpLinuxELF(ctx, e, space, pid, r.start, layout, limit)
					if er != nil {
						row.Cells["Error"] = evidence.Missing("elf_extraction_failed", er)
						failures.add(er)
					}
				}
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := out(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return failures.err("Linux ELF enumeration/extraction")
}

// The pinned pslist profile selects vm_start == mm.start_code exactly. This
// deliberate selection rule is distinct from enumerating every mapped ELF.
func linuxMainELF(ctx context.Context, e plugin.Environment, task, tid uint64, identity, layout string, limit uint64, max int) (output, plan, base evidence.Value, err error) {
	output, plan, base = evidence.Missing("main_elf_unavailable", nil), evidence.Missing("main_elf_unavailable", nil), evidence.Missing("main_elf_unavailable", nil)
	mm, err := e.Objects.Uint(ctx, task, "task_struct", "mm")
	if err == nil && mm == 0 {
		return evidence.Missing("no_user_mm", nil), evidence.Missing("no_user_mm", nil), evidence.Missing("no_user_mm", nil), nil
	}
	if err != nil {
		return output, plan, base, err
	}
	start, err := e.Objects.Uint(ctx, mm, "mm_struct", "start_code")
	if err != nil {
		return output, plan, base, err
	}
	base = evidence.Address(start)
	regions, _, err := linuxELFRegions(ctx, e, mm, max)
	if err != nil {
		return output, plan, base, err
	}
	for _, r := range regions {
		if r.start != start {
			continue
		}
		space, er := processMemory(ctx, e, task, mm, identity)
		if er != nil {
			return output, plan, base, er
		}
		output, plan, err = dumpLinuxELF(ctx, e, space, tid, start, layout, limit)
		return
	}
	return output, plan, base, fmt.Errorf("no VMA starts at mm.start_code %#x", start)
}
