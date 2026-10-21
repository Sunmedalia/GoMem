package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsMemmapPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.memmap", Upstream: "windows.memmap.Memmap", Platform: "windows", NeedsKernel: true,
		Description: "Print the virtual, physical and file layout of active process address spaces",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional single process ID; every other process is excluded"},
			{Name: "dump", Kind: "bool", Default: "false", Description: "Extract listed memory segments into the case"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active process list traversal bound"},
		},
		Columns: []evidence.Column{
			{Name: "Virtual", Kind: "address"}, {Name: "Physical", Kind: "address"}, {Name: "Size", Kind: "uint64"},
			{Name: "FileOffset", Kind: "uint64"}, {Name: "FileOutput", Kind: "string"}, {Name: "PID", Kind: "uint64"},
			{Name: "Process", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "Identity", Kind: "string"},
			{Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
		},
	}, windowsMemmap}}
}

type memmapStats struct {
	selected, pidUnread, dtbUnread, empty, rows, bytes, dumpErrors, nameUnread uint64
}

func (s memmapStats) coverage(pid string) map[string]string {
	return map[string]string{
		"pid": pid, "selected": formatCount(s.selected), "pid_unreadable": formatCount(s.pidUnread),
		"dtb_unreadable": formatCount(s.dtbUnread), "empty": formatCount(s.empty), "rows": formatCount(s.rows),
		"bytes": formatCount(s.bytes), "dump_errors": formatCount(s.dumpErrors), "name_unreadable": formatCount(s.nameUnread),
	}
}

func windowsMemmap(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if p == nil {
		p = map[string]string{}
	}
	if p["max-nodes"] == "" {
		p["max-nodes"] = "131072"
	}
	if p["dump"] == "" {
		p["dump"] = "false"
	}
	maxNodes, err := strconv.ParseUint(p["max-nodes"], 0, 32)
	if err != nil || maxNodes == 0 || maxNodes > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return err
	}
	if dump && e.Artifacts == nil {
		return fmt.Errorf("windows.memmap dump requires a case artifact sink")
	}
	switch e.Architecture {
	case "x64", "x86", "pae":
	default:
		return fmt.Errorf("windows.memmap requires an Intel address space, not %s", e.Architecture)
	}
	if _, err = e.Objects.Field("_EPROCESS", "Pcb.DirectoryTableBase"); err != nil {
		return err
	}
	selected, label, err := singleProcessID(p["pid"])
	if err != nil {
		return err
	}
	head, err := e.Symbol("PsActiveProcessHead")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return err
	}
	stats := memmapStats{}
	err = e.Objects.WalkList(ctx, head, links.Offset, int(maxNodes), func(process uint64) error {
		pid, err := e.Objects.Uint(ctx, process, "_EPROCESS", "UniqueProcessId")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			stats.pidUnread++
			return nil
		}
		if selected != nil && !selected[pid] {
			return nil
		}
		stats.selected++
		name, err := e.Objects.String(ctx, process, "_EPROCESS", "ImageFileName", 64)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			stats.nameUnread++
			name = ""
		}
		created, _ := windowsTime(ctx, e, process, "_EPROCESS", "CreateTime")
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		layer, err := processMemory(ctx, e, process, 0, identity)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			stats.dtbUnread++
			return nil
		}
		virt, ok := layer.(*memory.Virtual)
		if !ok {
			return fmt.Errorf("process %d layer is not virtual", pid)
		}
		intel, ok := virt.Translator.(*memory.Intel)
		if !ok {
			return fmt.Errorf("process %d translator is not an Intel page table", pid)
		}
		maps, err := intel.PageMappings(ctx)
		if err != nil {
			return err
		}
		if len(maps) == 0 {
			stats.empty++
			return nil
		}
		outputs := make([]string, len(maps))
		filename := fmt.Sprintf("pid.%d.dmp", pid)
		for i := range outputs {
			outputs[i] = "Disabled"
		}
		if dump {
			if err = dumpProcessMaps(ctx, e, virt, filename, maps, outputs, &stats); err != nil {
				return err
			}
		}
		var fileOffset uint64
		for i, span := range maps {
			next, err := memory.Add(fileOffset, span.Length)
			if err != nil {
				return err
			}
			row := evidence.Row{Cells: map[string]evidence.Value{
				"Virtual": evidence.Address(span.Virtual), "Physical": evidence.Address(span.Physical),
				"Size": evidence.Number(span.Length), "FileOffset": evidence.Number(fileOffset),
				"FileOutput": evidence.Text(outputs[i]), "PID": evidence.Number(pid), "Process": evidence.Text(name),
				"ProcessOffset": evidence.Address(process), "Identity": evidence.Text(identity),
				"RecordType": evidence.Text("map"), "Coverage": evidence.Missing("not_applicable", nil),
			}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", span.Virtual)}}
			if err = out(row); err != nil {
				return err
			}
			stats.rows++
			sum, err := memory.Add(stats.bytes, span.Length)
			if err != nil {
				return err
			}
			stats.bytes = sum
			fileOffset = next
		}
		return nil
	})
	if err != nil {
		return err
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{
		"Virtual": evidence.Missing("not_applicable", nil), "Physical": evidence.Missing("not_applicable", nil),
		"Size": evidence.Missing("not_applicable", nil), "FileOffset": evidence.Missing("not_applicable", nil),
		"FileOutput": evidence.Missing("not_applicable", nil), "PID": evidence.Missing("not_applicable", nil),
		"Process": evidence.Missing("not_applicable", nil), "ProcessOffset": evidence.Missing("not_applicable", nil),
		"Identity": evidence.Missing("not_applicable", nil), "RecordType": evidence.Text("summary"),
		"Coverage": poolCoverage(stats.coverage(label)),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name()}})
}

func singleProcessID(raw string) (map[uint64]bool, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "all", nil
	}
	if strings.Contains(raw, ",") {
		return nil, "", fmt.Errorf("pid must be one integer")
	}
	pid, err := strconv.ParseUint(raw, 0, 64)
	if err != nil {
		return nil, "", fmt.Errorf("pid: %w", err)
	}
	return map[uint64]bool{pid: true}, raw, nil
}

func dumpProcessMaps(ctx context.Context, e plugin.Environment, layer *memory.Virtual, filename string, maps []memory.PageMapping, outputs []string, stats *memmapStats) error {
	var total uint64
	for _, span := range maps {
		next, err := memory.Add(total, span.Length)
		if err != nil {
			return err
		}
		total = next
	}
	w, err := e.Artifacts.Create(ctx, evidence.ArtifactRequest{Name: filename, Size: total, Layer: layer.Name(), Offset: "0x0"})
	if err != nil {
		return err
	}
	var cause error
	for i, span := range maps {
		written, err := writePhysical(ctx, e.Physical, w, span.Physical, span.Length)
		if err != nil {
			stats.dumpErrors++
			outputs[i] = "Error outputting to file"
			if cause == nil {
				cause = err
			}
			if written < span.Length {
				if padErr := w.PadZero(ctx, span.Length-written, span.Physical+written, e.Physical.Name(), err); padErr != nil {
					_, finishErr := w.Finish(ctx, padErr)
					return joinErr(padErr, finishErr)
				}
			}
			continue
		}
		outputs[i] = filename
	}
	_, err = w.Finish(ctx, nil)
	return err
}

func writePhysical(ctx context.Context, layer memory.MemoryLayer, w evidence.ArtifactWriter, phys, size uint64) (uint64, error) {
	buf := make([]byte, 1<<20)
	var written uint64
	for written < size {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n := min(uint64(len(buf)), size-written)
		chunk, err := memory.Read(ctx, layer, phys+written, int(n))
		if err != nil {
			return written, err
		}
		if _, err = w.Write(chunk); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func joinErr(a, b error) error {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return fmt.Errorf("%w; %v", a, b)
}
