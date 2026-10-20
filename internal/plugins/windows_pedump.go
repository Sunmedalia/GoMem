package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func pePlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.pedump", Upstream: "windows.pedump.PEDump", Platform: "windows", NeedsKernel: true, Description: "Reconstruct mapped PE images with explicit header patches and missing-page evidence",
		Parameters: []plugin.Parameter{{Name: "base", Kind: "string", Description: "Required mapped PE base address"}, {Name: "pid", Kind: "string", Description: "Process IDs to select, unless kernel-module=true"}, {Name: "kernel-module", Kind: "bool", Default: "false", Description: "Use kernel or verified session spaces instead of selected processes"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process traversal bound"}, {Name: "max-session-layers", Kind: "uint", Default: "256", Description: "Maximum unique session roots cached for kernel extraction (1..4096)"}},
		Columns:    []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Base", Kind: "address"}, {Name: "Size", Kind: "uint64"}, {Name: "Machine", Kind: "uint64"}, {Name: "Patches", Kind: "structure"}, {Name: "Reconstruction", Kind: "string"}, {Name: "FileOutput", Kind: "artifact"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "ExtractionAttempts", Kind: "structure"}}}, windowsPEDump}}
}

func dumpPE(ctx context.Context, e plugin.Environment, layer memory.MemoryLayer, name string, base uint64) (evidence.Value, *pe.Image, error) {
	image, err := pe.Plan(ctx, layer, base)
	if err != nil {
		return evidence.Missing("invalid_or_unreadable_pe", err), nil, err
	}
	file, err := extractRegion(ctx, e, image.Overlay(layer), name, base, image.Size)
	return file, image, err
}

func windowsPEDump(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	base, err := strconv.ParseUint(p["base"], 0, 64)
	if err != nil || base == 0 {
		return fmt.Errorf("base must be a nonzero mapped PE address")
	}
	kernel, err := strconv.ParseBool(p["kernel-module"])
	if err != nil {
		return err
	}
	if kernel && len(pids) > 0 || !kernel && len(pids) == 0 {
		return fmt.Errorf("select either kernel-module=true or a nonempty pid set")
	}
	maxLayers, err := strconv.ParseUint(p["max-session-layers"], 0, 32)
	if err != nil || maxLayers == 0 || maxLayers > 4096 {
		return fmt.Errorf("max-session-layers must be 1..4096")
	}
	attempts := evidence.Missing("explicit_process_address_space", nil)
	var failures pluginFailures
	emit := func(layer memory.MemoryLayer, process, pid uint64, name, identity string, spaceErr error) error {
		file := evidence.Missing("process_address_space_unavailable", spaceErr)
		if process == 0 {
			file = evidence.Missing("kernel_address_space_unavailable", spaceErr)
		}
		var image *pe.Image
		dumpErr := spaceErr
		if dumpErr == nil {
			file, image, dumpErr = dumpPE(ctx, e, layer, fmt.Sprintf("PE.%#x.%d.%#x.dmp", process, pid, base), base)
		}
		size, machine, patches := evidence.Missing("pe_plan_unavailable", dumpErr), evidence.Missing("pe_plan_unavailable", dumpErr), evidence.Missing("pe_plan_unavailable", dumpErr)
		if image != nil {
			size, machine = evidence.Number(image.Size), evidence.Number(uint64(image.Machine))
			patches = evidence.Value{Kind: "structure", Data: image.Patches}
		}
		layerName := e.Kernel.Name()
		if layer != nil {
			layerName = layer.Name()
		}
		row := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "Base": evidence.Address(base), "Size": size, "Machine": machine, "Patches": patches, "Reconstruction": evidence.Text("mapped-image slack retained; ImageBase and section raw ranges rewritten; not original disk layout"), "FileOutput": file, "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity), "ExtractionAttempts": attempts}, Provenance: evidence.Provenance{Layer: layerName, Offset: fmt.Sprintf("0x%x", base)}}
		if process == 0 {
			row.Cells["ProcessOffset"] = evidence.Missing("kernel_address_space", nil)
			row.Cells["ProcessIdentity"] = evidence.Missing("kernel_address_space", nil)
		}
		if err := out(row); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		failures.add(dumpErr)
		return nil
	}
	if kernel {
		layers := windowsModuleLayers{env: e, max: max, maxLayers: int(maxLayers)}
		layer, tried, spaceErr := layers.find(ctx, base)
		attempts = evidence.Value{Kind: "structure", Data: tried}
		if err := emit(layer, 0, 4, "Kernel", "", spaceErr); err != nil {
			return err
		}
		return failures.err("kernel PE extraction")
	}
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		layer, err := processMemory(ctx, e, process, 0, identity)
		return emit(layer, process, pid, name, identity, err)
	})
	if err != nil {
		return err
	}
	return failures.err("process PE extraction")
}
