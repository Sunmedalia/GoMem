package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxModuleExtractPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.module_extract", Upstream: "linux.module_extract.ModuleExtract", Platform: "linux", NeedsKernel: true, Description: "Reconstruct a kernel module ELF directly from its object address", Parameters: []plugin.Parameter{{Name: "base", Kind: "string", Required: true, Description: "Struct module virtual address (decimal or 0x hex)"}, {Name: "max-module-bytes", Kind: "uint", Default: "67108864", Description: "Per-module source/output allocation bound, 4096..1073741824 bytes"}}, Columns: []evidence.Column{{Name: "Base", Kind: "address"}, {Name: "File Size", Kind: "uint64"}, {Name: "File output", Kind: "artifact"}, {Name: "KernelAddress", Kind: "address"}, {Name: "Name", Kind: "string"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "DumpEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "missing"}}}, linuxModuleExtract}}
}

// Volatility's Intel layer accepts low-48-bit offsets as well as canonical
// addresses. Translate that user coordinate into the native kernel layer while
// retaining the exact input for display and the pinned standalone filename.
func linuxModuleInputAddress(e plugin.Environment, base uint64) (uint64, error) {
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return 0, err
	}
	switch e.Architecture {
	case "x64", "arm64":
		if base <= mask {
			if base&(1<<47) != 0 {
				return base | ^mask, nil
			}
			return base, nil
		}
		if base>>48 != 0xffff || base&(1<<47) == 0 {
			return 0, fmt.Errorf("noncanonical module base %#x", base)
		}
	case "x86", "pae":
		if base > mask {
			return 0, fmt.Errorf("module base exceeds 32-bit address space")
		}
	default:
		return 0, fmt.Errorf("module base uses unsupported architecture %q", e.Architecture)
	}
	return base, nil
}

func linuxModuleExtract(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.module_extract requires kernel memory and symbols")
	}
	if p["base"] == "" {
		return fmt.Errorf("base is required: supply the virtual address of struct module")
	}
	base, err := strconv.ParseUint(p["base"], 0, 64)
	if err != nil {
		return fmt.Errorf("base: %w", err)
	}
	_, maxBytes, err := linuxModuleDumpOptions(map[string]string{"dump": "true", "max-module-bytes": p["max-module-bytes"]})
	if err != nil {
		return err
	}
	address, err := linuxModuleInputAddress(e, base)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	s := &linuxModuleSources{ctx: ctx, e: e, emit: out}
	fields := map[string]evidence.Value{}
	n := s.reader(fields)
	row := evidence.Row{Cells: map[string]evidence.Value{"Base": evidence.Address(base), "KernelAddress": evidence.Address(address), "FieldEvidence": {Kind: "structure", Data: fields}, "DumpEvidence": evidence.Missing("metadata_not_read", nil), "File Size": evidence.Missing("module_elf_unavailable", nil), "File output": evidence.Missing("module_elf_unavailable", nil), "Name": evidence.Missing("metadata_not_read", nil), "RecordType": evidence.Text("module_extract"), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
	finish := func(cause error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if cause != nil {
			row.Cells["Error"] = evidence.Missing("module_extraction_incomplete", cause)
		}
		if err := out(row); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return cause
	}
	_, probe, err := linuxCaptureRange(ctx, e.Kernel, address, 1)
	fields["BaseProbe"] = probe
	if err != nil {
		row.Cells["File output"] = evidence.Missing("module_base_unreadable", err)
		return finish(err)
	}
	name, err := n.text(address, "module", "name")
	if err != nil {
		row.Cells["Name"] = evidence.Missing("module_name_unreadable", err)
		row.Cells["File output"] = evidence.Missing("module_name_unreadable", err)
		return finish(err)
	}
	row.Cells["Name"] = evidence.Text(name)
	linuxDumpModuleAs(s, &row, address, maxBytes, fmt.Sprintf("kernel_module.%s.%#x.elf", name, base))
	row.Cells["File output"] = row.Cells["File Output"]
	delete(row.Cells, "File Output")
	if artifact, ok := row.Cells["File output"].Data.(evidence.Artifact); ok {
		size, parseErr := strconv.ParseUint(artifact.Size, 10, 64)
		if parseErr == nil {
			row.Cells["File Size"] = evidence.Number(size)
		} else {
			s.failures.add(parseErr)
			row.Cells["File Size"] = evidence.Missing("artifact_size_unavailable", parseErr)
		}
	}
	return finish(s.failures.err("Linux module extraction"))
}
