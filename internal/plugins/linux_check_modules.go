package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxCheckModulesPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"}, {Name: "Module Name", Kind: "string"},
		{Name: "Code Size", Kind: "address"}, {Name: "Taints", Kind: "string"},
		{Name: "Load Arguments", Kind: "string"}, {Name: "File Output", Kind: "artifact"}, {Name: "DumpEvidence", Kind: "structure"},
	}
	for _, column := range linuxModxviewPlugins()[0].spec.Columns {
		columns = append(columns, column)
	}
	return []builtin{{plugin.Spec{
		Name: "linux.check_modules", Upstream: "linux.malware.check_modules.Check_modules", Platform: "linux", NeedsKernel: true,
		Description: "Report sysfs modules whose names are absent from the active module list",
		Parameters: append([]plugin.Parameter{
			{Name: "plain-taints", Kind: "bool", Default: "false", Description: "Display pinned plain taint characters instead of descriptions"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Shared list visit bound, 1..1000000"},
		}, linuxModuleDumpParameters()...),
		Columns: columns,
	}, linuxCheckModules}}
}

func linuxCheckModules(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("linux.check_modules requires kernel memory and symbols")
	}
	plain, err := strconv.ParseBool(p["plain-taints"])
	if err != nil {
		return err
	}
	dump, maxBytes, err := linuxModuleDumpOptions(p)
	if err != nil {
		return err
	}
	s, err := linuxGatherModuleLists(ctx, e, p, out)
	if err != nil {
		return err
	}
	active := map[string]bool{}
	for _, module := range s.results["Lsmod"] {
		active[module.name] = true
	}

	var hidden int
	for _, name := range s.ksetOrder {
		if active[name] {
			continue
		}
		module, err := s.info(s.ksetModules[name], "SysFs")
		if err != nil {
			return err
		}
		if module == nil {
			continue
		}
		row, err := linuxModuleDisplayRow(s, *module, plain)
		if err != nil {
			return err
		}
		if dump {
			linuxDumpModule(s, &row, module.offset, maxBytes)
		}
		row.Cells["KObjectName"] = evidence.Text(name)
		if err = s.out(row); err != nil {
			return err
		}
		hidden++
	}
	summary := linuxModuleRow(e, 0, "summary", "check_modules")
	summary.Cells["Address"] = evidence.Missing("not_applicable", nil)
	summary.Provenance.Offset = "check_modules"
	summary.Cells["Coverage"] = poolCoverage(map[string]string{
		"lsmod": strconv.Itoa(len(s.results["Lsmod"])), "sysfs": strconv.Itoa(len(s.results["SysFs"])),
		"kset_only": strconv.Itoa(hidden), "read_layout_errors": strconv.Itoa(s.failures.count),
		"scope": "kset names absent from the active module list; an empty result is a completed comparison",
	})
	if err = s.out(summary); err != nil {
		return err
	}
	return s.failures.err("Linux module list comparison")
}

func linuxModuleDisplayRow(s *linuxModuleSources, module linuxModuleInfo, plain bool) (evidence.Row, error) {
	fields := map[string]evidence.Value{}
	n := s.reader(fields)
	row := linuxModuleRow(s.e, module.offset, "kset_only", "SysFs")
	row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	row.Cells["Offset"] = evidence.Address(module.offset)
	name, nameErr := n.text(module.offset, "module", "name")
	if nameErr != nil {
		row.Cells["Name"] = evidence.Missing("module_name_unreadable", nameErr)
	} else {
		row.Cells["Name"] = evidence.Text(name)
	}
	row.Cells["Module Name"] = row.Cells["Name"]
	n.capture(module.offset, "module", "list")
	base, baseErr := n.layout(module.offset, "base")
	size, sizeErr := n.layout(module.offset, "core")
	row.Cells["Base"] = evidence.Address(base)
	row.Cells["Size"] = evidence.Number(size)
	if baseErr != nil {
		s.failures.add(baseErr)
		row.Cells["Base"] = evidence.Missing("module_base_unavailable", baseErr)
	}
	if sizeErr != nil {
		s.failures.add(sizeErr)
		row.Cells["Size"] = evidence.Missing("module_size_unavailable", sizeErr)
	}
	end, endErr := memory.Add(base, size)
	if baseErr != nil || sizeErr != nil {
		row.Cells["End"] = evidence.Missing("module_range_unavailable", nil)
	} else if endErr != nil {
		s.failures.add(endErr)
		row.Cells["End"] = evidence.Missing("module_range_overflow", endErr)
	} else {
		row.Cells["End"] = evidence.Address(end)
	}
	initSize, initErr := n.layout(module.offset, "init")
	core, coreErr := size, sizeErr
	s.failures.add(initErr)
	if initErr != nil || coreErr != nil {
		err := initErr
		if err == nil {
			err = coreErr
		}
		row.Cells["Code Size"] = evidence.Missing("module_code_size_unavailable", err)
	} else {
		total, err := memory.Add(initSize, core)
		if err != nil {
			s.failures.add(err)
			row.Cells["Code Size"] = evidence.Missing("module_code_size_overflow", err)
		} else {
			row.Cells["Code Size"] = evidence.Address(total)
			row.Cells["InitSize"] = evidence.Number(initSize)
		}
	}
	taints, taintErr := n.uint(module.offset, "module", "taints")
	if taintErr != nil {
		row.Cells["Taints"] = evidence.Missing("module_taints_unreadable", taintErr)
	} else {
		row.Cells["TaintsRaw"] = evidence.Number(taints)
		display, err := linuxModuleTaints(n, taints)
		if err != nil {
			s.failures.add(err)
			row.Cells["Taints"] = evidence.Missing("module_taints_unreadable", err)
		} else if plain {
			row.Cells["Taints"] = evidence.Text(display)
		} else {
			row.Cells["Taints"] = evidence.Text(linuxTaintParsed(display))
		}
	}
	arguments, argErr := linuxModuleArguments(n, module.offset)
	if argErr != nil {
		s.failures.add(argErr)
		fields["LoadArgumentsPartial"] = evidence.Text(arguments)
		row.Cells["Error"] = evidence.Missing("module_arguments_incomplete", argErr)
		row.Cells["Load Arguments"] = evidence.Missing("module_arguments_unreadable", argErr)
	} else {
		row.Cells["Load Arguments"] = evidence.Text(arguments)
	}
	row.Cells["File Output"] = evidence.Missing("not_requested", nil)
	row.Cells["DumpEvidence"] = evidence.Missing("not_requested", nil)
	row.Cells["Status"] = evidence.Text("kset_only")
	return row, nil
}
