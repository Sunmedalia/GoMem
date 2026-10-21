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
		{Name: "Load Arguments", Kind: "string"}, {Name: "File Output", Kind: "string"},
	}
	for _, column := range linuxModxviewPlugins()[0].spec.Columns {
		columns = append(columns, column)
	}
	return []builtin{{plugin.Spec{
		Name: "linux.check_modules", Upstream: "linux.malware.check_modules.Check_modules", Platform: "linux", NeedsKernel: true,
		Description: "Report sysfs modules whose names are absent from the active module list",
		Parameters: []plugin.Parameter{
			{Name: "plain-taints", Kind: "bool", Default: "false", Description: "Display pinned plain taint characters instead of descriptions"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Shared list visit bound, 1..1000000"},
		},
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
		row, err := linuxCheckModuleRow(s, *module, plain)
		if err != nil {
			return err
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

func linuxCheckModuleRow(s *linuxModuleSources, module linuxModuleInfo, plain bool) (evidence.Row, error) {
	fields := map[string]evidence.Value{}
	n := s.reader(fields)
	row := linuxModuleRow(s.e, module.offset, "kset_only", "SysFs")
	row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	row.Cells["Name"] = evidence.Text(module.name)
	row.Cells["Module Name"] = evidence.Text(module.name)
	row.Cells["Offset"] = evidence.Address(module.offset)
	row.Cells["Base"] = evidence.Address(module.base)
	row.Cells["Size"] = evidence.Number(module.size)
	end, err := memory.Add(module.base, module.size)
	if err == nil {
		row.Cells["End"] = evidence.Address(end)
	} else {
		s.failures.add(err)
		row.Cells["End"] = evidence.Missing("module_range_overflow", err)
	}
	initSize, initErr := n.layout(module.offset, "init")
	core, coreErr := n.layout(module.offset, "core")
	if initErr != nil || coreErr != nil {
		err = initErr
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
	row.Cells["Status"] = evidence.Text("kset_only")
	return row, nil
}
