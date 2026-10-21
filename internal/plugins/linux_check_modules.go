package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
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
		row.Cells["Load Arguments"] = evidence.Missing("module_arguments_unreadable", argErr)
	} else {
		row.Cells["Load Arguments"] = evidence.Text(arguments)
	}
	row.Cells["File Output"] = evidence.Missing("not_requested", nil)
	row.Cells["Status"] = evidence.Text("kset_only")
	return row, nil
}

func linuxModuleArguments(n *linuxModuleRead, module uint64) (string, error) {
	present, err := n.has("module", "kp")
	if err != nil || !present {
		return "", err
	}
	count, err := n.uint(module, "module", "num_kp")
	if err != nil {
		return "", err
	}
	if count > 128 {
		return "", fmt.Errorf("module parameter count %d exceeds 128", count)
	}
	if count == 0 {
		return "", nil
	}
	kp, err := n.uint(module, "module", "kp")
	if err != nil {
		return "", err
	}
	param, err := n.e.Symbols.Type("kernel_param")
	if err != nil || param.Size == 0 {
		return "", fmt.Errorf("kernel_param stride unavailable: %v", err)
	}
	stride := param.Size
	var parts []string
	for i := uint64(0); i < count; i++ {
		if err := n.ctx.Err(); err != nil {
			return "", err
		}
		if stride > (^uint64(0)-kp)/count {
			return "", fmt.Errorf("kernel parameter address overflow")
		}
		at, err := memory.Add(kp, i*stride)
		if err != nil {
			return "", err
		}
		namePtr, err := n.uint(at, "kernel_param", "name")
		if err != nil {
			continue
		}
		raw, proof, err := linuxCaptureRange(n.ctx, n.e.Kernel, namePtr, 32)
		n.fields[fmt.Sprintf("param_name@%x", at)] = proof
		if err != nil {
			n.failures.add(err)
			continue
		}
		name := spoofDecoded(raw)
		value, err := linuxKernelParamValue(n, at)
		if err != nil {
			n.failures.add(err)
			continue
		}
		parts = append(parts, name+"="+value)
	}
	return joinComma(parts), nil
}

func linuxKernelParamValue(n *linuxModuleRead, param uint64) (string, error) {
	getter, err := linuxParamGetter(n, param)
	if err != nil || getter == 0 {
		return "", err
	}
	handlers := map[string]string{
		"param_get_invbool": "int", "param_get_bool": "int", "param_get_int": "int",
		"param_get_ulong": "long unsigned int", "param_get_ullong": "long long unsigned int",
		"param_get_long": "long int", "param_get_uint": "unsigned int",
		"param_get_ushort": "short unsigned int", "param_get_short": "short int", "param_get_byte": "char",
	}
	for name, typ := range handlers {
		address, err := n.e.Symbol(name)
		if err != nil || address != getter {
			continue
		}
		arg, err := n.uint(param, "kernel_param", "arg")
		if err != nil {
			return "", err
		}
		ref, err := n.e.Symbols.Type(typ)
		if err != nil {
			return "", err
		}
		value, err := n.scalar(arg, symbols.TypeRef{Kind: "base", Name: typ})
		_ = ref
		if err != nil {
			return "", err
		}
		if ref.Signed {
			return strconv.FormatInt(int64(value), 10), nil
		}
		return strconv.FormatUint(value, 10), nil
	}
	for _, name := range []string{"param_get_string", "param_get_charp"} {
		address, err := n.e.Symbol(name)
		if err != nil || address != getter {
			continue
		}
		return "<param>", nil
	}
	return "", nil
}

func linuxParamGetter(n *linuxModuleRead, param uint64) (uint64, error) {
	if ok, err := n.has("kernel_param", "get"); err != nil {
		return 0, err
	} else if ok {
		return n.uint(param, "kernel_param", "get")
	}
	return n.uint(param, "kernel_param", "ops.get")
}

func joinComma(parts []string) string {
	out := ""
	for i, part := range parts {
		if i != 0 {
			out += ", "
		}
		out += part
	}
	return out
}
