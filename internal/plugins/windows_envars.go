package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsEnvarPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.envars", Upstream: "windows.envars.Envars", Platform: "windows", NeedsKernel: true,
		Description: "Read each process PEB environment block; the pinned silent filter is not applied",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process traversal bound"},
			{Name: "max-env", Kind: "uint", Default: "1048576", Description: "Environment byte limit, 1..16777216; native bound, not an upstream parameter"},
			{Name: "silent", Kind: "bool", Default: "false", Description: "Accepted for the pinned flag. The pinned generator reads SILENT, so this does not filter"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"},
			{Name: "Process", Kind: "string"},
			{Name: "Block", Kind: "string"},
			{Name: "Variable", Kind: "string"},
			{Name: "Value", Kind: "string"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "ProcessIdentity", Kind: "string"},
			{Name: "Environment", Kind: "address"},
			{Name: "BlockSize", Kind: "uint64"},
			{Name: "SizeField", Kind: "string"},
			{Name: "Index", Kind: "uint64"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsEnvars}}
}

func windowsEnvars(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	maxEnv, err := strconv.ParseUint(p["max-env"], 0, 32)
	if err != nil || maxEnv == 0 || maxEnv > memory.MaxRead {
		return fmt.Errorf("max-env must be 1..%d", memory.MaxRead)
	}
	silent, err := strconv.ParseBool(p["silent"])
	if err != nil {
		return fmt.Errorf("silent: %w", err)
	}
	var failures pluginFailures
	coverage := map[string]int{"silent_requested": 0, "silent_applied": 0}
	if silent {
		coverage["silent_requested"] = 1
	}
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		rows, cause := readWindowsEnvironment(ctx, e, process, pid, name, created, maxEnv)
		for _, row := range rows {
			switch row.Cells["RecordType"].String() {
			case "variable":
				coverage["variables"]++
			case "diagnostic":
				coverage["diagnostics"]++
			}
		}
		failures.add(cause)
		for _, row := range rows {
			if err := out(row); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	summary := windowsEnvarRow(e, e.Kernel.Name(), 0, "summary")
	data := map[string]any{}
	for key, value := range coverage {
		data[key] = strconv.Itoa(value)
	}
	data["failures"] = strconv.Itoa(failures.count)
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: data}
	if cause := failures.err("Windows process environments"); cause != nil {
		summary.Cells["Error"] = evidence.Missing("environment_incomplete", cause)
	}
	if err = out(summary); err != nil {
		return err
	}
	return failures.err("Windows process environments")
}

func readWindowsEnvironment(ctx context.Context, e plugin.Environment, process, pid uint64, name string, created evidence.Value, maxEnv uint64) ([]evidence.Row, error) {
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
	base := func(kind, layer, offset string) evidence.Row {
		row := windowsEnvarRow(e, layer, 0, kind)
		row.Provenance.Layer = layer
		row.Provenance.Offset = offset
		row.Cells["PID"] = evidence.Number(pid)
		row.Cells["Process"] = evidence.Text(name)
		row.Cells["ProcessOffset"] = evidence.Address(process)
		row.Cells["ProcessIdentity"] = evidence.Text(identity)
		return row
	}
	fail := func(reason string, cause error, layer, offset string, block, size uint64, field string) ([]evidence.Row, error) {
		row := base("diagnostic", layer, offset)
		if block != 0 {
			row.Cells["Block"] = evidence.Text(fmt.Sprintf("0x%x", block))
		}
		if size != 0 || field != "" {
			row.Cells["BlockSize"] = evidence.Number(size)
			row.Cells["SizeField"] = evidence.Text(field)
		}
		row.Cells["Error"] = evidence.Missing(reason, cause)
		return []evidence.Row{row}, cause
	}
	peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
	if err != nil {
		return fail("peb_pointer_unreadable", err, e.Kernel.Name(), fmt.Sprintf("0x%x", process), 0, 0, "")
	}
	if peb == 0 {
		row := base("diagnostic", e.Kernel.Name(), fmt.Sprintf("0x%x", process))
		row.Cells["Error"] = evidence.Missing("no_process_peb", nil)
		return []evidence.Row{row}, nil
	}
	layer, err := processMemory(ctx, e, process, 0, identity)
	if err != nil {
		return fail("process_address_space_unavailable", err, e.Kernel.Name(), fmt.Sprintf("0x%x", process), 0, 0, "")
	}
	reader := &object.Reader{Layer: layer, Symbols: e.Symbols}
	parameters, err := reader.Uint(ctx, peb, "_PEB", "ProcessParameters")
	if err != nil {
		return fail("process_parameters_pointer_unreadable", err, layer.Name(), fmt.Sprintf("0x%x", peb), 0, 0, "")
	}
	mask := uint64(0xffffffff)
	if e.Symbols.PointerSize() == 8 {
		mask = 0x0000ffffffffffff
	}
	parameters &= mask
	if parameters == 0 {
		row := base("diagnostic", layer.Name(), fmt.Sprintf("0x%x", peb))
		row.Cells["Error"] = evidence.Missing("process_parameters_not_set", nil)
		return []evidence.Row{row}, nil
	}
	envField, err := reader.Field("_RTL_USER_PROCESS_PARAMETERS", "Environment")
	if err != nil {
		return fail("environment_layout_unavailable", err, layer.Name(), fmt.Sprintf("0x%x", parameters), 0, 0, "")
	}
	blockAt, err := memory.Add(parameters, envField.Offset)
	if err != nil {
		return fail("environment_descriptor_overflow", err, layer.Name(), fmt.Sprintf("0x%x", parameters), 0, 0, "")
	}
	blockAt &= mask
	sizeField := "EnvironmentSize"
	size, err := reader.Uint(ctx, parameters, "_RTL_USER_PROCESS_PARAMETERS", "EnvironmentSize")
	if errors.Is(err, object.ErrFieldAbsent) {
		sizeField = "Length"
		size, err = reader.Uint(ctx, parameters, "_RTL_USER_PROCESS_PARAMETERS", "Length")
	}
	if err != nil {
		reason := "environment_size_unreadable"
		if errors.Is(err, object.ErrFieldAbsent) {
			reason = "environment_layout_unavailable"
		}
		return fail(reason, err, layer.Name(), fmt.Sprintf("0x%x", blockAt), blockAt, 0, sizeField)
	}
	target, err := reader.Uint(ctx, parameters, "_RTL_USER_PROCESS_PARAMETERS", "Environment")
	if err != nil {
		return fail("environment_pointer_unreadable", err, layer.Name(), fmt.Sprintf("0x%x", blockAt), blockAt, size, sizeField)
	}
	target &= mask
	if size == 0 {
		row := base("diagnostic", layer.Name(), fmt.Sprintf("0x%x", blockAt))
		row.Cells["Block"] = evidence.Text(fmt.Sprintf("0x%x", blockAt))
		row.Cells["Environment"] = evidence.Address(target)
		row.Cells["BlockSize"] = evidence.Number(0)
		row.Cells["SizeField"] = evidence.Text(sizeField)
		row.Cells["Error"] = evidence.Missing("empty_environment", nil)
		return []evidence.Row{row}, nil
	}
	if size > maxEnv {
		return fail("environment_size_limit", fmt.Errorf("environment range %d exceeds max-env=%d", size, maxEnv), layer.Name(), fmt.Sprintf("0x%x", blockAt), blockAt, size, sizeField)
	}
	if _, err = memory.Add(target, size-1); err != nil {
		return fail("invalid_environment_range", err, layer.Name(), fmt.Sprintf("0x%x", blockAt), blockAt, size, sizeField)
	}
	raw := make([]byte, int(size))
	got, err := layer.ReadAt(ctx, raw, target)
	if got < 0 || got > len(raw) {
		return fail("invalid_environment_read", fmt.Errorf("source returned an invalid byte count"), layer.Name(), fmt.Sprintf("0x%x", target), blockAt, size, sizeField)
	}
	if err != nil || got != len(raw) {
		if err == nil {
			err = fmt.Errorf("short environment read")
		}
		rows, cause := fail("environment_buffer_unreadable", err, layer.Name(), fmt.Sprintf("0x%x", target), blockAt, size, sizeField)
		rows[0].Cells["Environment"] = evidence.Address(target)
		rows[0].Cells["Index"] = evidence.Number(uint64(got))
		return rows, cause
	}
	parts := strings.Split(decodeWindowsEnvironment(raw), "\x00")
	if len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	rows := make([]evidence.Row, 0, len(parts))
	for index, part := range parts {
		variable, value, ok := splitWindowsEnvar(part)
		if !ok {
			continue
		}
		row := base("variable", layer.Name(), fmt.Sprintf("0x%x", target))
		row.Cells["Block"] = evidence.Text(fmt.Sprintf("0x%x", blockAt))
		row.Cells["Environment"] = evidence.Address(target)
		row.Cells["BlockSize"] = evidence.Number(size)
		row.Cells["SizeField"] = evidence.Text(sizeField)
		row.Cells["Index"] = evidence.Number(uint64(index))
		row.Cells["Variable"] = evidence.Text(variable)
		row.Cells["Value"] = evidence.Text(value)
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		row := base("diagnostic", layer.Name(), fmt.Sprintf("0x%x", target))
		row.Cells["Block"] = evidence.Text(fmt.Sprintf("0x%x", blockAt))
		row.Cells["Environment"] = evidence.Address(target)
		row.Cells["BlockSize"] = evidence.Number(size)
		row.Cells["SizeField"] = evidence.Text(sizeField)
		row.Cells["Error"] = evidence.Missing("no_environment_variables", nil)
		return []evidence.Row{row}, nil
	}
	return rows, nil
}

func windowsEnvarRow(e plugin.Environment, layer string, address uint64, kind string) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsEnvarPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["RecordType"] = evidence.Text(kind)
	return row
}

func decodeWindowsEnvironment(raw []byte) string {
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
	}
	decoded := string(utf16.Decode(units))
	if len(raw)%2 != 0 {
		decoded += "\ufffd"
	}
	return decoded
}

func splitWindowsEnvar(envar string) (string, string, bool) {
	index := strings.Index(envar, "=")
	var name, value string
	if index < 0 {
		if envar == "" {
			return "", "", false
		}
		name = envar[:len(envar)-1]
		value = envar
	} else {
		name = envar[:index]
		value = envar[index+1:]
	}
	if name == "" || value == "" {
		return "", "", false
	}
	return name, value, true
}
