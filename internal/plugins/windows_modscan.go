package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsModScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "Base", Kind: "address"},
		{Name: "Size", Kind: "uint64"},
		{Name: "Name", Kind: "string"},
		{Name: "Path", Kind: "string"},
		{Name: "NameError", Kind: "string"},
		{Name: "PathError", Kind: "string"},
		{Name: "FileOutput", Kind: "string"},
		{Name: "FileOutputError", Kind: "string"},
		{Name: "Artifact", Kind: "artifact"},
		{Name: "Patches", Kind: "structure"},
		{Name: "ExtractionAttempts", Kind: "structure"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.modscan", Upstream: "windows.modscan.ModScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan nonpaged pool headers for kernel module objects and report base, size, names, and optional PE extraction",
		Parameters: []plugin.Parameter{
			{Name: "base", Kind: "string", Description: "Optional exact DllBase; zero disables filtering"},
			{Name: "name", Kind: "string", Description: "Case-sensitive substring of the base module name"},
			{Name: "dump", Kind: "bool", Default: "false", Description: "Extract listed modules from the kernel or a verified session layer"},
			{Name: "max-nodes", Kind: "uint", Default: "65536", Description: "Process traversal bound used only while finding a session layer"},
			{Name: "max-session-layers", Kind: "uint", Default: "256", Description: "Maximum unique session roots cached for extraction (1..4096)"},
		},
		Columns: columns,
	}, windowsModScan}}
}

func windowsModScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if err := requireModScanFields(e); err != nil {
		return err
	}
	dump := false
	if p["dump"] != "" {
		var err error
		dump, err = strconv.ParseBool(p["dump"])
		if err != nil {
			return err
		}
	}
	var baseFilter uint64
	if p["base"] != "" {
		var err error
		baseFilter, err = strconv.ParseUint(p["base"], 0, 64)
		if err != nil {
			return fmt.Errorf("base: %w", err)
		}
	}
	maxNodes := 65536
	if p["max-nodes"] != "" {
		parsed, err := strconv.ParseUint(p["max-nodes"], 0, 31)
		if err != nil || parsed == 0 {
			return fmt.Errorf("max-nodes must be a positive 31-bit count")
		}
		maxNodes = int(parsed)
	}
	maxLayers := uint64(256)
	if p["max-session-layers"] != "" {
		var err error
		maxLayers, err = strconv.ParseUint(p["max-session-layers"], 0, 32)
		if err != nil || maxLayers == 0 || maxLayers > 4096 {
			return fmt.Errorf("max-session-layers must be 1..4096")
		}
	}
	constraints, err := builtinPoolConstraints("MmLd")
	if err != nil {
		return err
	}
	layers := windowsModuleLayers{env: e, max: maxNodes, maxLayers: int(maxLayers)}
	return scanPoolObjects(ctx, e, constraints, "modules", modScanRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		return modScanHit(ctx, e, found, dump, baseFilter, p["name"], &layers)
	})
}

func requireModScanFields(e plugin.Environment) error {
	if e.Objects == nil {
		return fmt.Errorf("module pool scan needs kernel symbols")
	}
	for _, path := range []string{"DllBase", "SizeOfImage", "BaseDllName", "FullDllName"} {
		if _, err := e.Objects.Field("_LDR_DATA_TABLE_ENTRY", path); err != nil {
			return fmt.Errorf("_LDR_DATA_TABLE_ENTRY.%s: %w", path, err)
		}
	}
	return nil
}

func modScanRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsModScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func modScanHit(ctx context.Context, e plugin.Environment, found poolHit, dump bool, baseFilter uint64, nameFilter string, layers *windowsModuleLayers) (evidence.Row, bool, error) {
	base, err := found.scan.Uint(ctx, found.object, "_LDR_DATA_TABLE_ENTRY", "DllBase")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		return evidence.Row{}, false, poolFatalError{err}
	}
	if baseFilter != 0 && base != baseFilter {
		return evidence.Row{}, false, nil
	}
	size, err := found.scan.Uint(ctx, found.object, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		return evidence.Row{}, false, poolFatalError{err}
	}
	name, err := volatilityObjectString(ctx, e.Kernel, found.scan, found.object, "_LDR_DATA_TABLE_ENTRY", "BaseDllName")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		name = evidence.Missing("name_unavailable", err)
	}
	if nameFilter != "" && name.Kind == "string" && !strings.Contains(name.String(), nameFilter) {
		return evidence.Row{}, false, nil
	}
	path, err := volatilityObjectString(ctx, e.Kernel, found.scan, found.object, "_LDR_DATA_TABLE_ENTRY", "FullDllName")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		path = evidence.Missing("path_unavailable", err)
	}
	row := modScanRow(found.layer, found.object)
	row.Cells["Base"] = evidence.Address(base)
	row.Cells["Size"] = evidence.Number(size)
	row.Cells["Name"], row.Cells["NameError"] = splitName(name)
	row.Cells["Path"], row.Cells["PathError"] = splitName(path)
	row.Cells["FileOutput"] = evidence.Text("Disabled")
	row.Cells["RecordType"] = evidence.Text("module")
	if dump {
		if err = modScanDump(ctx, e, found, base, path, layers, &row); err != nil {
			return evidence.Row{}, false, err
		}
	}
	return row, true, nil
}

func modScanDump(ctx context.Context, e plugin.Environment, found poolHit, base uint64, path evidence.Value, layers *windowsModuleLayers, row *evidence.Row) error {
	layer, attempts, err := layers.find(ctx, base)
	row.Cells["ExtractionAttempts"] = evidence.Value{Kind: "structure", Data: attempts}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		row.Cells["FileOutput"] = evidence.Text(fmt.Sprintf("Cannot find a viable session layer for %#x", base))
		row.Cells["FileOutputError"] = evidence.Missing("module_address_space_unavailable", err)
		row.Cells["Patches"] = evidence.Missing("pe_plan_unavailable", err)
		return nil
	}
	leaf := "UnreadableDLLName"
	if path.Kind == "string" {
		leaf = path.String()
		if i := strings.LastIndexAny(leaf, `/\`); i >= 0 {
			leaf = leaf[i+1:]
		}
	}
	file, image, err := dumpPE(ctx, e, layer, fmt.Sprintf("%s.%#x.%#x.dmp", leaf, found.object, base), base)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		row.Cells["FileOutput"] = evidence.Text("Error outputting file")
		row.Cells["FileOutputError"] = evidence.Missing("module_dump_failed", err)
		row.Cells["Patches"] = evidence.Missing("pe_plan_unavailable", err)
		return nil
	}
	if art, ok := file.Data.(evidence.Artifact); ok {
		row.Cells["FileOutput"] = evidence.Text(art.Name)
		row.Cells["Artifact"] = file
	} else {
		row.Cells["FileOutput"] = file
	}
	if image != nil {
		row.Cells["Patches"] = evidence.Value{Kind: "structure", Data: image.Patches}
	}
	return nil
}
