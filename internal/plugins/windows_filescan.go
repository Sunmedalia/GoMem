package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsFileScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "Name", Kind: "string"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.filescan", Upstream: "windows.filescan.FileScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan pool headers for file objects and report the file-object address and file name",
		Columns:     columns,
	}, windowsFileScan}}
}

func windowsFileScan(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	constraints, err := builtinPoolConstraints("Fil\xe5", "File")
	if err != nil {
		return err
	}
	return scanPoolObjects(ctx, e, constraints, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		name, err := readPoolUnicode(ctx, found.scan, found.native, found.object, "_FILE_OBJECT", "FileName", 0)
		if err != nil {
			return evidence.Row{}, false, err
		}
		row := fileScanRow(found.layer, found.object)
		row.Cells["Name"] = evidence.Text(name)
		row.Cells["RecordType"] = evidence.Text("file")
		return row, true, nil
	})
}

func fileScanRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsFileScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func poolCoverage(fields map[string]string) evidence.Value {
	data := map[string]any{}
	for key, value := range fields {
		data[key] = value
	}
	return evidence.Value{Kind: "structure", Data: data}
}

func formatCount(n uint64) string { return strconv.FormatUint(n, 10) }
