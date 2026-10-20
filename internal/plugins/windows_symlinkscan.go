package plugins

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsSymlinkScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "CreateTime", Kind: "string"},
		{Name: "CreateTimeRaw", Kind: "uint64"},
		{Name: "FromName", Kind: "string"},
		{Name: "ToName", Kind: "string"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.symlinkscan", Upstream: "windows.symlinkscan.SymlinkScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan paged pool headers for symbolic links and report both names and the creation time",
		Columns:     columns,
	}, windowsSymlinkScan}}
}

func windowsSymlinkScan(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if err := requireSymlinkFields(e); err != nil {
		return err
	}
	constraints, err := builtinPoolConstraints("Sym\xe2", "Symb")
	if err != nil {
		return err
	}
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return err
	}
	return scanPoolObjects(ctx, e, constraints, "symlinks", symlinkScanRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		return symlinkScanHit(ctx, e, found, body.Offset)
	})
}

func requireSymlinkFields(e plugin.Environment) error {
	for _, path := range []string{"CreationTime", "LinkTarget"} {
		if _, err := e.Objects.Field("_OBJECT_SYMBOLIC_LINK", path); err != nil {
			return fmt.Errorf("_OBJECT_SYMBOLIC_LINK.%s: %w", path, err)
		}
	}
	return requireObjectNameFields(e)
}

func symlinkScanRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsSymlinkScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func symlinkObjectValid(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// The pinned symbolic-link check accepts every carved object.
	return true, nil
}

func symlinkScanHit(ctx context.Context, e plugin.Environment, found poolHit, body uint64) (evidence.Row, bool, error) {
	fromName, keep, err := symlinkFromName(ctx, e, found, body)
	if err != nil || !keep {
		return evidence.Row{}, false, err
	}
	toName, err := volatilityObjectString(ctx, e.Kernel, found.scan, found.object, "_OBJECT_SYMBOLIC_LINK", "LinkTarget")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		return evidence.Row{}, false, err
	}
	created, raw, err := symlinkCreateTime(ctx, found)
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Row{}, false, ctx.Err()
		}
		return evidence.Row{}, false, poolFatalError{err}
	}
	row := symlinkScanRow(found.layer, found.object)
	row.Cells["CreateTime"] = created
	row.Cells["CreateTimeRaw"] = raw
	row.Cells["FromName"] = fromName
	row.Cells["ToName"] = toName
	row.Cells["RecordType"] = evidence.Text("symlink")
	return row, true, nil
}

func symlinkFromName(ctx context.Context, e plugin.Environment, found poolHit, body uint64) (evidence.Value, bool, error) {
	if found.object < body {
		return evidence.Value{}, false, nil
	}
	header := found.object - body
	offset, err := mutantNameInfoOffset(ctx, e, found.scan, header)
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, false, ctx.Err()
		}
		return evidence.Value{}, false, err
	}
	// A zero NameInfo offset is the pinned ValueError and drops the row.
	if offset == 0 {
		return evidence.Value{}, false, nil
	}
	if header < uint64(offset) {
		return evidence.Value{}, false, fmt.Errorf("object header name precedes the layer")
	}
	value, err := volatilityObjectString(ctx, e.Kernel, found.scan, header-uint64(offset), "_OBJECT_HEADER_NAME_INFO", "Name")
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, false, ctx.Err()
		}
		return evidence.Value{}, false, err
	}
	return value, true, nil
}

// volatilityObjectString follows UNICODE_STRING.String. Length zero is an empty
// string and does not read the buffer. A failed length, pointer, or buffer read
// is returned so the caller can drop the row.
func volatilityObjectString(ctx context.Context, kernel memory.MemoryLayer, scan *object.Reader, base uint64, typ, field string) (evidence.Value, error) {
	member, err := scan.Field(typ, field)
	if err != nil {
		return evidence.Value{}, err
	}
	address, err := memory.Add(base, member.Offset)
	if err != nil {
		return evidence.Value{}, err
	}
	length, err := scan.Uint(ctx, address, "_UNICODE_STRING", "Length")
	if err != nil {
		return evidence.Value{}, err
	}
	buffer, err := scan.Uint(ctx, address, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return evidence.Value{}, err
	}
	if length == 0 {
		return evidence.Text(""), nil
	}
	if length > uint64(memory.MaxRead) {
		return evidence.Value{}, fmt.Errorf("unicode string is %d bytes", length)
	}
	raw, err := memory.Read(ctx, kernel, buffer, int(length))
	if err != nil {
		return evidence.Value{}, err
	}
	text := poolUTF16(raw)
	return evidence.Text(text), nil
}

func symlinkCreateTime(ctx context.Context, found poolHit) (evidence.Value, evidence.Value, error) {
	raw, err := windowsRawTime(ctx, plugin.Environment{Objects: found.scan}, found.object, "_OBJECT_SYMBOLIC_LINK", "CreationTime")
	if err != nil {
		return evidence.Value{}, evidence.Value{}, err
	}
	signed, err := quadSigned(found.scan, "_OBJECT_SYMBOLIC_LINK", "CreationTime")
	if err != nil {
		return evidence.Value{}, evidence.Value{}, err
	}
	ticks, ok := interpretedTicks(raw, signed)
	if !ok {
		return evidence.Missing("unparsable_filetime", nil), evidence.Number(raw), nil
	}
	when, datetime := volatilityFiletime(ticks)
	if !datetime {
		reason := "unparsable_filetime"
		if floorDivInt64(ticks, 10000000) == 0 {
			reason = "not_set"
		}
		return evidence.Missing(reason, nil), evidence.Number(raw), nil
	}
	return evidence.Text(when.Format("2006-01-02T15:04:05Z07:00")), evidence.Number(raw), nil
}
