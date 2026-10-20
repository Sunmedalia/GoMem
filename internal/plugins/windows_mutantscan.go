package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsMutantScanPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "Offset", Kind: "address"},
		{Name: "Name", Kind: "string"},
		{Name: "RecordType", Kind: "string"},
		{Name: "Coverage", Kind: "structure"},
		{Name: "Error", Kind: "string"},
	}
	return []builtin{{plugin.Spec{
		Name: "windows.mutantscan", Upstream: "windows.mutantscan.MutantScan", Platform: "windows", NeedsKernel: true,
		Description: "Scan pool headers for KMUTANT objects and report the object-header name",
		Columns:     columns,
	}, windowsMutantScan}}
}

func windowsMutantScan(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if err := requireMutantFields(e); err != nil {
		return err
	}
	constraints, err := builtinPoolConstraints("Mut\xe1", "Muta")
	if err != nil {
		return err
	}
	body, err := e.Objects.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return err
	}
	return scanPoolObjects(ctx, e, constraints, "mutants", mutantScanRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		row := mutantScanRow(found.layer, found.object)
		name, err := mutantObjectName(ctx, e, found, body.Offset)
		if err != nil {
			return evidence.Row{}, false, err
		}
		row.Cells["Name"] = name
		row.Cells["RecordType"] = evidence.Text("mutant")
		return row, true, nil
	})
}

func requireMutantFields(e plugin.Environment) error {
	if e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("mutant scan needs kernel symbols")
	}
	if _, err := e.Objects.Field("_KMUTANT", "Header"); err != nil {
		return fmt.Errorf("_KMUTANT.Header: %w", err)
	}
	if _, err := e.Objects.Field("_OBJECT_HEADER", "Body"); err != nil {
		return err
	}
	if _, err := e.Objects.Field("_OBJECT_HEADER", "NameInfoOffset"); errors.Is(err, object.ErrFieldAbsent) {
		if _, err = e.Symbol("ObpInfoMaskToOffset"); err != nil {
			return fmt.Errorf("mutant names need NameInfoOffset or ObpInfoMaskToOffset: %w", err)
		}
		if _, err = e.Objects.Field("_OBJECT_HEADER", "InfoMask"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err := e.Objects.Field("_OBJECT_HEADER_NAME_INFO", "Name"); err != nil {
		return fmt.Errorf("_OBJECT_HEADER_NAME_INFO.Name: %w", err)
	}
	return nil
}

func mutantScanRow(layer string, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsMutantScanPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	return row
}

func mutantObjectValid(ctx context.Context, _ uint64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// The pinned KMUTANT check accepts every carved object.
	return true, nil
}

func mutantObjectName(ctx context.Context, e plugin.Environment, found poolHit, body uint64) (evidence.Value, error) {
	if found.object < body {
		return evidence.Missing("name_unavailable", nil), nil
	}
	header := found.object - body
	offset, err := mutantNameInfoOffset(ctx, e, found.scan, header)
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("name_unavailable", err), nil
	}
	if offset == 0 {
		return evidence.Missing("name_unavailable", nil), nil
	}
	if header < uint64(offset) {
		return evidence.Missing("name_unavailable", nil), nil
	}
	info := header - uint64(offset)
	name, err := readMutantName(ctx, e, found.scan, info)
	if err != nil {
		if ctx.Err() != nil {
			return evidence.Value{}, ctx.Err()
		}
		return evidence.Missing("name_unavailable", err), nil
	}
	if name == "" {
		return evidence.Missing("name_unavailable", nil), nil
	}
	return evidence.Text(name), nil
}

func mutantNameInfoOffset(ctx context.Context, e plugin.Environment, scan *object.Reader, header uint64) (byte, error) {
	if _, err := scan.Field("_OBJECT_HEADER", "NameInfoOffset"); err == nil {
		value, err := scan.Uint(ctx, header, "_OBJECT_HEADER", "NameInfoOffset")
		if err != nil {
			return 0, err
		}
		if value > 255 {
			return 0, fmt.Errorf("NameInfoOffset %#x is wider than a byte", value)
		}
		return byte(value), nil
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return 0, err
	}
	mask, err := scan.Uint(ctx, header, "_OBJECT_HEADER", "InfoMask")
	if err != nil {
		return 0, err
	}
	table, err := e.Symbol("ObpInfoMaskToOffset")
	if err != nil {
		return 0, err
	}
	slot, err := memory.Add(table, mask&0x3)
	if err != nil {
		return 0, err
	}
	raw, err := memory.Read(ctx, e.Kernel, slot, 1)
	if err != nil {
		return 0, err
	}
	return raw[0], nil
}

func readMutantName(ctx context.Context, e plugin.Environment, scan *object.Reader, info uint64) (string, error) {
	member, err := scan.Field("_OBJECT_HEADER_NAME_INFO", "Name")
	if err != nil {
		return "", err
	}
	address, err := memory.Add(info, member.Offset)
	if err != nil {
		return "", err
	}
	length, err := scan.Uint(ctx, address, "_UNICODE_STRING", "Length")
	if err != nil {
		return "", err
	}
	maximum, err := scan.Uint(ctx, address, "_UNICODE_STRING", "MaximumLength")
	if err != nil {
		return "", err
	}
	if length == 0 || maximum == 0 || length > maximum {
		return "", nil
	}
	env := e
	env.Objects = scan
	return unicodeString(ctx, env, info, "_OBJECT_HEADER_NAME_INFO", "Name")
}
