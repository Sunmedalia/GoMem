package plugins

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsGetCellRoutinePlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"address", "HiveOffset Handler"},
		{"string", "HiveName Module RecordType Error"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{
		Name: "windows.getcellroutine", Upstream: "windows.registry.getcellroutine.GetCellRoutine", Platform: "windows", NeedsKernel: true,
		Description: "Report hive GetCellRoutine handlers that are not inside a known kernel module",
		Columns:     columns,
	}, windowsGetCellRoutine}}
}

// The pinned SSDT module collection strips the final extension and refuses a
// repeated stem. These four stems are the only handlers treated as native.
var kernelModuleStems = map[string]bool{
	"ntkrnlmp": true, "ntkrnlpa": true, "ntkrpamp": true, "ntoskrnl": true,
}

type kernelModule struct {
	stem string
	base uint64
	size uint64
}

func windowsGetCellRoutine(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	modules, err := windowsKernelModules(ctx, e)
	if err != nil {
		return err
	}
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil {
		return err
	}
	for _, hive := range hives {
		if err := ctx.Err(); err != nil {
			return err
		}
		handler, readErr := e.Objects.Uint(ctx, hive.Address, "_CMHIVE", "Hive.GetCellRoutine")
		if errors.Is(readErr, object.ErrFieldAbsent) {
			return fmt.Errorf("hive GetCellRoutine: %w", readErr)
		}
		if readErr != nil {
			row := cellRoutineRow(e, hive)
			row.Cells["RecordType"] = evidence.Text("unreadable")
			row.Cells["Handler"] = evidence.Missing("unreadable", nil)
			row.Cells["Module"] = evidence.Missing("unreadable", nil)
			row.Cells["Error"] = evidence.Missing("getcellroutine_unreadable", readErr)
			if err := out(row); err != nil {
				return err
			}
			continue
		}
		var outside []kernelModule
		for _, module := range modules {
			if addressInModule(module.base, module.size, handler) && !kernelModuleStems[module.stem] {
				outside = append(outside, module)
			}
		}
		if len(outside) == 0 && handlerInKernel(modules, handler) {
			continue
		}
		if len(outside) == 0 {
			row := cellRoutineRow(e, hive)
			row.Cells["RecordType"] = evidence.Text("unmapped")
			row.Cells["Handler"] = evidence.Address(handler)
			row.Cells["Module"] = evidence.Missing("not_available", nil)
			if err := out(row); err != nil {
				return err
			}
			continue
		}
		for _, module := range outside {
			row := cellRoutineRow(e, hive)
			row.Cells["RecordType"] = evidence.Text("hook")
			row.Cells["Handler"] = evidence.Address(handler)
			row.Cells["Module"] = evidence.Text(module.stem)
			if err := out(row); err != nil {
				return err
			}
		}
	}
	return nil
}

func handlerInKernel(modules []kernelModule, handler uint64) bool {
	for _, module := range modules {
		if kernelModuleStems[module.stem] && addressInModule(module.base, module.size, handler) {
			return true
		}
	}
	return false
}

func cellRoutineRow(e plugin.Environment, hive listedHive) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", hive.Address)}}
	for _, column := range windowsGetCellRoutinePlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["HiveOffset"] = evidence.Address(hive.Address)
	name := hive.Name
	if name == "" {
		name = "[NONAME]"
	}
	row.Cells["HiveName"] = evidence.Text(name)
	return row
}

func windowsKernelModules(ctx context.Context, e plugin.Environment) ([]kernelModule, error) {
	head, err := e.Symbol("PsLoadedModuleList")
	if err != nil {
		return nil, err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	link, err := e.Objects.Field(typ, "InLoadOrderLinks")
	if err != nil {
		typ = "_LDR_DATA_TABLE_ENTRY"
		link, err = e.Objects.Field(typ, "InLoadOrderLinks")
	}
	if err != nil {
		return nil, err
	}
	var modules []kernelModule
	seen := map[string]bool{}
	err = e.Objects.WalkList(ctx, head, link.Offset, 65536, func(address uint64) error {
		name, nameErr := unicodeString(ctx, e, address, typ, "BaseDllName")
		if nameErr != nil {
			return nil
		}
		stem := moduleStem(name)
		base, baseErr := e.Objects.Uint(ctx, address, typ, "DllBase")
		if baseErr != nil {
			return fmt.Errorf("module %s base: %w", stem, baseErr)
		}
		size, sizeErr := e.Objects.Uint(ctx, address, typ, "SizeOfImage")
		if sizeErr != nil {
			return fmt.Errorf("module %s size: %w", stem, sizeErr)
		}
		if seen[stem] {
			return fmt.Errorf("duplicate kernel module stem %q", stem)
		}
		seen[stem] = true
		modules = append(modules, kernelModule{stem: stem, base: base, size: size})
		return nil
	})
	return modules, err
}

// moduleStem matches os.path.splitext: the last dot is the extension, unless
// it is the first character.
func moduleStem(name string) string {
	dot := strings.LastIndex(name, ".")
	if dot <= 0 {
		return name
	}
	return name[:dot]
}

// addressInModule matches the pinned inclusive end. A size that overflows the
// address space still contains every address at or above the base, because the
// reference adds the size with unbounded integers.
func addressInModule(base, size, address uint64) bool {
	if address < base {
		return false
	}
	if size > ^uint64(0)-base {
		return true
	}
	return address <= base+size
}
