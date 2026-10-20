package plugins

import (
	"context"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func windowsHashdumpPlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"string", "User lmhash nthash RecordType"},
		{"uint64", "rid"},
		{"address", "HiveOffset Cell"},
		{"string", "Error"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{
		Name: "windows.hashdump", Upstream: "windows.registry.hashdump.Hashdump", Platform: "windows", NeedsKernel: true,
		Description: "Decrypt local SAM LM and NT hashes using the SYSTEM LSA boot key",
		Columns:     columns,
	}, windowsHashdump}}
}

func windowsHashdump(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	layout, err := windowsHiveLayout(e)
	if err != nil {
		return err
	}
	proc, _, err := windowsRegistryLayer(ctx, e)
	if err != nil {
		return err
	}
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil {
		return err
	}
	var system, sam *listedHive
	for i := range hives {
		switch hiveLeaf(hives[i].Name) {
		case "SYSTEM":
			system = &hives[i]
		case "SAM":
			sam = &hives[i]
		}
	}
	if system == nil || sam == nil {
		err = fmt.Errorf("windows.hashdump requires SYSTEM and SAM hives")
		if system == nil {
			err = fmt.Errorf("%w; SYSTEM is absent", err)
		}
		if sam == nil {
			err = fmt.Errorf("%w; SAM is absent", err)
		}
		if emitErr := out(hashDiagnostic(e, 0, err)); emitErr != nil {
			return emitErr
		}
		return err
	}
	sysHive, err := registry.Open(ctx, e.Kernel, proc, system.Address, system.Name, layout)
	if err != nil {
		return emitHashError(out, hashDiagnostic(e, system.Address, fmt.Errorf("SYSTEM hive %#x: %w", system.Address, err)))
	}
	samHive, err := registry.Open(ctx, e.Kernel, proc, sam.Address, sam.Name, layout)
	if err != nil {
		return emitHashError(out, hashDiagnostic(e, sam.Address, fmt.Errorf("SAM hive %#x: %w", sam.Address, err)))
	}
	users, err := registry.DumpSAM(ctx, sysHive, samHive)
	for _, user := range users {
		if user.Err != nil {
			row := hashDiagnostic(e, sam.Address, user.Err)
			row.Cells["Cell"] = evidence.Address(user.Cell)
			row.Cells["rid"] = evidence.Number(uint64(user.RID))
			if emitErr := out(row); emitErr != nil {
				return emitErr
			}
			continue
		}
		row := hashRow(e, sam.Address, user.Cell)
		if name, ok := samHive.LayerName(user.Cell); ok {
			row.Provenance.Layer = name
		}
		if user.NameKnown {
			row.Cells["User"] = evidence.Text(user.Name)
		} else {
			row.Cells["User"] = evidence.Missing("sam_username_unavailable", nil)
		}
		row.Cells["rid"] = evidence.Number(uint64(user.RID))
		row.Cells["lmhash"] = evidence.Text(user.LM)
		row.Cells["nthash"] = evidence.Text(user.NT)
		row.Cells["RecordType"] = evidence.Text("hash")
		if emitErr := out(row); emitErr != nil {
			return emitErr
		}
	}
	if err != nil {
		if len(users) == 0 {
			anchor := sam.Address
			if strings.Contains(err.Error(), "LSA key") {
				anchor = system.Address
			}
			if emitErr := out(hashDiagnostic(e, anchor, err)); emitErr != nil {
				return emitErr
			}
		}
		return err
	}
	return nil
}

func emitHashError(out plugin.Emit, row evidence.Row) error {
	if err := out(row); err != nil {
		return err
	}
	return fmt.Errorf("%s", row.Cells["Error"].Error)
}

func hashDiagnostic(e plugin.Environment, hive uint64, cause error) evidence.Row {
	row := hashRow(e, hive, 0)
	row.Cells["RecordType"] = evidence.Text("diagnostic")
	row.Cells["Error"] = evidence.Missing("sam_hash_unavailable", cause)
	return row
}

func hashRow(e plugin.Environment, hive, cell uint64) evidence.Row {
	offset := cell
	if offset == 0 {
		offset = hive
	}
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", offset)}}
	for _, column := range windowsHashdumpPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	if hive != 0 {
		row.Cells["HiveOffset"] = evidence.Address(hive)
	}
	if cell != 0 {
		row.Cells["Cell"] = evidence.Address(cell)
	}
	return row
}

func hiveLeaf(name string) string {
	name = strings.TrimRight(name, `\`)
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToUpper(name)
}
