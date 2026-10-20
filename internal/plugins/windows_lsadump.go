package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsCredentialPlugins() []builtin {
	return []builtin{credentialPlugin(true), credentialPlugin(false)}
}

func credentialPlugin(secrets bool) builtin {
	name, upstream, description := "windows.cachedump", "windows.registry.cachedump.Cachedump", "Decrypt cached domain credentials from the SYSTEM boot key and SECURITY NL$KM"
	columns := []evidence.Column{}
	groups := []struct{ kind, names string }{
		{"string", "Username Domain DomainName Hash RecordType Cipher Value"},
		{"bytes", "HashBytes"},
		{"address", "HiveOffset Cell"},
		{"string", "Error"},
	}
	if secrets {
		name, upstream, description = "windows.lsadump", "windows.registry.lsadump.Lsadump", "Decrypt LSA secrets from the SYSTEM boot key and SECURITY policy key"
		groups = []struct{ kind, names string }{
			{"string", "Key Secret RecordType Cipher"},
			{"bytes", "Hex"},
			{"address", "HiveOffset Cell"},
			{"string", "Error"},
		}
	}
	for _, group := range groups {
		for _, column := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: column, Kind: group.kind})
		}
	}
	run := windowsCachedump
	if secrets {
		run = windowsLsadump
	}
	return builtin{plugin.Spec{
		Name: name, Upstream: upstream, Platform: "windows", NeedsKernel: true,
		Description: description, Columns: columns,
	}, run}
}

func windowsLsadump(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	sys, sec, vista, err := openCredentialHives(ctx, e)
	if err != nil {
		return emitCredential(out, credentialDiagnostic(e, "windows.lsadump", anchorHive(sys, sec), err))
	}
	rows, err := registry.DumpLSA(ctx, sys.hive, sec.hive, vista)
	for _, item := range rows {
		if item.Err != nil {
			row := credentialDiagnostic(e, "windows.lsadump", sec.addr, item.Err)
			if item.NameKnown {
				row.Cells["Key"] = evidence.Text(item.Name)
			}
			row.Cells["Cell"] = evidence.Address(item.Cell)
			row.Cells["Cipher"] = evidence.Text(cipherName(vista))
			if emitErr := out(row); emitErr != nil {
				return emitErr
			}
			continue
		}
		row := credentialRow(e, "windows.lsadump", sec.addr, item.Cell)
		if name, ok := sec.hive.LayerName(item.Cell); ok {
			row.Provenance.Layer = name
		}
		row.Cells["Key"] = evidence.Text(item.Name)
		row.Cells["Secret"] = evidence.Text(spacedHex(item.Data))
		row.Cells["Hex"] = evidence.Bytes(item.Data)
		row.Cells["RecordType"] = evidence.Text("secret")
		row.Cells["Cipher"] = evidence.Text(cipherName(vista))
		if emitErr := out(row); emitErr != nil {
			return emitErr
		}
	}
	if err != nil && len(rows) == 0 {
		anchor := sec.addr
		if strings.Contains(err.Error(), "LSA key") {
			anchor = sys.addr
		}
		if emitErr := out(credentialDiagnostic(e, "windows.lsadump", anchor, err)); emitErr != nil {
			return emitErr
		}
	}
	return err
}

func windowsCachedump(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	sys, sec, vista, err := openCredentialHives(ctx, e)
	if err != nil {
		return emitCredential(out, credentialDiagnostic(e, "windows.cachedump", anchorHive(sys, sec), err))
	}
	rows, err := registry.DumpCache(ctx, sys.hive, sec.hive, vista)
	for _, item := range rows {
		if item.Err != nil {
			row := credentialDiagnostic(e, "windows.cachedump", sec.addr, item.Err)
			row.Cells["Value"] = evidence.Text(item.Value)
			row.Cells["Cell"] = evidence.Address(item.Cell)
			row.Cells["Cipher"] = evidence.Text(cipherName(vista))
			if emitErr := out(row); emitErr != nil {
				return emitErr
			}
			continue
		}
		row := credentialRow(e, "windows.cachedump", sec.addr, item.Cell)
		if name, ok := sec.hive.LayerName(item.Cell); ok {
			row.Provenance.Layer = name
		}
		row.Cells["Username"] = evidence.Text(item.Username)
		row.Cells["Domain"] = evidence.Text(item.Domain)
		row.Cells["DomainName"] = evidence.Text(item.DomainName)
		row.Cells["Hash"] = evidence.Text(spacedHex(item.Hash))
		row.Cells["HashBytes"] = evidence.Bytes(item.Hash)
		row.Cells["Value"] = evidence.Text(item.Value)
		row.Cells["RecordType"] = evidence.Text("credential")
		row.Cells["Cipher"] = evidence.Text(cipherName(vista))
		if emitErr := out(row); emitErr != nil {
			return emitErr
		}
	}
	if err != nil && len(rows) == 0 {
		anchor := sec.addr
		if strings.Contains(err.Error(), "LSA key") || strings.Contains(err.Error(), "boot key") {
			anchor = sys.addr
		}
		if emitErr := out(credentialDiagnostic(e, "windows.cachedump", anchor, err)); emitErr != nil {
			return emitErr
		}
	}
	return err
}

type openedHive struct {
	hive *registry.Hive
	addr uint64
}

func openCredentialHives(ctx context.Context, e plugin.Environment) (openedHive, openedHive, bool, error) {
	var sys, sec openedHive
	vista := windowsVistaOrLater(e.Symbols)
	layout, err := windowsHiveLayout(e)
	if err != nil {
		return sys, sec, vista, err
	}
	proc, _, err := windowsRegistryLayer(ctx, e)
	if err != nil {
		return sys, sec, vista, err
	}
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil {
		return sys, sec, vista, err
	}
	var system, security *listedHive
	for i := range hives {
		switch hiveLeaf(hives[i].Name) {
		case "SYSTEM":
			system = &hives[i]
		case "SECURITY":
			security = &hives[i]
		}
	}
	if system == nil || security == nil {
		err = fmt.Errorf("windows credential dump requires SYSTEM and SECURITY hives")
		if system == nil {
			err = fmt.Errorf("%w; SYSTEM is absent", err)
		}
		if security == nil {
			err = fmt.Errorf("%w; SECURITY is absent", err)
		}
		if system != nil {
			sys.addr = system.Address
		}
		if security != nil {
			sec.addr = security.Address
		}
		return sys, sec, vista, err
	}
	sys.addr, sec.addr = system.Address, security.Address
	sys.hive, err = registry.Open(ctx, e.Kernel, proc, system.Address, system.Name, layout)
	if err != nil {
		return sys, sec, vista, fmt.Errorf("SYSTEM hive %#x: %w", system.Address, err)
	}
	sec.hive, err = registry.Open(ctx, e.Kernel, proc, security.Address, security.Name, layout)
	if err != nil {
		return sys, sec, vista, fmt.Errorf("SECURITY hive %#x: %w", security.Address, err)
	}
	return sys, sec, vista, nil
}

func anchorHive(sys, sec openedHive) uint64 {
	if sec.addr != 0 {
		return sec.addr
	}
	return sys.addr
}

func cipherName(vista bool) string {
	if vista {
		return "aes"
	}
	return "des"
}

func emitCredential(out plugin.Emit, row evidence.Row) error {
	if err := out(row); err != nil {
		return err
	}
	return fmt.Errorf("%s", row.Cells["Error"].Error)
}

func credentialDiagnostic(e plugin.Environment, pluginName string, hive uint64, cause error) evidence.Row {
	row := credentialRow(e, pluginName, hive, 0)
	row.Cells["RecordType"] = evidence.Text("diagnostic")
	reason := "lsa_secret_unavailable"
	if pluginName == "windows.cachedump" {
		reason = "cached_credential_unavailable"
	}
	row.Cells["Error"] = evidence.Missing(reason, cause)
	return row
}

func credentialRow(e plugin.Environment, pluginName string, hive, cell uint64) evidence.Row {
	offset := cell
	if offset == 0 {
		offset = hive
	}
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", offset)}}
	columns := windowsLsadumpColumns()
	if pluginName == "windows.cachedump" {
		columns = windowsCachedumpColumns()
	}
	for _, column := range columns {
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

func windowsLsadumpColumns() []evidence.Column {
	return credentialPlugin(true).spec.Columns
}

func windowsCachedumpColumns() []evidence.Column {
	return credentialPlugin(false).spec.Columns
}

func spacedHex(b []byte) string {
	var out strings.Builder
	for i, c := range b {
		if i > 0 {
			out.WriteByte(' ')
		}
		fmt.Fprintf(&out, "%02x", c)
	}
	return out.String()
}

// windowsVistaOrLater follows the pinned distinguisher. PE major.minor is used
// when revision is present. Otherwise KdCopyDataBlock as a symbol or type means
// Vista or later, and its absence means the earlier DES path.
func windowsVistaOrLater(table symbols.SymbolTable) bool {
	if table == nil {
		return false
	}
	if major, _, ok := windowsPEVersion(table); ok {
		return major >= 6
	}
	if _, err := table.Lookup("KdCopyDataBlock"); err == nil {
		return true
	}
	_, err := table.Type("KdCopyDataBlock")
	return err == nil
}

func windowsPEVersion(table symbols.SymbolTable) (int, int, bool) {
	meta := table.Metadata()
	raw, ok := meta["windows"]
	if !ok || len(raw) == 0 {
		return 0, 0, false
	}
	var decoded struct {
		PE struct {
			Major    *int `json:"major"`
			Minor    *int `json:"minor"`
			Revision *int `json:"revision"`
		} `json:"pe"`
	}
	if json.Unmarshal(raw, &decoded) != nil || decoded.PE.Major == nil || decoded.PE.Minor == nil || decoded.PE.Revision == nil {
		return 0, 0, false
	}
	return *decoded.PE.Major, *decoded.PE.Minor, true
}
