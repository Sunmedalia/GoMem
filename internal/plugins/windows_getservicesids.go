package plugins

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func windowsGetServiceSIDPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.getservicesids", Upstream: "windows.getservicesids.GetServiceSIDs", Platform: "windows", NeedsKernel: true,
		Description: "Compute service SIDs for SYSTEM hive services that are absent from the pinned service table",
		Columns: []evidence.Column{
			{Name: "SID", Kind: "string"},
			{Name: "Service", Kind: "string"},
			{Name: "Hive", Kind: "string"},
			{Name: "HiveOffset", Kind: "address"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsGetServiceSIDs}}
}

var windowsServiceNames = serviceNameSet()

func serviceNameSet() map[string]struct{} {
	names := make(map[string]struct{}, len(windowsServiceSIDs))
	for _, name := range windowsServiceSIDs {
		names[name] = struct{}{}
	}
	return names
}

func windowsGetServiceSIDs(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.getservicesids requires a kernel layer and symbols")
	}
	hives, err := listPrintKeyHives(ctx, e)
	if err != nil && len(hives) == 0 {
		return err
	}
	layout, err := windowsHiveLayout(e)
	if err != nil {
		return err
	}
	proc, _, _ := windowsRegistryLayer(ctx, e)
	const filter = `machine\system`
	var matched, opened, rowsOut, known, skipped int
	for _, hive := range hives {
		if !strings.Contains(strings.ToLower(hive.Name), filter) {
			continue
		}
		matched++
		reg, openErr := registry.Open(ctx, e.Kernel, proc, hive.Address, hive.Name, layout)
		if openErr != nil {
			skipped++
			continue
		}
		opened++
		path, keyErr := serviceKey(ctx, reg)
		if keyErr != nil {
			skipped++
			continue
		}
		subs, _ := reg.Subkeys(ctx, path[len(path)-1])
		for _, sub := range subs {
			if _, ok := windowsServiceNames[sub.Name]; ok {
				known++
				continue
			}
			rowsOut++
			if err := out(serviceSIDRow(e, hive.Address, hive.Name, sub.Name)); err != nil {
				return err
			}
		}
	}
	summary := serviceSIDBase(e, 0, "")
	summary.Provenance.Offset = "0x0"
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"hives":   strconv.Itoa(matched),
		"opened":  strconv.Itoa(opened),
		"rows":    strconv.Itoa(rowsOut),
		"known":   strconv.Itoa(known),
		"skipped": strconv.Itoa(skipped),
	}}
	return out(summary)
}

func serviceKey(ctx context.Context, hive *registry.Hive) ([]registry.Key, error) {
	path, err := resolveRegistryKey(ctx, hive, `CurrentControlSet\Services`)
	if err == nil {
		return path, nil
	}
	return resolveRegistryKey(ctx, hive, `ControlSet001\Services`)
}

func serviceSID(name string) string {
	upper := strings.ToUpper(name)
	buf := make([]byte, 0, len(upper)*2)
	var tmp [utf8.UTFMax]byte
	for _, r := range upper {
		n := utf8.EncodeRune(tmp[:], r)
		buf = append(buf, tmp[:n]...)
		buf = append(buf, 0)
	}
	sum := sha1.Sum(buf)
	parts := make([]string, 0, 6)
	parts = append(parts, "S-1-5-80")
	for i := 0; i < 5; i++ {
		parts = append(parts, strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[i*4:(i+1)*4])), 10))
	}
	return strings.Join(parts, "-")
}

func serviceSIDRow(e plugin.Environment, hive uint64, hiveName, service string) evidence.Row {
	row := serviceSIDBase(e, hive, hiveName)
	row.Cells["RecordType"] = evidence.Text("service")
	row.Cells["SID"] = evidence.Text(serviceSID(service))
	row.Cells["Service"] = evidence.Text(service)
	return row
}

func serviceSIDBase(e plugin.Environment, hive uint64, hiveName string) evidence.Row {
	layer := ""
	if e.Kernel != nil {
		layer = e.Kernel.Name()
	}
	name := evidence.Missing("not_applicable", nil)
	if hiveName != "" {
		name = evidence.Text(hiveName)
	}
	offset := evidence.Missing("not_applicable", nil)
	text := "0x0"
	if hive != 0 {
		offset = evidence.Address(hive)
		text = fmt.Sprintf("0x%x", hive)
	}
	return evidence.Row{Cells: map[string]evidence.Value{
		"SID": evidence.Missing("not_applicable", nil), "Service": evidence.Missing("not_applicable", nil),
		"Hive": name, "HiveOffset": offset,
		"RecordType": evidence.Missing("not_applicable", nil),
		"Error":      evidence.Missing("not_applicable", nil),
		"Coverage":   evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: layer, Offset: text}}
}
