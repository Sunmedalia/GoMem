package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func TestLdrModulesPluginRegistered(t *testing.T) {
	registry := plugin.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	spec, err := registry.Get("windows.ldrmodules")
	if err != nil || spec.Spec().Upstream != "windows.malware.ldrmodules.LdrModules" {
		t.Fatal(err, spec)
	}
}

func TestWowLoaderHasThreeLists(t *testing.T) {
	table, err := wowLoaderSymbols()
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		typ, field string
		offset     uint64
	}{
		{"_PEB_LDR_DATA", "InLoadOrderModuleList", 12},
		{"_PEB_LDR_DATA", "InMemoryOrderModuleList", 20},
		{"_PEB_LDR_DATA", "InInitializationOrderModuleList", 28},
		{"_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks", 0},
		{"_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks", 8},
		{"_LDR_DATA_TABLE_ENTRY", "InInitializationOrderLinks", 16},
		{"_LDR_DATA_TABLE_ENTRY", "DllBase", 24},
	}
	reader := table
	for _, check := range checks {
		typ, err := reader.Type(check.typ)
		if err != nil {
			t.Fatal(check, err)
		}
		field, ok := typ.Fields[check.field]
		if !ok || field.Offset != check.offset {
			t.Fatalf("%s.%s offset %d", check.typ, check.field, field.Offset)
		}
	}
}

func TestVadMZAndPathSplit(t *testing.T) {
	mem := make(flatMemory, 8)
	mem[0], mem[1] = 'M', 'Z'
	ok, err := vadHasMZ(context.Background(), mem, 0)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	mem[0] = 'P'
	ok, err = vadHasMZ(context.Background(), mem, 0)
	if err != nil || ok {
		t.Fatal(ok, err)
	}
	ok, err = vadHasMZ(context.Background(), mem, 7)
	if err != nil || ok {
		t.Fatal(ok, err)
	}
	path, pathErr := ldrPath(evidence.Text(`\Windows\System32\ntdll.dll`))
	if path.String() != `\Windows\System32\ntdll.dll` || pathErr.Kind != "missing" {
		t.Fatal(path, pathErr)
	}
	missing := evidence.Missing("unreadable_or_unavailable", context.Canceled)
	path, pathErr = ldrPath(missing)
	if path.Kind != "missing" || path.Error != "" || path.Reason != "unreadable_or_unavailable" || pathErr.Error == "" {
		t.Fatal(path, pathErr)
	}
}
