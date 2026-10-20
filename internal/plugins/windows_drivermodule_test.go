package plugins

import (
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsDriverModuleDecision(t *testing.T) {
	modules := []kernelModule{{stem: "ntoskrnl", base: 0xFFFFF80436000000, size: 0x1000000}}
	kernel := maskKernelStart(0xFFFF800000000000, 8)
	raw := evidence.Text("RAW")
	other := evidence.Text("Foo")
	alt := evidence.Text(`\FileSystem\RAW`)
	missing := evidence.Missing("name_unavailable", nil)
	emit, known, why := driverModuleDecide(0, 8, kernel, modules, raw, missing, alt)
	if !emit || !known || why != "hidden" {
		t.Fatalf("raw %v %v %s", emit, known, why)
	}
	emit, known, why = driverModuleDecide(0xFFFFF8043601F000, 8, kernel, modules, evidence.Text("ACPI_HAL"), missing, missing)
	if emit || known || why != "in_module" {
		t.Fatalf("in module %v %v %s", emit, known, why)
	}
	emit, known, why = driverModuleDecide(0xFFFFF90000000000, 8, kernel, modules, other, missing, missing)
	if !emit || known || why != "hidden" {
		t.Fatalf("outside %v %v %s", emit, known, why)
	}
	emit, _, why = driverModuleDecide(0xFFFFF90000000000, 8, kernel, modules, missing, missing, missing)
	if emit || why != "unnamed" {
		t.Fatalf("unnamed %v %s", emit, why)
	}
	emit, _, why = driverModuleDecide(0xFFFF000000001000, 8, kernel, modules, raw, missing, alt)
	if emit || why != "smear" {
		t.Fatalf("smear %v %s", emit, why)
	}
	emit, known, why = driverModuleDecide(0, 8, kernel, modules, missing, evidence.Text("RAW"), missing)
	if !emit || known || why != "hidden" {
		t.Fatalf("service only %v %v %s", emit, known, why)
	}
	if !knownDriverModuleName("Fs_Rec") || knownDriverModuleName("Raw") || knownDriverModuleName("ntoskrnl") {
		t.Fatal("known names")
	}
}
