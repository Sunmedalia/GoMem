package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsDriverIRPHandlers(t *testing.T) {
	if maskKernelStart(0xFFFF800000000000, 8) != 0x800000000000 || maskKernelStart(0x80000000, 4) != 0x80000000 {
		t.Fatal(maskKernelStart(0xFFFF800000000000, 8))
	}
	mem := make(flatMemory, 0x130)
	object := uint64(0x100)
	major := uint64(0x10)
	putU64(mem, object+major, 0xFFFF800000001234)
	putU64(mem, object+major+8, 0xFFFF000000001000)
	putU64(mem, object+major+16, 0xFFFF800000002000)
	putU64(mem, object+major+24, 0xFFFFF00000000000)
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Size: 8, Endian: "little"}}}
	env := plugin.Environment{Kernel: mem, Symbols: table}
	modules := []kernelModule{{stem: "ntoskrnl", base: 0xFFFF800000000000, size: 0x100000}}
	symbolsByAddress := map[uint64][]string{0x1234: {"Alias", "IopInvalidDeviceRequest"}}
	var stats driverIRPStats
	var rows []evidence.Row
	name, nameErr := driverIRPName(evidence.Missing("unparsable", errIRPName("gone")))
	err := driverIRPObject(context.Background(), env, mem, object, name, nameErr, major, 5, 8, 0x800000000000, modules, symbolsByAddress, &stats, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.low != 1 || stats.unreadable != 1 || stats.outside != 1 || stats.unavailable != 1 || stats.rows != 4 || len(rows) != 4 {
		t.Fatalf("stats %+v rows %d", stats, len(rows))
	}
	if rows[0].Cells["IRP"].String() != "IRP_MJ_CREATE" || rows[0].Cells["Symbol"].String() != "Alias" || rows[1].Cells["Symbol"].String() != "IopInvalidDeviceRequest" {
		t.Fatalf("%s %s %s", rows[0].Cells["IRP"], rows[0].Cells["Symbol"], rows[1].Cells["Symbol"])
	}
	if rows[2].Cells["IRP"].String() != "IRP_MJ_CLOSE" || rows[2].Cells["Symbol"].Reason != "not_available" || rows[2].Cells["Module"].String() != "ntoskrnl" {
		t.Fatal(rows[2].Cells["IRP"], rows[2].Cells["Symbol"], rows[2].Cells["Module"])
	}
	if rows[3].Cells["IRP"].String() != "IRP_MJ_READ" || rows[3].Cells["Module"].Reason != "not_available" || rows[3].Cells["Symbol"].Reason != "not_available" || rows[3].Cells["Symbol"].Error != "" {
		t.Fatal(rows[3].Cells["IRP"], rows[3].Cells["Module"], rows[3].Cells["Symbol"])
	}
	if rows[3].Cells["Address"].String() != "0xfffff00000000000" {
		t.Fatal(rows[3].Cells["Address"])
	}
	if rows[0].Cells["DriverName"].Reason != "not_applicable" || rows[0].Cells["DriverName"].Error != "" || rows[0].Cells["DriverNameError"].Error != "gone" {
		t.Fatal(rows[0].Cells["DriverName"], rows[0].Cells["DriverNameError"])
	}
}

type irpNameError string

func (e irpNameError) Error() string { return string(e) }

func errIRPName(text string) error { return irpNameError(text) }
