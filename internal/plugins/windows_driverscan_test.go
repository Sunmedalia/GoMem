package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func driverScanSymbols() *symbols.ISF {
	table := mutantScanSymbols()
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	unicode := symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}
	table.Types["_DRIVER_OBJECT"] = symbols.Type{Kind: "struct", Size: 336, Fields: map[string]symbols.Field{
		"DriverStart":     {Offset: 24, Type: ptr},
		"DriverSize":      {Offset: 32, Type: u32},
		"DriverExtension": {Offset: 48, Type: ptr},
		"DriverName":      {Offset: 56, Type: unicode},
	}}
	table.Types["_DRIVER_EXTENSION"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{
		"ServiceKeyName": {Offset: 24, Type: unicode},
	}}
	table.Symbols["MmSystemRangeStart"] = symbols.Symbol{Address: 0x20}
	return table
}

func TestWindowsDriverScanKeepsKernelOrZeroStart(t *testing.T) {
	buf := make(flatMemory, 0x1200)
	for i := range buf {
		buf[i] = 0xff
	}
	putU64(buf, 0x20, 0xFFFF800000000000)
	putHeader := func(header uint64, typeIndex byte) uint64 {
		buf[header+2] = 16
		buf[header+3] = 2
		copy(buf[header+4:], []byte("Driv"))
		start := header + 16
		putU64(buf, start, 1)
		buf[start+24] = typeIndex
		buf[start+26] = 1
		return start + 48
	}
	first := putHeader(0x200, 3)
	putU64(buf, first+24, 0)
	putU64(buf, first+32, 0x1000)
	putU64(buf, first+48, 0)
	putUnicode(buf, first+56, 0x480, `\Driver\Foo`)
	low := putHeader(0x500, 4)
	putU64(buf, low+24, 0x1000)
	putU64(buf, low+32, 0x20)
	high := putHeader(0x900, 8)
	putU64(buf, high+24, 0xFFFF800000010000)
	putU64(buf, high+32, 0x2000)
	putU64(buf, high+48, 0)
	putUnicode(buf, high+56, 0xa80, `\Driver\Bar`)
	buf[0x100] = 0
	buf[0x101] = 0x30
	putUnicode(buf, 0x1e8, 0x300, `\Driver\Foo`)
	putUnicode(buf, 0x8e8, 0xb00, `\Driver\Bar`)
	putU64(buf, 0x188, 0x700)
	putUnicode(buf, 0x710, 0x780, "Driver")
	table := driverScanSymbols()
	env := plugin.Environment{Physical: buf, Kernel: buf, Symbols: table, Objects: &object.Reader{Layer: buf, Symbols: table}, OS: "windows"}
	var drivers []evidence.Row
	var summary evidence.Row
	if err := windowsDriverScan(context.Background(), env, nil, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "driver":
			drivers = append(drivers, row)
		case "summary":
			summary = row
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(drivers) != 2 {
		for _, row := range drivers {
			t.Log(row.Cells["Offset"], row.Cells["Start"], row.Cells["Name"], row.Cells["DriverName"])
		}
		t.Fatalf("drivers %d", len(drivers))
	}
	if drivers[0].Cells["Offset"].String() != "0x0000000000000240" || drivers[0].Cells["Start"].String() != "0x0000000000000000" || drivers[0].Cells["Size"].String() != "4096" || drivers[0].Cells["Name"].String() != `\Driver\Foo` || drivers[0].Cells["DriverName"].String() != `\Driver\Foo` || drivers[0].Cells["ServiceKey"].String() != "<name_unavailable>" {
		t.Fatalf("%+v", drivers[0].Cells)
	}
	if drivers[1].Cells["Offset"].String() != "0x0000000000000940" || drivers[1].Cells["Start"].String() != "0xffff800000010000" || drivers[1].Cells["Name"].String() != `\Driver\Bar` {
		t.Fatalf("%+v", drivers[1].Cells)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["drivers"] != "2" || coverage["top_down"] != "true" {
		t.Fatal(coverage)
	}
}
