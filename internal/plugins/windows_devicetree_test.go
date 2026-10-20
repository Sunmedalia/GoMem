package plugins

import (
	"context"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type holeMemory struct {
	flatMemory
	holes []uint64
}

func (m holeMemory) ReadAt(ctx context.Context, p []byte, addr uint64) (int, error) {
	// Pool scans read the layer in large windows. Only a field-sized read of the
	// hole fails, which is the unreadable AttachedDevice pointer in this fixture.
	if len(p) <= 8 {
		end := addr + uint64(len(p))
		for _, hole := range m.holes {
			if addr < hole+8 && end > hole {
				return 0, io.ErrUnexpectedEOF
			}
		}
	}
	return m.flatMemory.ReadAt(ctx, p, addr)
}

func TestWindowsDeviceTreeLinksNamesAndStops(t *testing.T) {
	buf := make(flatMemory, 0x3600)
	for i := range buf {
		buf[i] = 0xff
	}
	putU64(buf, 0x20, 0xFFFF800000000000)
	buf[0x100] = 0
	buf[0x101] = 0x30
	putU64(buf, 0x188, 0x1800)
	putUnicode(buf, 0x1810, 0x1900, "Driver")
	table := driverScanSymbols()
	driver := table.Types["_DRIVER_OBJECT"]
	driver.Fields["DeviceObject"] = symbols.Field{Offset: 8, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["_DRIVER_OBJECT"] = driver
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	table.Types["_DEVICE_OBJECT"] = symbols.Type{Kind: "struct", Size: 80, Fields: map[string]symbols.Field{
		"DeviceType":     {Type: u32},
		"DriverObject":   {Offset: 8, Type: ptr},
		"NextDevice":     {Offset: 16, Type: ptr},
		"AttachedDevice": {Offset: 24, Type: ptr},
	}}

	putPoolDriver := func(pool, start, device uint64, infoMask byte, name string, nameBuf uint64) uint64 {
		header := pool + 16
		buf[pool+2] = 16
		buf[pool+3] = 2
		copy(buf[pool+4:pool+8], []byte("Driv"))
		putU64(buf, header, 1)
		buf[header+24] = byte((header >> 8) ^ 1)
		buf[header+26] = infoMask
		body := header + 48
		putU64(buf, body+8, device)
		putU64(buf, body+24, start)
		if infoMask == 1 {
			putUnicode(buf, header-0x30+8, nameBuf, name)
		}
		return body
	}
	putDev := func(addr, devType, next, attached, driver uint64, infoMask byte, name string, nameBuf uint64) {
		for i := uint64(0); i < 32; i++ {
			buf[addr+i] = 0
		}
		putU32(buf, addr, uint32(devType))
		putU64(buf, addr+8, driver)
		putU64(buf, addr+16, next)
		putU64(buf, addr+24, attached)
		header := addr - 48
		buf[header+26] = infoMask
		if infoMask == 1 {
			putUnicode(buf, header-0x30+8, nameBuf, name)
		}
	}
	putNamedDriver := func(addr uint64, name string, nameBuf uint64) {
		for i := uint64(0); i < 80; i++ {
			buf[addr+i] = 0
		}
		putUnicode(buf, addr+56, nameBuf, name)
	}

	const (
		d1  = 0x2100
		a1  = 0x2200
		a2  = 0x2300
		d2  = 0x2400
		e1  = 0x2500
		e2  = 0x2600
		u1  = 0x2700
		t1  = 0x2800
		t2  = 0x2900
		c1  = 0x2a00
		flt = 0x2b00
		vol = 0x2c00
	)
	putNamedDriver(flt, `\Driver\Flt`, 0x3000)
	putNamedDriver(vol, `\Driver\Vol`, 0x3040)
	putDev(d1, 0x7, d2, a1, 0, 1, "Disk", 0x3080)
	putDev(a1, 0x22, 0, a2, flt, 1, "Filt", 0x30c0)
	putDev(a2, 0x12, 0, 0, vol, 0, "", 0)
	putDev(d2, 0x22, 0, 0, 0, 1, "Hidden", 0x3100)
	putDev(e1, 0x99, e2, 0, 0, 1, "", 0x3140)
	putDev(e2, 0x22, 0, 0, 0, 1, "HiddenEmpty", 0x3180)
	putDev(u1, 0x22, 0, 0, 0, 1, "Named", 0x31c0)
	putDev(t1, 0x4, t2, 0, 0, 1, "Edge", 0x3200)
	putDev(t2, 0x22, 0, 0, 0, 1, "Second", 0x3240)
	putDev(c1, 0x7, c1, 0, 0, 1, "Loop", 0x3280)
	putPoolDriver(0x400, 0, d1, 1, `\Driver\Tree`, 0x32c0)
	putPoolDriver(0x600, 0, 0, 1, `\Driver\Only`, 0x3300)
	putPoolDriver(0x800, 0x1000, 0, 1, `\Driver\Drop`, 0x3340)
	putPoolDriver(0xa00, 0, e1, 1, `\Driver\Empty`, 0x3380)
	putPoolDriver(0xc00, 0, u1, 0, "", 0)
	putPoolDriver(0xe00, 0, c1, 1, `\Driver\Cycle`, 0x33c0)
	putPoolDriver(0x1200, 0, t1, 1, `\Driver\Two`, 0x3400)

	layer := holeMemory{flatMemory: buf, holes: []uint64{t1 + 24, c1 + 24}}
	env := plugin.Environment{Physical: layer, Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows"}
	var rows []evidence.Row
	if err := windowsDeviceTree(context.Background(), env, nil, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var entities []evidence.Row
	var summary evidence.Row
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "summary":
			summary = row
		case "driver", "device", "attached":
			entities = append(entities, row)
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
	}
	want := []struct {
		kind, driver, device, attached, devType, parent string
		depth                                           int
	}{
		{"DRV", `\Driver\Tree`, "<not_applicable>", "<not_applicable>", "<not_applicable>", "", 0},
		{"DEV", `\Driver\Tree`, "Disk", "<not_applicable>", "FILE_DEVICE_DISK", "0", 1},
		{"ATT", `\Driver\Tree`, "Filt", `\Driver\Flt`, "FILE_DEVICE_UNKNOWN", "1", 2},
		{"ATT", `\Driver\Tree`, "<unparsable>", `\Driver\Vol`, "FILE_DEVICE_NETWORK", "2", 3},
		{"DRV", `\Driver\Only`, "<not_applicable>", "<not_applicable>", "<not_applicable>", "", 0},
		{"DRV", `\Driver\Empty`, "<not_applicable>", "<not_applicable>", "<not_applicable>", "", 0},
		{"DEV", `\Driver\Empty`, "", "<not_applicable>", "UNKNOWN", "5", 1},
		{"DRV", "<unparsable>", "<not_applicable>", "<not_applicable>", "<not_applicable>", "", 0},
		{"DEV", "<unparsable>", "Named", "<not_applicable>", "FILE_DEVICE_UNKNOWN", "7", 1},
		{"DRV", `\Driver\Cycle`, "<not_applicable>", "<not_applicable>", "<not_applicable>", "", 0},
		{"DEV", `\Driver\Cycle`, "Loop", "<not_applicable>", "FILE_DEVICE_DISK", "9", 1},
		{"DRV", `\Driver\Two`, "<not_applicable>", "<not_applicable>", "<not_applicable>", "", 0},
		{"DEV", `\Driver\Two`, "Edge", "<not_applicable>", "FILE_DEVICE_CONTROLLER", "11", 1},
		{"DEV", `\Driver\Two`, "Second", "<not_applicable>", "FILE_DEVICE_UNKNOWN", "11", 1},
	}
	if len(entities) != len(want) {
		for _, row := range entities {
			t.Log(row.ID, row.ParentID, row.Cells["Type"], row.Cells["DriverName"], row.Cells["DeviceName"], row.Cells["DriverNameOfAttDevice"], row.Cells["DeviceType"], row.Cells["Depth"])
		}
		t.Fatalf("rows %d", len(entities))
	}
	byID := map[string]evidence.Row{}
	for i, row := range entities {
		byID[row.ID] = row
		item := want[i]
		if row.Cells["Type"].String() != item.kind || row.Cells["DriverName"].String() != item.driver || row.Cells["DeviceName"].String() != item.device || row.Cells["DriverNameOfAttDevice"].String() != item.attached || row.Cells["DeviceType"].String() != item.devType || row.ParentID != item.parent || row.Cells["Depth"].String() != evidence.Number(uint64(item.depth)).String() {
			t.Fatalf("row %d got type %s driver %s device %s att %s devtype %s parent %s depth %s", i, row.Cells["Type"], row.Cells["DriverName"], row.Cells["DeviceName"], row.Cells["DriverNameOfAttDevice"], row.Cells["DeviceType"], row.ParentID, row.Cells["Depth"])
		}
		if item.device == "" && row.Cells["DeviceName"].Kind != "string" {
			t.Fatal("empty device name was dropped")
		}
		if item.parent != "" {
			parent := byID[item.parent]
			if row.Cells["Offset"].String() != parent.Cells["Offset"].String() {
				t.Fatal("child offset drifted from the driver")
			}
		}
	}
	if entities[3].Cells["ObjectOffset"].String() == entities[2].Cells["ObjectOffset"].String() {
		t.Fatal("attached objects lost their own addresses")
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["drivers"] != "6" || coverage["devices"] != "6" || coverage["attached"] != "2" || coverage["stopped_drivers"] != "5" {
		t.Fatal(coverage)
	}
}
