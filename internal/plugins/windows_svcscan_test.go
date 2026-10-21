package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
)

func TestSvcScanPluginRegistered(t *testing.T) {
	registry := plugin.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	spec, err := registry.Get("windows.svcscan")
	if err != nil || spec.Spec().Upstream != "windows.svcscan.SvcScan" {
		t.Fatal(err, spec)
	}
}

func TestServiceTypeAndRegistryString(t *testing.T) {
	if serviceTypeName(16|256) != "SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS" {
		t.Fatal(serviceTypeName(16 | 256))
	}
	if serviceTypeName(0) != "" || svcStartNames[3] != "SERVICE_DEMAND_START" || svcStateNames[4] != "SERVICE_RUNNING" {
		t.Fatal("enum")
	}
	text, ok := registryUTF16(registry.Value{Data: utf16Bytes(`System32\DRIVERS\srvnet.sys`)})
	if !ok || text != `System32\DRIVERS\srvnet.sys` {
		t.Fatal(text, ok)
	}
	if _, ok = registryUTF16(registry.Value{Data: []byte{0}}); ok {
		t.Fatal("odd length decoded")
	}
	// A failed value read is zero-filled by the pinned decoder, then rstrip leaves nothing.
	text, ok = registryUTF16(registry.Value{DataErr: errors.New("missing cell")})
	if !ok || text != "" {
		t.Fatal(text, ok)
	}
}

func TestServiceWalkUsesPrevEntryAddress(t *testing.T) {
	mem := make(flatMemory, 0x1000)
	copy(mem[0x100:], []byte("serH"))
	putU64(mem, 0x110, 0x200)
	putService(mem, 0x200, 0x400, 7, 3, 1, 4, 0x800, 0x840, 0x880)
	putService(mem, 0x400, 0, 6, 2, 16, 1, 0x900, 0x940, 0)
	putUTF16(mem, 0x800, "srvnet")
	putUTF16(mem, 0x840, "srvnet display")
	putUTF16(mem, 0x880, `\FileSystem\srvnet`)
	putUTF16(mem, 0x900, "stopped")
	putUTF16(mem, 0x940, "stopped display")
	var rows []evidence.Row
	seen := map[string]bool{}
	stats := svcStats{}
	err := (serviceReader{mem, serviceLayouts["services-win10-19041-x64"]}).walkHeader(context.Background(), 0x100, nil, seen, &stats, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	})
	if err != nil || len(rows) != 2 || stats.records != 2 {
		t.Fatal(len(rows), stats, err)
	}
	if rows[0].Cells["Offset"].String() != "0x0000000000000200" || rows[0].Cells["Name"].String() != "srvnet" || rows[0].Cells["Binary"].String() != `\FileSystem\srvnet` || rows[0].Cells["PID"].Kind != "missing" {
		t.Fatal(rows[0].Cells)
	}
	if rows[1].Cells["Offset"].String() != "0x0000000000000210" || rows[1].Cells["Order"].String() != "6" || rows[1].Cells["Binary"].Kind != "missing" || rows[1].Cells["State"].String() != "SERVICE_STOPPED" {
		t.Fatal(rows[1].Cells)
	}
	// PID and binary are fresh absent values here, and neither name is in the
	// registry map, so the pinned tuple comparison does not stop the chain.
	before := len(rows)
	if err = (serviceReader{mem, serviceLayouts["services-win10-19041-x64"]}).walkHeader(context.Background(), 0x100, nil, seen, &stats, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil || len(rows) != before+2 || stats.records != 4 {
		t.Fatal("unstable chain should be emitted again", len(rows), stats, err)
	}
}

func TestServiceWalkStopsOnStableDuplicate(t *testing.T) {
	mem := make(flatMemory, 0x1200)
	copy(mem[0x100:], []byte("serH"))
	putU64(mem, 0x110, 0x200)
	putService(mem, 0x200, 0, 9, 3, 32, 4, 0x800, 0x840, 0xA00)
	putUTF16(mem, 0x800, "spooler")
	putUTF16(mem, 0x840, "spooler display")
	putU64(mem, 0xA00+serviceLayouts["services-win10-19041-x64"].binaryPtr, 0xB00)
	putU32(mem, 0xA00+serviceLayouts["services-win10-19041-x64"].pid, 1234)
	putUTF16(mem, 0xB00, `C:\spoolsv.exe`)
	binaries := map[string]svcBinary{
		"spooler": {path: `C:\Windows\System32\spoolsv.exe`, dll: `spoolsv.dll`, pathOK: true, dllOK: true},
	}
	var rows []evidence.Row
	seen := map[string]bool{}
	stats := svcStats{}
	emit := func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}
	if err := (serviceReader{mem, serviceLayouts["services-win10-19041-x64"]}).walkHeader(context.Background(), 0x100, binaries, seen, &stats, emit); err != nil || len(rows) != 1 {
		t.Fatal(len(rows), err)
	}
	if rows[0].Cells["PID"].String() != "1234" || rows[0].Cells["Binary"].String() != `C:\spoolsv.exe` || rows[0].Cells["BinaryRegistry"].String() != `C:\Windows\System32\spoolsv.exe` || rows[0].Cells["Dll"].String() != "spoolsv.dll" {
		t.Fatal(rows[0].Cells)
	}
	if err := (serviceReader{mem, serviceLayouts["services-win10-19041-x64"]}).walkHeader(context.Background(), 0x100, binaries, seen, &stats, emit); err != nil || len(rows) != 1 || stats.records != 1 {
		t.Fatal("stable duplicate chain was emitted", len(rows), stats, err)
	}
}

func putService(mem flatMemory, record, prev uint64, order, start, typ, state uint32, name, display, proc uint64) {
	putU64(mem, record+serviceLayouts["services-win10-19041-x64"].prev, prev)
	binary.LittleEndian.PutUint32(mem[record+serviceLayouts["services-win10-19041-x64"].order:], order)
	binary.LittleEndian.PutUint32(mem[record+serviceLayouts["services-win10-19041-x64"].start:], start)
	putU64(mem, record+serviceLayouts["services-win10-19041-x64"].namePtr, name)
	putU64(mem, record+serviceLayouts["services-win10-19041-x64"].displayPtr, display)
	binary.LittleEndian.PutUint32(mem[record+serviceLayouts["services-win10-19041-x64"].serviceType:], typ)
	binary.LittleEndian.PutUint32(mem[record+serviceLayouts["services-win10-19041-x64"].state:], state)
	putU64(mem, record+serviceLayouts["services-win10-19041-x64"].processPtr, proc)
}

func putUTF16(mem flatMemory, addr uint64, text string) {
	units := utf16.Encode([]rune(text))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(mem[addr+uint64(i*2):], unit)
	}
}
