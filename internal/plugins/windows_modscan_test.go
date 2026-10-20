package plugins

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func putU32(b []byte, addr uint64, value uint32) {
	binary.LittleEndian.PutUint32(b[addr:], value)
}

func modScanSymbols() *symbols.ISF {
	table := fileSymbols(true)
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	unicode := symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}
	table.Types["_LDR_DATA_TABLE_ENTRY"] = symbols.Type{Kind: "struct", Size: 288, Fields: map[string]symbols.Field{
		"DllBase":     {Offset: 48, Type: ptr},
		"SizeOfImage": {Offset: 64, Type: u32},
		"FullDllName": {Offset: 72, Type: unicode},
		"BaseDllName": {Offset: 88, Type: unicode},
	}}
	return table
}

func putModule(buf flatMemory, header uint64, poolType byte, base, size uint64, name, path string, nameBuf, pathBuf uint64, badName bool) {
	buf[header+2] = 20
	buf[header+3] = poolType
	copy(buf[header+4:], []byte("MmLd"))
	object := header + 16
	putU64(buf, object+48, base)
	putU32(buf, object+64, uint32(size))
	if path != "" {
		putUnicode(buf, object+72, pathBuf, path)
	} else {
		putU16(buf, object+72, 0)
		putU16(buf, object+74, 0)
		putU64(buf, object+80, 0)
	}
	if badName {
		putU16(buf, object+88, 8)
		putU16(buf, object+90, 8)
		putU64(buf, object+96, 0xffffffffffffffff)
		return
	}
	if name == "" {
		putU16(buf, object+88, 0)
		putU16(buf, object+90, 0)
		putU64(buf, object+96, 0)
		return
	}
	putUnicode(buf, object+88, nameBuf, name)
}

func TestWindowsModScanKeepsUnreadableNameAndEmptyString(t *testing.T) {
	buf := make(flatMemory, 0x1600)
	for i := range buf {
		buf[i] = 0xff
	}
	putModule(buf, 0x200, 2, 0xffff800000100000, 0x1000, "ntoskrnl.exe", `\SystemRoot\system32\ntoskrnl.exe`, 0x1100, 0x1000, false)
	putModule(buf, 0x400, 2, 0xffff800000200000, 0x2000, "", `\SystemRoot\bad.sys`, 0, 0x1200, true)
	putModule(buf, 0x600, 1, 0xffff800000210000, 0x20, "paged.sys", `\SystemRoot\paged.sys`, 0x1400, 0x1480, false)
	putModule(buf, 0x800, 2, 0xffff800000300000, 3, "", `\SystemRoot\empty.sys`, 0, 0x1300, false)
	table := modScanSymbols()
	env := plugin.Environment{Physical: buf, Kernel: buf, Symbols: table, Objects: &object.Reader{Layer: buf, Symbols: table}, OS: "windows"}
	collect := func(params map[string]string) ([]evidence.Row, evidence.Row) {
		t.Helper()
		var modules []evidence.Row
		var summary evidence.Row
		if err := windowsModScan(context.Background(), env, params, func(row evidence.Row) error {
			switch row.Cells["RecordType"].String() {
			case "module":
				modules = append(modules, row)
			case "summary":
				summary = row
			default:
				t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return modules, summary
	}
	modules, summary := collect(nil)
	if len(modules) != 3 {
		for _, row := range modules {
			t.Log(row.Cells["Offset"], row.Cells["Name"], row.Cells["Path"])
		}
		t.Fatalf("modules %d", len(modules))
	}
	if modules[0].Cells["Offset"].String() != "0x0000000000000210" || modules[0].Cells["Base"].String() != "0xffff800000100000" || modules[0].Cells["Size"].String() != "4096" || modules[0].Cells["Name"].String() != "ntoskrnl.exe" || modules[0].Cells["Path"].String() != `\SystemRoot\system32\ntoskrnl.exe` || modules[0].Cells["FileOutput"].String() != "Disabled" {
		t.Fatalf("named %+v", modules[0].Cells)
	}
	if modules[1].Cells["Name"].String() != "<name_unavailable>" || modules[1].Cells["NameError"].Error == "" || modules[1].Cells["Path"].String() != `\SystemRoot\bad.sys` {
		t.Fatalf("unreadable %+v", modules[1].Cells)
	}
	if modules[2].Cells["Name"].Kind != "string" || modules[2].Cells["Name"].Data != "" || modules[2].Cells["Path"].String() != `\SystemRoot\empty.sys` || modules[2].Cells["Size"].String() != "3" {
		t.Fatalf("empty %+v", modules[2].Cells)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["modules"] != "3" || coverage["top_down"] != "true" || coverage["windows10"] != "true" {
		t.Fatal(coverage)
	}
	filtered, _ := collect(map[string]string{"name": "ntos"})
	if len(filtered) != 2 || filtered[0].Cells["Name"].String() != "ntoskrnl.exe" || filtered[1].Cells["Name"].String() != "<name_unavailable>" {
		t.Fatalf("name filter %+v", filtered)
	}
	byBase, _ := collect(map[string]string{"base": "0xffff800000300000"})
	if len(byBase) != 1 || byBase[0].Cells["Path"].String() != `\SystemRoot\empty.sys` {
		t.Fatalf("base filter %+v", byBase)
	}
}

func TestWindowsModScanBaseReadFailsTheTask(t *testing.T) {
	buf := make(flatMemory, 0x800)
	for i := range buf {
		buf[i] = 0xff
	}
	putModule(buf, 0x200, 2, 0xffff800000100000, 0x1000, "ntoskrnl.exe", `\SystemRoot\system32\ntoskrnl.exe`, 0x500, 0x600, false)
	layer := failSmallRead{flatMemory: buf, addr: 0x240}
	table := modScanSymbols()
	env := plugin.Environment{Physical: layer, Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows"}
	err := windowsModScan(context.Background(), env, nil, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "module" {
			t.Fatal("unreadable DllBase emitted a module")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected DllBase failure")
	}
}
