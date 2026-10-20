package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsSSDTShiftsModulesAndSkipsOutside(t *testing.T) {
	const base = uint64(0x100000)
	mem := make(flatMemory, 0x110000)
	table := ssdtSymbols64()
	linkSSDT(mem, base+0x80, []uint64{0x2000, 0x2400, 0x2800, 0x2c00}, 8)
	putSSDTModule(mem, 0x2000, base, 0x20000, "ntoskrnl.exe", 0x3000)
	putSSDTModule(mem, 0x2400, 0x100700, 0x20, "extra.sys", 0x3100)
	putSSDTModule(mem, 0x2800, 0x100620, 0x10, "skip.sys", 0x3200)
	putU16(mem, 0x2800+0x20, 1)
	putSSDTModule(mem, 0x2c00, 0x4000, 0x2000, "low.sys", 0x3300)
	putU32(mem, base+0x600, 4)
	putSSDTDelta(mem, base+0x500, 0, 0x100620)
	putSSDTDelta(mem, base+0x500, 1, 0x100700)
	putSSDTDelta(mem, base+0x500, 2, 0x4800)
	putSSDTDelta(mem, base+0x500, 3, 0x900000)

	rows := runSSDT(t, mem, table, base)
	got := filterSSDT(rows, "service")
	want := []struct {
		index  uint64
		module string
		symbol string
		absent bool
	}{
		{0, "ntoskrnl", "NtClose", false},
		{0, "ntoskrnl", "ZwClose", false},
		{1, "ntoskrnl", "", true},
		{1, "extra", "Hook", false},
		{2, "low", "", true},
	}
	if len(got) != len(want) {
		t.Fatalf("%d %#v", len(got), ssdtCells(got))
	}
	for i, row := range got {
		index, _ := row.Cells["Index"].Uint()
		if index != want[i].index || row.Cells["Module"].String() != want[i].module {
			t.Fatalf("row %d index %d module %s", i, index, row.Cells["Module"])
		}
		if want[i].absent {
			if row.Cells["Symbol"].Kind != "missing" || row.Cells["Symbol"].Reason != "not_available" || row.Cells["Symbol"].Error != "" {
				t.Fatalf("row %d symbol %#v", i, row.Cells["Symbol"])
			}
		} else if row.Cells["Symbol"].String() != want[i].symbol {
			t.Fatalf("row %d symbol %q", i, row.Cells["Symbol"])
		}
	}
	coverage := ssdtCoverage(t, rows)
	if coverage["entries"] != "4" || coverage["rows"] != "5" || coverage["modules"] != "3" || coverage["outside"] != "1" || coverage["symbols_unavailable"] != "2" {
		t.Fatal(coverage)
	}
	if ssdtDisplaySymbol("NtClose") != "NtClose" || ssdtDisplaySymbol("foo!bar") != "foo" {
		t.Fatal(ssdtDisplaySymbol("foo!bar"))
	}
}

func TestWindowsSSDT32BitUsesAbsolutePointers(t *testing.T) {
	const base = uint64(0x10000)
	mem := make(flatMemory, 0x12000)
	table := ssdtSymbols32()
	linkSSDT(mem, base+0x80, []uint64{0x3000}, 4)
	putSSDTModule32(mem, 0x3000, 0x2000, 0x1000, "ntoskrnl.exe", 0x3400)
	putU32(mem, base+0x500, 2)
	putU32(mem, base+0x400, 0x2200)
	putU32(mem, base+0x404, 0x9000)
	rows := runSSDT(t, mem, table, base)
	got := filterSSDT(rows, "service")
	if len(got) != 1 || got[0].Cells["Module"].String() != "ntoskrnl" || got[0].Cells["Symbol"].String() != "NtCreateFile" {
		t.Fatalf("%#v", ssdtCells(got))
	}
	address, _ := got[0].Cells["Address"].Uint()
	if address != 0x2200 {
		t.Fatal(address)
	}
}

func TestWindowsSSDTDuplicateModuleStemFails(t *testing.T) {
	const base = uint64(0x100000)
	mem := make(flatMemory, 0x110000)
	table := ssdtSymbols64()
	linkSSDT(mem, base+0x80, []uint64{0x2000, 0x2400}, 8)
	putSSDTModule(mem, 0x2000, base, 0x1000, "ntoskrnl.exe", 0x3000)
	putSSDTModule(mem, 0x2400, base+0x2000, 0x1000, "ntoskrnl.dll", 0x3100)
	putU32(mem, base+0x600, 0)
	env := plugin.Environment{Physical: mem, Kernel: mem, Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}, OS: "windows", KernelBase: base}
	err := windowsSSDT(context.Background(), env, nil, func(evidence.Row) error { return nil })
	if err == nil {
		t.Fatal("duplicate stem succeeded")
	}
}

func runSSDT(t *testing.T, layer flatMemory, table *symbols.ISF, base uint64) []evidence.Row {
	t.Helper()
	env := plugin.Environment{Physical: layer, Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows", KernelBase: base, ImageHash: "img"}
	var rows []evidence.Row
	if err := windowsSSDT(context.Background(), env, nil, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

func filterSSDT(rows []evidence.Row, kind string) []evidence.Row {
	var out []evidence.Row
	for _, row := range rows {
		if row.Cells["RecordType"].String() == kind {
			out = append(out, row)
		}
	}
	return out
}

func ssdtCoverage(t *testing.T, rows []evidence.Row) map[string]any {
	t.Helper()
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "summary" {
			data, _ := row.Cells["Coverage"].Data.(map[string]any)
			return data
		}
	}
	t.Fatal("missing summary")
	return nil
}

func ssdtCells(rows []evidence.Row) []map[string]evidence.Value {
	var out []map[string]evidence.Value
	for _, row := range rows {
		out = append(out, row.Cells)
	}
	return out
}

func linkSSDT(mem flatMemory, head uint64, nodes []uint64, pointer int) {
	putWidth(mem, head+uint64(pointer), nodes[len(nodes)-1], pointer)
	prev := head
	for i, node := range nodes {
		next := head
		if i+1 < len(nodes) {
			next = nodes[i+1]
		}
		putWidth(mem, node, next, pointer)
		putWidth(mem, node+uint64(pointer), prev, pointer)
		prev = node
	}
	putWidth(mem, head, nodes[0], pointer)
}

func putWidth(mem []byte, addr, value uint64, pointer int) {
	if pointer == 4 {
		putU32(mem, addr, uint32(value))
		return
	}
	putU64(mem, addr, value)
}

func putSSDTDelta(mem []byte, table uint64, index int, target uint64) {
	delta := int64(target) - int64(table)
	putU32(mem, table+uint64(index*4), uint32(int32(delta)<<4))
}

func putSSDTModule(mem flatMemory, object, base, size uint64, name string, buf uint64) {
	putHandleUnicode(mem, object+0x20, buf, name)
	putU64(mem, object+0x40, base)
	putU32(mem, object+0x48, uint32(size))
}

func putSSDTModule32(mem flatMemory, object, base, size uint64, name string, buf uint64) {
	raw := fileUTF16Bytes(name)
	putU16(mem, object+0x20, uint16(len(raw)))
	putU16(mem, object+0x22, uint16(len(raw)))
	putU32(mem, object+0x24, uint32(buf))
	copy(mem[buf:], raw)
	putU32(mem, object+0x40, uint32(base))
	putU32(mem, object+0x44, uint32(size))
}

func ssdtSymbols64() *symbols.ISF {
	table := ssdtSymbolTable(8)
	table.Symbols = map[string]symbols.Symbol{
		"PsLoadedModuleList": {Address: 0x80},
		"KiServiceTable":     {Address: 0x500},
		"KiServiceLimit":     {Address: 0x600},
		"ZwClose":            {Address: 0x620},
		"NtClose":            {Address: 0x620},
		"Hook":               {Address: 0},
	}
	return table
}

func ssdtSymbols32() *symbols.ISF {
	table := ssdtSymbolTable(4)
	unicode := table.Types["_UNICODE_STRING"]
	unicode.Fields["Buffer"] = symbols.Field{Offset: 4, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["_UNICODE_STRING"] = unicode
	module := table.Types["_KLDR_DATA_TABLE_ENTRY"]
	module.Fields["BaseDllName"] = symbols.Field{Offset: 0x20, Type: symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}}
	module.Fields["DllBase"] = symbols.Field{Offset: 0x40, Type: symbols.TypeRef{Kind: "base", Name: "unsigned long"}}
	module.Fields["SizeOfImage"] = symbols.Field{Offset: 0x44, Type: symbols.TypeRef{Kind: "base", Name: "unsigned long"}}
	table.Types["_KLDR_DATA_TABLE_ENTRY"] = module
	table.Types["_LIST_ENTRY"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{
		"Flink": {Type: symbols.TypeRef{Kind: "pointer"}},
		"Blink": {Offset: 4, Type: symbols.TypeRef{Kind: "pointer"}},
	}}
	table.Symbols = map[string]symbols.Symbol{
		"PsLoadedModuleList": {Address: 0x80},
		"KiServiceTable":     {Address: 0x400},
		"KiServiceLimit":     {Address: 0x500},
		"NtCreateFile":       {Address: 0x200},
	}
	return table
}

func ssdtSymbolTable(pointer int) *symbols.ISF {
	u16 := symbols.TypeRef{Kind: "base", Name: "unsigned short"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	u64 := symbols.TypeRef{Kind: "base", Name: "unsigned long long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	base := u64
	if pointer == 4 {
		base = u32
	}
	return &symbols.ISF{
		Bases: map[string]symbols.Type{
			"pointer":            {Size: uint64(pointer), Endian: "little"},
			"unsigned short":     {Size: 2, Endian: "little"},
			"unsigned long":      {Size: 4, Endian: "little"},
			"unsigned long long": {Size: 8, Endian: "little"},
			"long":               {Size: 4, Endian: "little", Signed: true},
		},
		Types: map[string]symbols.Type{
			"_LIST_ENTRY": {Kind: "struct", Size: uint64(pointer * 2), Fields: map[string]symbols.Field{
				"Flink": {Type: ptr}, "Blink": {Offset: uint64(pointer), Type: ptr},
			}},
			"_UNICODE_STRING": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
				"Length": {Type: u16}, "MaximumLength": {Offset: 2, Type: u16}, "Buffer": {Offset: 8, Type: ptr},
			}},
			"_KLDR_DATA_TABLE_ENTRY": {Kind: "struct", Size: 0x60, Fields: map[string]symbols.Field{
				"InLoadOrderLinks": {Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}},
				"BaseDllName":      {Offset: 0x20, Type: symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}},
				"DllBase":          {Offset: 0x40, Type: base},
				"SizeOfImage":      {Offset: 0x48, Type: u32},
			}},
		},
	}
}
