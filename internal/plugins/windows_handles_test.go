package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsHandlesNamesLevelsAndStops(t *testing.T) {
	mem := make(flatMemory, 0x9000)
	table := handleSymbols(true, 8)
	linkProcesses(mem, 0x80, []uint64{0x1000, 0x1400})
	putU64(mem, 0x1000+0x10, 4)
	copy(mem[0x1000+0x20:], []byte("System"))
	putU64(mem, 0x1000+0x30, 0x1800)
	putU64(mem, 0x1400+0x10, 8)
	copy(mem[0x1400+0x20:], []byte("idle"))
	putU64(mem, 0x1400+0x30, 0x00F00000)

	putHandleU32(mem, 0x200, 0x5a)
	mem[0x210] = 0
	mem[0x211] = 0
	mem[0x212] = 0x20
	mem[0x213] = 0x20
	putType(mem, 0x300, 1, "File", 0x380)
	putType(mem, 0x3a0, 2, "Process", 0x3c0)
	putType(mem, 0x400, 3, "Thread", 0x420)
	putType(mem, 0x460, 4, "Key", 0x480)
	putType(mem, 0x4c0, 5, "Event", 0x4e0)
	putU64(mem, 0x500, 0)
	putU64(mem, 0x508, 0x300)
	putU64(mem, 0x510, 0x3a0)
	putU64(mem, 0x518, 0x400)
	putU64(mem, 0x520, 0x460)
	putU64(mem, 0x528, 0x4c0)
	putU64(mem, 0x530, 0)

	// Level-1 table: page 0 at 0x4000 and page 1 at 0x4800.
	putU64(mem, 0x1800+8, 0x3000|1)
	putU64(mem, 0x3000, 0x4000)
	putU64(mem, 0x3008, 0x7000)
	putU64(mem, 0x3010, 0x3000)

	fileHeader := uint64(0x5100)
	processHeader := uint64(0x5200)
	threadHeader := uint64(0x5300)
	keyHeader := uint64(0x5400)
	namedHeader := uint64(0x5500)
	silentHeader := uint64(0x5600)
	zeroHeader := uint64(0x5700)
	deviceHeader := uint64(0x5800)
	putHeader(mem, fileHeader, 0x5100, 1, 0x5a, 2, "HarddiskVolume1", 0x5a00)
	putHeader(mem, processHeader, 0x5200, 2, 0x5a, 0, "", 0)
	putHeader(mem, threadHeader, 0x5300, 3, 0x5a, 0, "", 0)
	putHeader(mem, keyHeader, 0x5400, 4, 0x5a, 0, "", 0)
	putHeader(mem, namedHeader, 0x5500, 5, 0x5a, 2, "NamedEvent", 0x5a40)
	putHeader(mem, silentHeader, 0x5600, 5, 0x5a, 0, "", 0)
	putHeader(mem, zeroHeader, 0x5700, 5, 0x5a, 0, "", 0)
	mem[zeroHeader+0x18] = 0
	putHeader(mem, deviceHeader, 0x5800, 5, 0x5a, 2, "HarddiskVolume2", 0x5a80)

	putHandle(mem, 0x4010, fileHeader, 0x120089)
	putHandle(mem, 0x4020, processHeader, 0x1fffff)
	putHandle(mem, 0x4030, threadHeader, 0x1fffff)
	putHandle(mem, 0x4040, keyHeader, 0x20019)
	putHandle(mem, 0x4050, namedHeader, 0x1f0003)
	putHandle(mem, 0x4060, silentHeader, 0x1f0003)
	putHandle(mem, 0x4070, zeroHeader, 0x1f0003)
	putHandle(mem, 0x7000, deviceHeader, 0x1f0001)

	putFile(mem, fileHeader+0x20, deviceHeader+0x20, `\Windows\note.exe`, 0x5b00)
	putProcessBody(mem, processHeader+0x20, 72, "Registry")
	putHandleThread(mem, threadHeader+0x20, 72, 88)
	putKey(mem, keyHeader+0x20, 0x6000)
	putKeyChain(mem)

	rows := runHandles(t, mem, table, map[string]string{"pid": "4", "max-nodes": "16"})
	got := filterHandles(rows, "handle")
	want := []struct {
		handle, access uint64
		kind, name     string
		missing        string
	}{
		{4, 0x120089, "File", `\Device\HarddiskVolume2\Windows\note.exe`, ""},
		{8, 0x1fffff, "Process", "Registry Pid 72", ""},
		{12, 0x1fffff, "Thread", "Tid 88 Pid 72", ""},
		{16, 0x20019, "Key", `MACHINE\SYSTEM\CurrentControlSet`, ""},
		{20, 0x1f0003, "Event", "NamedEvent", ""},
		{24, 0x1f0003, "Event", "", "not_available"},
		{1024, 0x1f0001, "Event", "HarddiskVolume2", ""},
	}
	if len(got) != len(want) {
		for _, row := range got {
			t.Log(row.Cells["HandleValue"], row.Cells["Type"], row.Cells["Name"], row.Cells["NameError"])
		}
		t.Fatalf("handles %d", len(got))
	}
	for i, row := range got {
		item := want[i]
		handle, _ := row.Cells["HandleValue"].Uint()
		access, _ := row.Cells["GrantedAccess"].Uint()
		if handle != item.handle || access != item.access || row.Cells["Type"].String() != item.kind || row.Cells["Process"].String() != "System" || row.Cells["PID"].String() != "4" {
			t.Fatalf("row %d handle %d access %#x type %s process %s pid %s", i, handle, access, row.Cells["Type"], row.Cells["Process"], row.Cells["PID"])
		}
		if item.missing != "" {
			if row.Cells["Name"].Kind != "missing" || row.Cells["Name"].Reason != item.missing {
				t.Fatalf("row %d name %#v", i, row.Cells["Name"])
			}
		} else if row.Cells["Name"].String() != item.name {
			t.Fatalf("row %d name %q", i, row.Cells["Name"])
		}
		body, _ := row.Cells["Offset"].Uint()
		if body == 0 {
			t.Fatal("missing body")
		}
	}
	coverage := handleCoverage(t, rows)
	if coverage["handles"] != "7" || coverage["processes"] != "1" || coverage["level1"] != "1" || coverage["cycles"] != "1" || coverage["skipped_handle_tables"] != "0" {
		t.Fatal(coverage)
	}

	filtered := runHandles(t, mem, table, map[string]string{"pid": "99", "max-nodes": "16"})
	if len(filterHandles(filtered, "handle")) != 0 || handleCoverage(t, filtered)["processes"] != "0" {
		t.Fatal(handleCoverage(t, filtered))
	}
}

func TestWindowsHandlesLegacyFastRefAndNarrowInfoTable(t *testing.T) {
	mem := make(flatMemory, 0x3000)
	table := handleSymbols(false, 8)
	linkProcesses(mem, 0x80, []uint64{0x1000})
	putU64(mem, 0x1000+0x10, 4)
	copy(mem[0x1000+0x20:], []byte("old"))
	putU64(mem, 0x1000+0x30, 0x1800)
	putU64(mem, 0x1800+8, 0x2000)
	putU64(mem, 0x2000, 0x2400|0x3)
	putHandleU32(mem, 0x2008, 0x1f0001)
	putU64(mem, 0x2400, 0x2600)
	mem[0x2419] = 0x20
	putHandleUnicode(mem, 0x2600, 0x2700, "Event")
	putHandleUnicode(mem, 0x23e8, 0x2740, "Legacy")
	rows := runHandles(t, mem, table, map[string]string{"max-nodes": "8"})
	got := filterHandles(rows, "handle")
	if len(got) != 1 || got[0].Cells["Type"].String() != "Event" || got[0].Cells["Name"].String() != "Legacy" {
		t.Fatalf("%d %#v", len(got), cells(got))
	}
	handle, _ := got[0].Cells["HandleValue"].Uint()
	access, _ := got[0].Cells["GrantedAccess"].Uint()
	if handle != 0 || access != 0x1f0001 {
		t.Fatal(handle, access)
	}

	narrow := make(flatMemory, 0x3000)
	narrowTable := handleSymbols(true, 4)
	putHandleU32(narrow, 0x80, 0x1000)
	putHandleU32(narrow, 0x84, 0x1000)
	putHandleU32(narrow, 0x1000, 0x80)
	putHandleU32(narrow, 0x1004, 0x80)
	putHandleU32(narrow, 0x1000+0x10, 4)
	copy(narrow[0x1000+0x20:], []byte("narrow"))
	putHandleU32(narrow, 0x1000+0x30, 0x1800)
	putHandleU32(narrow, 0x1800+4, 0x2000)
	putHandleU32(narrow, 0x2000, 0x2403)
	putHandleU32(narrow, 0x2004, 0x21)
	putHandleU32(narrow, 0x2400+0x10, 7)
	for index := 1; index < 7; index++ {
		putHandleU32(narrow, uint64(0x500+index*4), 1)
	}
	putHandleU32(narrow, 0x500+7*4, 0x2800)
	putHandleUnicode(narrow, 0x2800, 0x2900, "Event")
	rows = runHandles(t, narrow, narrowTable, map[string]string{"max-nodes": "8"})
	got = filterHandles(rows, "handle")
	if len(got) != 1 || got[0].Cells["Type"].String() != "Event" {
		t.Fatalf("%d %#v", len(got), cells(got))
	}
	access, _ = got[0].Cells["GrantedAccess"].Uint()
	if access != 0x21 {
		t.Fatal(access)
	}
}

func TestWindowsHandlesOffsetSelectsPoolProcess(t *testing.T) {
	buf := make(flatMemory, 0x3000)
	buf[0x102] = 41
	buf[0x103] = 2
	copy(buf[0x104:], []byte("Proc"))
	putProcess(buf, 0x340, 128, "keep.exe")
	buf[0x402] = 40
	buf[0x403] = 2
	copy(buf[0x404:], []byte("Proc"))
	putProcess(buf, 0x640, 256, "drop.exe")
	table := processScanSymbols()
	process := table.Types["_EPROCESS"]
	process.Size = 80
	process.Fields["ObjectTable"] = symbols.Field{Offset: 64, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["_EPROCESS"] = process
	handle := table.Types["_HANDLE_TABLE"]
	handle.Fields["TableCode"] = symbols.Field{Offset: 4, Type: symbols.TypeRef{Kind: "base", Name: "unsigned long long"}}
	handle.Size = 16
	table.Types["_HANDLE_TABLE"] = handle
	u8 := symbols.TypeRef{Kind: "base", Name: "unsigned char"}
	bits := func(base string, pos, length uint64) symbols.TypeRef {
		underlying := symbols.TypeRef{Kind: "base", Name: base}
		return symbols.TypeRef{Kind: "bitfield", BitPosition: pos, BitLength: length, BitType: &underlying}
	}
	table.Types["_OBJECT_HEADER"] = symbols.Type{Kind: "struct", Size: 0x30, Fields: map[string]symbols.Field{
		"TypeIndex": {Offset: 0x18, Type: u8},
		"InfoMask":  {Offset: 0x19, Type: u8},
		"Body":      {Offset: 0x20, Type: symbols.TypeRef{Kind: "struct", Name: "_QUAD"}},
	}}
	table.Types["_HANDLE_TABLE_ENTRY"] = symbols.Type{Kind: "union", Size: 16, Fields: map[string]symbols.Field{
		"ObjectPointerBits": {Type: bits("unsigned long long", 20, 44)},
		"GrantedAccessBits": {Offset: 8, Type: bits("unsigned long", 0, 25)},
	}}
	table.Types["_OBJECT_HEADER_NAME_INFO"] = symbols.Type{Kind: "struct", Size: 0x20, Fields: map[string]symbols.Field{
		"Name": {Offset: 8, Type: symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}},
	}}
	table.Types["_UNICODE_STRING"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
		"Length": {Type: symbols.TypeRef{Kind: "base", Name: "unsigned short"}},
		"Buffer": {Offset: 8, Type: symbols.TypeRef{Kind: "pointer"}},
	}}
	table.Types["_OBJECT_TYPE"] = symbols.Type{Kind: "struct", Size: 0x20, Fields: map[string]symbols.Field{
		"Name": {Type: symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}},
	}}
	table.Bases["unsigned short"] = symbols.Type{Size: 2, Endian: "little"}
	table.Symbols["ObpInfoMaskToOffset"] = symbols.Symbol{Address: 0xb00}
	table.Symbols["ObTypeIndexTable"] = symbols.Symbol{Address: 0xa00}
	putU64(buf, 0x340+64, 0xc00)
	putU64(buf, 0x640+64, 0xc80)
	putU64(buf, 0xc00+4, 0xd00)
	putU64(buf, 0xc80+4, 0x2000)
	buf[0xb02] = 0
	putU64(buf, 0xa00, 0)
	putU64(buf, 0xa08, 0xb20)
	putU64(buf, 0xa10, 0)
	putHandleUnicode(buf, 0xb20, 0xb40, "Event")
	putHeader(buf, 0xf00, 0xf00, 1, 0, 0, "", 0)
	buf[0xf18] = 1
	putHandle(buf, 0xd00, 0xf00, 7)
	putHeader(buf, 0x2200, 0x2200, 1, 0, 0, "", 0)
	buf[0x2218] = 1
	putHandle(buf, 0x2000, 0x2200, 9)
	rows := runHandles(t, buf, table, map[string]string{"offset": "0x340", "max-nodes": "16"})
	got := filterHandles(rows, "handle")
	if len(got) != 1 || got[0].Cells["Process"].String() != "keep.exe" || got[0].Cells["PID"].String() != "128" {
		t.Fatalf("%d %#v coverage %#v", len(got), cells(got), handleCoverage(t, rows))
	}
	if handleCoverage(t, rows)["mode"] != "psscan" {
		t.Fatal(handleCoverage(t, rows))
	}
}

func runHandles(t *testing.T, layer flatMemory, table *symbols.ISF, params map[string]string) []evidence.Row {
	t.Helper()
	env := plugin.Environment{Physical: layer, Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows", ImageHash: "img"}
	var rows []evidence.Row
	if err := windowsHandles(context.Background(), env, params, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

func filterHandles(rows []evidence.Row, kind string) []evidence.Row {
	var out []evidence.Row
	for _, row := range rows {
		if row.Cells["RecordType"].String() == kind {
			out = append(out, row)
		}
	}
	return out
}

func handleCoverage(t *testing.T, rows []evidence.Row) map[string]any {
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

func cells(rows []evidence.Row) []map[string]evidence.Value {
	var out []map[string]evidence.Value
	for _, row := range rows {
		out = append(out, row.Cells)
	}
	return out
}

func linkProcesses(mem flatMemory, head uint64, processes []uint64) {
	if len(processes) == 0 {
		putU64(mem, head, head)
		putU64(mem, head+8, head)
		return
	}
	putU64(mem, head, processes[0])
	putU64(mem, head+8, processes[len(processes)-1])
	for i, process := range processes {
		next := head
		prev := head
		if i+1 < len(processes) {
			next = processes[i+1]
		}
		if i > 0 {
			prev = processes[i-1]
		}
		putU64(mem, process, next)
		putU64(mem, process+8, prev)
	}
}

func putHandleU32(mem []byte, addr uint64, value uint32) {
	mem[addr] = byte(value)
	mem[addr+1] = byte(value >> 8)
	mem[addr+2] = byte(value >> 16)
	mem[addr+3] = byte(value >> 24)
}

func putType(mem flatMemory, object uint64, index int, name string, buf uint64) {
	putHandleUnicode(mem, object, buf, name)
}

func putHandleUnicode(mem flatMemory, object, buf uint64, text string) {
	raw := fileUTF16Bytes(text)
	putU16(mem, object, uint16(len(raw)))
	putU16(mem, object+2, uint16(len(raw)))
	putU64(mem, object+8, buf)
	copy(mem[buf:], raw)
}

func putHeader(mem flatMemory, header, body uint64, decoded, cookie int, info byte, name string, nameBuf uint64) {
	raw := byte(((header >> 8) ^ uint64(cookie) ^ uint64(decoded)) & 0xff)
	mem[header+0x18] = raw
	mem[header+0x19] = info
	if info&0x2 != 0 {
		putHandleUnicode(mem, header-0x20+8, nameBuf, name)
	}
	_ = body
}

func putHandle(mem flatMemory, slot, header, access uint64) {
	bits := (header & 0x0000ffffffffffff) >> 4
	putU64(mem, slot, bits<<20)
	putHandleU32(mem, slot+8, uint32(access))
}

func putFile(mem flatMemory, body, device uint64, name string, buf uint64) {
	putU64(mem, body+8, device)
	putHandleUnicode(mem, body+0x10, buf, name)
}

func putProcessBody(mem flatMemory, body uint64, pid uint64, name string) {
	putU64(mem, body+0x10, pid)
	copy(mem[body+0x20:], []byte(name))
}

func putHandleThread(mem flatMemory, body, pid, tid uint64) {
	putU64(mem, body+0x40, pid)
	putU64(mem, body+0x48, tid)
}

func putKey(mem flatMemory, body, kcb uint64) {
	putU64(mem, body+8, kcb)
}

func putKeyChain(mem flatMemory) {
	// Leaf hive entry is skipped. Parent and its parent are kept. The root is not.
	putU64(mem, 0x6000+0x10, 0x6100)
	putHandleU32(mem, 0x6000+0x18, keyHiveEntry)
	putU64(mem, 0x6000+0x20, 0x6200)
	putNameBlock(mem, 0x6200, "Skipped")
	putU64(mem, 0x6100+0x10, 0x6300)
	putU64(mem, 0x6100+0x20, 0x6400)
	putNameBlock(mem, 0x6400, "CurrentControlSet")
	putU64(mem, 0x6300+0x10, 0x6500)
	putU64(mem, 0x6300+0x20, 0x6600)
	putNameBlock(mem, 0x6600, "SYSTEM")
	putU64(mem, 0x6500+0x10, 0x6900)
	putU64(mem, 0x6900+0x10, 0)
	putU64(mem, 0x6500+0x20, 0x6700)
	putNameBlock(mem, 0x6700, "MACHINE")
}

func putNameBlock(mem flatMemory, block uint64, name string) {
	putU16(mem, block+0x18, uint16(len(name)))
	copy(mem[block+0x1a:], []byte(name))
}

func handleSymbols(modern bool, pointer int) *symbols.ISF {
	u8 := symbols.TypeRef{Kind: "base", Name: "unsigned char"}
	u16 := symbols.TypeRef{Kind: "base", Name: "unsigned short"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	u64 := symbols.TypeRef{Kind: "base", Name: "unsigned long long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	unicode := symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}
	bits := func(base string, pos, length uint64) symbols.TypeRef {
		underlying := symbols.TypeRef{Kind: "base", Name: base}
		return symbols.TypeRef{Kind: "bitfield", BitPosition: pos, BitLength: length, BitType: &underlying}
	}
	name := symbols.TypeRef{Kind: "array", Count: 15, Subtype: &u8}
	entry := symbols.Type{Kind: "union", Size: 16}
	header := symbols.Type{Kind: "struct", Size: 0x28, Fields: map[string]symbols.Field{
		"Body": {Offset: 0x20, Type: symbols.TypeRef{Kind: "struct", Name: "_QUAD"}},
	}}
	if modern {
		entry.Fields = map[string]symbols.Field{
			"ObjectPointerBits": {Type: bits("unsigned long long", 20, 44)},
			"InfoTable":         {Type: ptr},
			"GrantedAccessBits": {Offset: 8, Type: bits("unsigned long", 0, 25)},
		}
		if pointer == 4 {
			entry.Size = 8
			entry.Fields = map[string]symbols.Field{
				"InfoTable":         {Type: ptr},
				"GrantedAccessBits": {Offset: 4, Type: bits("unsigned long", 0, 25)},
			}
		}
		typeIndex := uint64(0x18)
		if pointer == 4 {
			typeIndex = 0x10
		}
		header.Fields["TypeIndex"] = symbols.Field{Offset: typeIndex, Type: u8}
		header.Fields["InfoMask"] = symbols.Field{Offset: 0x19, Type: u8}
	} else {
		entry.Fields = map[string]symbols.Field{
			"Object":        {Type: ptr},
			"GrantedAccess": {Offset: 8, Type: u32},
		}
		header.Fields["Type"] = symbols.Field{Type: ptr}
		header.Fields["NameInfoOffset"] = symbols.Field{Offset: 0x19, Type: u8}
	}
	process := symbols.Type{Kind: "struct", Size: 0x40, Fields: map[string]symbols.Field{
		"ActiveProcessLinks": {Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}},
		"UniqueProcessId":    {Offset: 0x10, Type: u64},
		"ImageFileName":      {Offset: 0x20, Type: name},
		"ObjectTable":        {Offset: 0x30, Type: ptr},
	}}
	if pointer == 4 {
		process.Fields["UniqueProcessId"] = symbols.Field{Offset: 0x10, Type: u32}
		process.Fields["ObjectTable"] = symbols.Field{Offset: 0x30, Type: ptr}
	}
	tableCode := u64
	if pointer == 4 {
		tableCode = u32
	}
	symbolsTable := &symbols.ISF{
		Bases: map[string]symbols.Type{
			"pointer":            {Size: uint64(pointer), Endian: "little"},
			"unsigned char":      {Size: 1, Endian: "little"},
			"unsigned short":     {Size: 2, Endian: "little"},
			"unsigned long":      {Size: 4, Endian: "little"},
			"unsigned long long": {Size: 8, Endian: "little"},
			"wchar":              {Size: 2, Endian: "little"},
		},
		Types: map[string]symbols.Type{
			"_LIST_ENTRY":              {Kind: "struct", Size: uint64(pointer * 2), Fields: map[string]symbols.Field{"Flink": {Type: ptr}, "Blink": {Offset: uint64(pointer), Type: ptr}}},
			"_UNICODE_STRING":          {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Length": {Type: u16}, "MaximumLength": {Offset: 2, Type: u16}, "Buffer": {Offset: 8, Type: ptr}}},
			"_QUAD":                    {Kind: "struct", Size: 8},
			"_OBJECT_HEADER":           header,
			"_OBJECT_HEADER_NAME_INFO": {Kind: "struct", Size: 0x20, Fields: map[string]symbols.Field{"Name": {Offset: 8, Type: unicode}}},
			"_OBJECT_TYPE":             {Kind: "struct", Size: 0x20, Fields: map[string]symbols.Field{"Name": {Type: unicode}}},
			"_HANDLE_TABLE":            {Kind: "struct", Size: 0x20, Fields: map[string]symbols.Field{"TableCode": {Offset: uint64(pointer), Type: tableCode}}},
			"_HANDLE_TABLE_ENTRY":      entry,
			"_EPROCESS":                process,
			"_FILE_OBJECT":             {Kind: "struct", Size: 0x40, Fields: map[string]symbols.Field{"DeviceObject": {Offset: 8, Type: ptr}, "FileName": {Offset: 0x10, Type: unicode}}},
			"_ETHREAD":                 {Kind: "struct", Size: 0x60, Fields: map[string]symbols.Field{"Cid": {Offset: 0x40, Type: symbols.TypeRef{Kind: "struct", Name: "_CLIENT_ID"}}}},
			"_CLIENT_ID":               {Kind: "struct", Size: 0x10, Fields: map[string]symbols.Field{"UniqueProcess": {Type: u64}, "UniqueThread": {Offset: 8, Type: u64}}},
			"_CM_KEY_BODY":             {Kind: "struct", Size: 0x20, Fields: map[string]symbols.Field{"KeyControlBlock": {Offset: 8, Type: ptr}, "Trans": {Offset: 0x10, Type: ptr}}},
			"_CM_KEY_CONTROL_BLOCK":    {Kind: "struct", Size: 0x30, Fields: map[string]symbols.Field{"ParentKcb": {Offset: 0x10, Type: ptr}, "Flags": {Offset: 0x18, Type: u32}, "NameBlock": {Offset: 0x20, Type: ptr}}},
			"_CM_NAME_CONTROL_BLOCK":   {Kind: "struct", Size: 0x20, Fields: map[string]symbols.Field{"NameLength": {Offset: 0x18, Type: u16}, "Name": {Offset: 0x1a, Type: symbols.TypeRef{Kind: "array", Count: 1, Subtype: &symbols.TypeRef{Kind: "base", Name: "wchar"}}}}},
		},
		Symbols: map[string]symbols.Symbol{
			"PsActiveProcessHead": {Address: 0x80},
			"ObTypeIndexTable":    {Address: 0x500},
			"ObHeaderCookie":      {Address: 0x200},
			"ObpInfoMaskToOffset": {Address: 0x210},
		},
	}
	if !modern {
		delete(symbolsTable.Symbols, "ObHeaderCookie")
		delete(symbolsTable.Symbols, "ObpInfoMaskToOffset")
		body := symbolsTable.Types["_CM_KEY_BODY"]
		delete(body.Fields, "Trans")
		symbolsTable.Types["_CM_KEY_BODY"] = body
		header := symbolsTable.Types["_OBJECT_HEADER"]
		header.Fields["NameInfoOffset"] = symbols.Field{Offset: 0x19, Type: u8}
		symbolsTable.Types["_OBJECT_HEADER"] = header
	}
	if pointer == 4 {
		delete(symbolsTable.Symbols, "ObHeaderCookie")
	}
	return symbolsTable
}
