package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func processScanSymbols() *symbols.ISF {
	u8 := symbols.TypeRef{Kind: "base", Name: "unsigned char"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	u64 := symbols.TypeRef{Kind: "base", Name: "unsigned long long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	bits := func(base string, pos, length uint64) symbols.TypeRef {
		underlying := symbols.TypeRef{Kind: "base", Name: base}
		return symbols.TypeRef{Kind: "bitfield", BitPosition: pos, BitLength: length, BitType: &underlying}
	}
	name := symbols.TypeRef{Kind: "array", Count: 15, Subtype: &u8}
	return &symbols.ISF{
		Bases: map[string]symbols.Type{
			"pointer":            {Size: 8, Endian: "little"},
			"unsigned char":      {Size: 1, Endian: "little"},
			"unsigned short":     {Size: 2, Endian: "little"},
			"unsigned long":      {Size: 4, Endian: "little"},
			"unsigned long long": {Size: 8, Endian: "little"},
			"long long":          {Size: 8, Endian: "little", Signed: true},
		},
		Types: map[string]symbols.Type{
			"_POOL_HEADER": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
				"BlockSize": {Offset: 2, Type: bits("unsigned short", 0, 8)},
				"PoolType":  {Offset: 2, Type: bits("unsigned short", 8, 8)},
				"PoolTag":   {Offset: 4, Type: u32},
			}},
			"_OBJECT_HEADER": {Kind: "struct", Size: 56, Fields: map[string]symbols.Field{
				"Body": {Offset: 48, Type: symbols.TypeRef{Kind: "struct", Name: "_QUAD"}},
			}},
			"_QUAD":          {Kind: "struct", Size: 8},
			"_LARGE_INTEGER": {Kind: "union", Size: 8, Fields: map[string]symbols.Field{"QuadPart": {Type: u64}}},
			"_LIST_ENTRY":    {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Flink": {Type: ptr}, "Blink": {Offset: 8, Type: ptr}}},
			"_KPROCESS":      {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"DirectoryTableBase": {Type: u64}}},
			"_HANDLE_TABLE":  {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"HandleCount": {Type: u32}}},
			"_EPROCESS": {Kind: "struct", Size: 64, Fields: map[string]symbols.Field{
				"ImageFileName":                {Type: name},
				"UniqueProcessId":              {Offset: 16, Type: u64},
				"InheritedFromUniqueProcessId": {Offset: 16, Type: u64},
				"ActiveThreads":                {Offset: 16, Type: u32},
				"CreateTime":                   {Offset: 24, Type: symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}},
				"ExitTime":                     {Offset: 32, Type: symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}},
				"Pcb":                          {Offset: 40, Type: symbols.TypeRef{Kind: "struct", Name: "_KPROCESS"}},
				"ThreadListHead":               {Offset: 48, Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}},
			}},
		},
		Symbols: map[string]symbols.Symbol{
			"KdCopyDataBlock":  {Address: 1},
			"ObTypeIndexTable": {Address: 0x20},
		},
	}
}

func putProcess(buf flatMemory, object, pid uint64, name string) {
	copy(buf[object:], name)
	putU64(buf, object+16, pid)
	putU64(buf, object+24, (1577836800+11644473600)*10000000)
	putU64(buf, object+40, 0x1ad000)
	putU64(buf, object+48, 0xffff800000001000)
	putU64(buf, object+56, 0xffff800000002000)
}

func TestWindowsPsScanBottomUpKeepsAlignedProcess(t *testing.T) {
	buf := make(flatMemory, 0x900)
	buf[0x102] = 40
	buf[0x103] = 2
	copy(buf[0x104:], []byte("Proc"))
	putProcess(buf, 0x340, 128, "test.exe")
	buf[0x402] = 40
	buf[0x403] = 2
	copy(buf[0x404:], []byte("Proc"))
	putProcess(buf, 0x640, 6, "bad.exe")
	table := processScanSymbols()
	env := plugin.Environment{Physical: buf, Kernel: buf, Symbols: table, Objects: &object.Reader{Layer: buf, Symbols: table}, OS: "windows"}
	var rows []evidence.Row
	if err := windowsPsScan(context.Background(), env, map[string]string{"pid": "128"}, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var processes []evidence.Row
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "process":
			processes = append(processes, row)
		case "summary":
			if row.Cells["Coverage"].Data.(map[string]any)["processes"] != "1" {
				t.Fatal(row.Cells["Coverage"].Data)
			}
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
	}
	if len(processes) != 1 || processes[0].Cells["Name"].String() != "test.exe" || processes[0].Cells["PID"].String() != "128" || processes[0].Cells["Offset"].String() != "0x0000000000000340" || processes[0].Cells["FileOutput"].String() != "Disabled" {
		t.Fatalf("%+v", processes)
	}
}
