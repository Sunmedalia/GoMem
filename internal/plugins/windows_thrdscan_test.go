package plugins

import (
	"context"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func threadScanSymbols(win10 bool) *symbols.ISF {
	u8 := symbols.TypeRef{Kind: "base", Name: "unsigned char"}
	u16 := symbols.TypeRef{Kind: "base", Name: "unsigned short"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	u64 := symbols.TypeRef{Kind: "base", Name: "unsigned long long"}
	i64 := symbols.TypeRef{Kind: "base", Name: "long long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	unicode := symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}
	bits := func(base string, pos, length uint64) symbols.TypeRef {
		underlying := symbols.TypeRef{Kind: "base", Name: base}
		return symbols.TypeRef{Kind: "bitfield", BitPosition: pos, BitLength: length, BitType: &underlying}
	}
	handle := map[string]symbols.Field{}
	if !win10 {
		handle["HandleCount"] = symbols.Field{Type: u32}
	}
	table := &symbols.ISF{
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
				"PointerCount": {Type: i64},
				"TypeIndex":    {Offset: 24, Type: u8},
				"InfoMask":     {Offset: 26, Type: u8},
				"Body":         {Offset: 48, Type: symbols.TypeRef{Kind: "struct", Name: "_QUAD"}},
			}},
			"_QUAD":           {Kind: "struct", Size: 8},
			"_UNICODE_STRING": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Length": {Type: u16}, "MaximumLength": {Offset: 2, Type: u16}, "Buffer": {Offset: 8, Type: ptr}}},
			"_LARGE_INTEGER":  {Kind: "union", Size: 8, Fields: map[string]symbols.Field{"QuadPart": {Type: i64}}},
			"_KTHREAD":        {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Process": {Type: ptr}}},
			"_CLIENT_ID": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
				"UniqueProcess": {Type: u64},
				"UniqueThread":  {Offset: 8, Type: u64},
			}},
			"_ETHREAD": {Kind: "struct", Size: 80, Fields: map[string]symbols.Field{
				"Tcb":               {Type: symbols.TypeRef{Kind: "struct", Name: "_KTHREAD"}},
				"Cid":               {Offset: 8, Type: symbols.TypeRef{Kind: "struct", Name: "_CLIENT_ID"}},
				"CreateTime":        {Offset: 24, Type: symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}},
				"ExitTime":          {Offset: 32, Type: symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}},
				"StartAddress":      {Offset: 40, Type: ptr},
				"Win32StartAddress": {Offset: 48, Type: ptr},
			}},
			"_OBJECT_TYPE":                 {Kind: "struct", Size: 48, Fields: map[string]symbols.Field{"Name": {Offset: 16, Type: unicode}}},
			"_HANDLE_TABLE":                {Kind: "struct", Size: 16, Fields: handle},
			"_OBJECT_HEADER_CREATOR_INFO":  {Kind: "struct", Size: 32},
			"_OBJECT_HEADER_NAME_INFO":     {Kind: "struct", Size: 32},
			"_OBJECT_HEADER_HANDLE_INFO":   {Kind: "struct", Size: 16},
			"_OBJECT_HEADER_QUOTA_INFO":    {Kind: "struct", Size: 32},
			"_OBJECT_HEADER_PROCESS_INFO":  {Kind: "struct", Size: 16},
			"_OBJECT_HEADER_AUDIT_INFO":    {Kind: "struct", Size: 16},
			"_OBJECT_HEADER_EXTENDED_INFO": {Kind: "struct", Size: 16},
			"_OBJECT_HEADER_PADDING_INFO":  {Kind: "struct", Size: 4},
		},
		Symbols: map[string]symbols.Symbol{
			"KdCopyDataBlock":  {Address: 1},
			"ObTypeIndexTable": {Address: 0x180},
		},
	}
	if win10 {
		table.Symbols["ObHeaderCookie"] = symbols.Symbol{Address: 0x100}
	}
	return table
}

func putThread(buf flatMemory, object, pid, tid, created uint64) {
	putU64(buf, object+8, pid)
	putU64(buf, object+16, tid)
	putU64(buf, object+24, created)
	putU64(buf, object+40, 0x1000)
	putU64(buf, object+48, 0x2000)
}

func TestWindowsThrdScanBottomUpKeepsAlignedThreads(t *testing.T) {
	buf := make(flatMemory, 0xc00)
	created := uint64(132223104000000000)
	putPool := func(header uint64) {
		buf[header+2] = 40
		buf[header+3] = 2
		copy(buf[header+4:], []byte{'T', 'h', 'r', 0xe5})
	}
	objectAt := func(header uint64) uint64 { return header + 40*16 - 80 }
	putPool(0x100)
	putThread(buf, objectAt(0x100), 128, 256, created)
	putPool(0x400)
	putThread(buf, objectAt(0x400), 4, 12, 0)
	putPool(0x700)
	putThread(buf, objectAt(0x700), 0, 16, created)
	table := threadScanSymbols(false)
	env := plugin.Environment{Physical: buf, Kernel: buf, Symbols: table, Objects: &object.Reader{Layer: buf, Symbols: table}, OS: "windows"}
	var threads []evidence.Row
	var summary evidence.Row
	if err := windowsThrdScan(context.Background(), env, nil, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "thread":
			threads = append(threads, row)
		case "summary":
			summary = row
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(threads) != 2 {
		t.Fatalf("threads %d", len(threads))
	}
	if threads[0].Cells["PID"].String() != "128" || threads[0].Cells["TID"].String() != "256" || threads[0].Cells["Offset"].String() != "0x0000000000000330" || threads[0].Cells["CreateTime"].String() != "2020-01-01T00:00:00Z" || threads[0].Cells["StartPath"].String() != "<owner_not_valid>" {
		t.Fatalf("%+v", threads[0].Cells)
	}
	if threads[1].Cells["PID"].String() != "4" || threads[1].Cells["CreateTime"].String() != "<not_set>" || threads[1].Cells["ExitTime"].String() != "<not_set>" {
		t.Fatalf("%+v", threads[1].Cells)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["threads"] != "2" || coverage["top_down"] != "false" || coverage["windows10"] != "false" {
		t.Fatal(coverage)
	}
}

func TestWindowsThrdScanTopDownRequiresThreadType(t *testing.T) {
	buf := make(flatMemory, 0x1000)
	created := uint64(132223104000000000)
	putHeader := func(header uint64, typeIndex byte) uint64 {
		buf[header+2] = 40
		buf[header+3] = 2
		copy(buf[header+4:], []byte("Thre"))
		start := header + 16
		putU64(buf, start, 1)
		buf[start+24] = typeIndex
		return start + 48
	}
	putThread(buf, putHeader(0x200, 3), 128, 256, created)
	putThread(buf, putHeader(0x900, 0), 132, 260, created)
	putU64(buf, 0x188, 0x700)
	putUnicode(buf, 0x710, 0x780, "Thread")
	table := threadScanSymbols(true)
	env := plugin.Environment{Physical: buf, Kernel: buf, Symbols: table, Objects: &object.Reader{Layer: buf, Symbols: table}, OS: "windows"}
	var threads []evidence.Row
	var summary evidence.Row
	if err := windowsThrdScan(context.Background(), env, nil, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "thread":
			threads = append(threads, row)
		case "summary":
			summary = row
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 || threads[0].Cells["Offset"].String() != "0x0000000000000240" || threads[0].Cells["TID"].String() != "256" {
		t.Fatalf("%+v", threads)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["threads"] != "1" || coverage["skipped_type"] != "1" || coverage["top_down"] != "true" || coverage["windows10"] != "true" {
		t.Fatal(coverage)
	}
}

func TestVolatilityFiletimeUsesPinnedFloorDivision(t *testing.T) {
	when, ok := volatilityFiletime(-1)
	if !ok || when.Format(time.RFC3339) != "1600-12-31T23:59:59Z" {
		t.Fatal(when, ok)
	}
	if _, ok := volatilityFiletime(0); ok {
		t.Fatal("zero ticks are not a datetime")
	}
	when, ok = volatilityFiletime(132223104000000000)
	if !ok || when.Format(time.RFC3339) != "2020-01-01T00:00:00Z" || !processYear(when) {
		t.Fatal(when, ok)
	}
	shifted := int64(132223104000000000) >> 3
	when, ok = volatilityFiletime(shifted)
	if !ok || when.Format(time.RFC3339) != "1653-05-17T12:00:00Z" {
		t.Fatal(when, ok)
	}
}
