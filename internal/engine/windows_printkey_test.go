package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsPrintKeySynthetic(t *testing.T) {
	f := printKeyFixture(t, true)
	rows, state, err := printKeyRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 2 {
		t.Fatal(state, len(rows), err, printSummary(rows))
	}
	key, value := rows[0].Cells, rows[1].Cells
	if key["RecordType"].String() != "key" || key["Type"].String() != "Key" || key["Name"].String() != "Run" || key["Key"].String() != `\REGISTRY\MACHINE\SYSTEM` || key["Data"].String() != "" || key["Volatile"].Data != false || key["RootFrom"].String() != "base_block" {
		t.Fatal(key)
	}
	if value["RecordType"].String() != "value" || value["Type"].String() != "REG_DWORD" || value["Name"].String() != "Version" || value["Data"].String() != "2" || value["Volatile"].Data != false || value["Key"].String() != key["Key"].String() {
		t.Fatal(value)
	}
	if key["LastWriteTime"].Kind != "string" || value["RegistryProcess"].Kind != "address" {
		t.Fatal(key["LastWriteTime"], value["RegistryProcess"])
	}
	recur, state, err := printKeyRows(t, f, map[string]string{"recurse": "true"})
	if err != nil || state != "completed" || len(recur) != 3 || recur[0].Cells["Name"].String() != "Run" || recur[1].Cells["Name"].String() != "Once" || recur[1].Cells["Key"].String() != `\REGISTRY\MACHINE\SYSTEM\Run` || recur[2].Cells["Name"].String() != "Version" {
		t.Fatal(state, printSummary(recur), err)
	}
	filtered, state, err := printKeyRows(t, f, map[string]string{"key": `run`})
	if err != nil || state != "completed" || len(filtered) != 1 || filtered[0].Cells["Name"].String() != "Once" {
		t.Fatal(state, printSummary(filtered), err)
	}
	offset, state, err := printKeyRows(t, f, map[string]string{"offset": "0x30000"})
	if err != nil || state != "completed" || len(offset) != 2 {
		t.Fatal(state, len(offset), err)
	}
	none, state, err := printKeyRows(t, f, map[string]string{"offset": "0x1111"})
	if err != nil || state != "completed" || len(none) != 0 {
		t.Fatal(state, len(none), err)
	}
	missing, state, err := printKeyRows(t, f, map[string]string{"key": `Missing\`})
	if err != nil || state != "completed" || len(missing) != 1 || missing[0].Cells["Key"].String() != `\REGISTRY\MACHINE\SYSTEM\Missing\` || missing[0].Cells["Name"].Kind != "missing" || missing[0].Cells["Name"].Error != "" || missing[0].Cells["Error"].Reason != "hive_unreadable" {
		t.Fatal(state, printSummary(missing), err)
	}
	if _, err := openWindowsImage(t, f).Run(context.Background(), "windows.printkey", map[string]string{"max-nodes": "1"}, engine.RunOptions{}); err == nil {
		t.Fatal("max-nodes accepted a second row")
	}
}

func TestWindowsPrintKeyUserBinNeedsRegistryProcess(t *testing.T) {
	f := printKeyFixture(t, false)
	rows, state, err := printKeyRows(t, f, nil)
	if err != nil || state != "completed" || len(rows) != 1 {
		t.Fatal(state, len(rows), err, printSummary(rows))
	}
	row := rows[0].Cells
	if row["RecordType"].String() != "key" || row["Type"].String() != "Key" || !strings.HasSuffix(row["Key"].String(), `\`) || row["Name"].Kind != "missing" || row["Name"].Reason != "unreadable" || row["Volatile"].Kind != "missing" || row["RegistryProcess"].Reason != "registry_process_absent" || !strings.Contains(row["Error"].Error, "registry process layer is required") {
		t.Fatal(row)
	}
}

func printKeyFixture(t *testing.T, withRegistry bool) testfixture.Fixture {
	t.Helper()
	f := hiveFixture(t)
	raw, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table symbols.ISF
	if err = json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	dual := symbols.TypeRef{Kind: "struct", Name: "_DUAL"}
	field := func(off uint64, ref symbols.TypeRef) symbols.Field { return symbols.Field{Offset: off, Type: ref} }
	strct := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	table.Types["_DUAL"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Length": field(0, u32), "Map": field(8, ptr)}}
	table.Types["_HMAP_ENTRY"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"BlockOffset": field(0, u64), "PermanentBinAddress": field(8, u64)}}
	table.Types["_HHIVE"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{
		"Signature": field(0, u32), "BaseBlock": field(8, ptr), "Version": field(16, u32),
		"Storage": field(24, symbols.TypeRef{Kind: "array", Count: 2, Subtype: &dual}),
	}}
	table.Types["_CMHIVE"] = symbols.Type{Kind: "struct", Size: 160, Fields: map[string]symbols.Field{
		"Hive": field(0, strct("_HHIVE")), "HiveList": field(64, strct("_LIST_ENTRY")),
		"FileFullPath": field(80, strct("_UNICODE_STRING")), "FileUserName": field(96, strct("_UNICODE_STRING")), "HiveRootPath": field(112, strct("_UNICODE_STRING")),
	}}
	encoded, err := json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 0x50000 {
		data = append(data, make([]byte, 0x50000-len(data))...)
	}
	const hive = 0x30000
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put32 := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(data[a:], v) }
	put32(hive, 0xBEE0BEE0)
	put(hive+8, 0x31000)
	put32(hive+16, 1)
	put32(hive+24, 0x1000)
	put(hive+32, 0x32000)
	put(hive+48, 0x32000)
	copy(data[0x31000:], []byte("regf"))
	put32(0x31000+36, 0x40)
	put(0x32000, 0x33000)
	put(0x33008, 0x36000)
	putUnicode(data, hive+80, 0x34000, "")
	putUnicode(data, hive+96, 0x34100, `\REGISTRY\MACHINE\SYSTEM`)
	putUnicode(data, hive+112, 0x34200, "")
	putCell(data, 0x36000, 0x40, nkCell("ROOT", 0x24, 133000000000000000, 1, 0x100, 0, 0, 1, 0x500))
	putCell(data, 0x36000, 0x100, lfCell(0x200))
	putCell(data, 0x36000, 0x200, nkCell("Run", 0x20, 133000000100000000, 1, 0x300, 0, 0, 0, 0))
	putCell(data, 0x36000, 0x300, lfCell(0x400))
	putCell(data, 0x36000, 0x400, nkCell("Once", 0x20, 133000000200000000, 0, 0, 0, 0, 0, 0))
	putCell(data, 0x36000, 0x500, u32Cell(0x580))
	putCell(data, 0x36000, 0x580, vkCell("Version", 4, []byte{2, 0, 0, 0}))
	linkHives(data, hiveHead, hive+64)
	if withRegistry {
		put(0x9000, 0x19000)
		put(0x19000, 0x6000)
		put(0x19008, 0x9000)
		put(0x6008, 0x19000)
		put(0x19000+16, 88)
		put(0x19000+24, 4)
		copy(data[0x19000+32:], "Registry")
		put(0x19000+48, 133000000000000000)
		put(0x19000+56, 0x1000)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func printKeyRows(t *testing.T, f testfixture.Fixture, params map[string]string) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.printkey", params, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}

func printSummary(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Cells["RecordType"].String()+" "+row.Cells["Type"].String()+" "+row.Cells["Key"].String()+" "+row.Cells["Name"].String()+" "+row.Cells["Error"].String())
	}
	return out
}

func putCell(data []byte, bin uint64, index int, payload []byte) {
	total := len(payload) + 4
	if total%8 != 0 {
		total += 8 - total%8
	}
	addr := bin + uint64(index)
	binary.LittleEndian.PutUint32(data[addr:], uint32(-int32(total)))
	copy(data[addr+4:], payload)
}

func nkCell(name string, flags uint16, stamp uint64, stable, stableList, volatile, volatileList, values, valueList uint32) []byte {
	buf := make([]byte, 76+len(name))
	copy(buf, "nk")
	binary.LittleEndian.PutUint16(buf[2:], flags|0x20)
	binary.LittleEndian.PutUint64(buf[4:], stamp)
	binary.LittleEndian.PutUint32(buf[20:], stable)
	binary.LittleEndian.PutUint32(buf[24:], volatile)
	binary.LittleEndian.PutUint32(buf[28:], stableList)
	binary.LittleEndian.PutUint32(buf[32:], volatileList)
	binary.LittleEndian.PutUint32(buf[36:], values)
	binary.LittleEndian.PutUint32(buf[40:], valueList)
	binary.LittleEndian.PutUint16(buf[72:], uint16(len(name)))
	copy(buf[76:], name)
	return buf
}

func lfCell(child uint32) []byte {
	buf := make([]byte, 12)
	copy(buf, "lf")
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[4:], child)
	return buf
}

func u32Cell(v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return buf
}

func vkCell(name string, typ uint32, inline []byte) []byte {
	buf := make([]byte, 20+len(name))
	copy(buf, "vk")
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(name)))
	binary.LittleEndian.PutUint32(buf[4:], 0x80000000|uint32(len(inline)))
	copy(buf[8:], inline)
	binary.LittleEndian.PutUint32(buf[12:], typ)
	binary.LittleEndian.PutUint16(buf[16:], 1)
	copy(buf[20:], name)
	return buf
}
