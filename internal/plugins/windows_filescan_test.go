package plugins

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type flatMemory []byte

func (m flatMemory) Name() string { return "flat" }
func (m flatMemory) ReadAt(ctx context.Context, p []byte, addr uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if addr > uint64(len(m)) {
		return 0, io.EOF
	}
	n := copy(p, m[addr:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func (m flatMemory) Ranges() []memory.Range {
	return []memory.Range{{Length: uint64(len(m))}}
}

func fileUTF16Bytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[i*2:], unit)
	}
	return out
}

func putU16(b []byte, addr uint64, value uint16) {
	binary.LittleEndian.PutUint16(b[addr:], value)
}
func putU64(b []byte, addr, value uint64) {
	binary.LittleEndian.PutUint64(b[addr:], value)
}

func fileSymbols(win10 bool) *symbols.ISF {
	u8 := symbols.TypeRef{Kind: "base", Name: "unsigned char"}
	u16 := symbols.TypeRef{Kind: "base", Name: "unsigned short"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
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
			"pointer":        {Size: 8, Endian: "little"},
			"unsigned char":  {Size: 1, Endian: "little"},
			"unsigned short": {Size: 2, Endian: "little"},
			"unsigned long":  {Size: 4, Endian: "little"},
			"long long":      {Size: 8, Endian: "little", Signed: true},
		},
		Types: map[string]symbols.Type{
			"_POOL_HEADER": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
				"PreviousSize": {Offset: 0, Type: bits("unsigned short", 0, 8)},
				"PoolIndex":    {Offset: 0, Type: bits("unsigned short", 8, 8)},
				"BlockSize":    {Offset: 2, Type: bits("unsigned short", 0, 8)},
				"PoolType":     {Offset: 2, Type: bits("unsigned short", 8, 8)},
				"PoolTag":      {Offset: 4, Type: u32},
			}},
			"_OBJECT_HEADER": {Kind: "struct", Size: 56, Fields: map[string]symbols.Field{
				"PointerCount": {Type: i64},
				"TypeIndex":    {Offset: 24, Type: u8},
				"InfoMask":     {Offset: 26, Type: u8},
				"Body":         {Offset: 48, Type: symbols.TypeRef{Kind: "struct", Name: "_QUAD"}},
			}},
			"_QUAD":                        {Kind: "struct", Size: 8},
			"_UNICODE_STRING":              {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Length": {Type: u16}, "MaximumLength": {Offset: 2, Type: u16}, "Buffer": {Offset: 8, Type: ptr}}},
			"_FILE_OBJECT":                 {Kind: "struct", Size: 216, Fields: map[string]symbols.Field{"FileName": {Offset: 88, Type: unicode}}},
			"_OBJECT_TYPE":                 {Kind: "struct", Size: 216, Fields: map[string]symbols.Field{"Name": {Offset: 16, Type: unicode}}},
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
			"KdCopyDataBlock":  {Address: 0x10},
			"ObTypeIndexTable": {Address: 0x180},
		},
	}
	if win10 {
		table.Symbols["ObHeaderCookie"] = symbols.Symbol{Address: 0x100}
	}
	return table
}

func putUnicode(b []byte, addr, buffer uint64, text string) {
	raw := fileUTF16Bytes(text)
	putU16(b, addr, uint16(len(raw)))
	putU16(b, addr+2, uint16(len(raw)))
	putU64(b, addr+8, buffer)
	copy(b[buffer:], raw)
}

func TestWindowsFileScanTopDownTypeAndName(t *testing.T) {
	buf := make(flatMemory, 0x800)
	buf[0x042] = 16
	buf[0x043] = 1
	copy(buf[0x044:], []byte("File"))
	buf[0x082] = 1
	buf[0x083] = 2
	copy(buf[0x084:], []byte("File"))
	buf[0x202] = 16
	buf[0x203] = 2
	copy(buf[0x204:], []byte("File"))
	putU64(buf, 0x210, 1)
	buf[0x228] = 3
	copy(buf[0x400:], []byte{0x5c, 0x00, 0x41, 0x00, 0x00, 0x00, 0x42, 0x00})
	putU16(buf, 0x298, 8)
	putU16(buf, 0x29a, 8)
	putU64(buf, 0x2a0, 0x400)
	buf[0x482] = 16
	buf[0x483] = 2
	copy(buf[0x484:], []byte("File"))
	putU64(buf, 0x490, 1)
	buf[0x4a8] = 5
	putU16(buf, 0x518, 4)
	putU64(buf, 0x520, 0x7ff)
	putU64(buf, 0x188, 0x600)
	putUnicode(buf, 0x610, 0x700, "File")

	table := fileSymbols(true)
	layer := buf
	env := plugin.Environment{Physical: layer, Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows"}
	var rows []evidence.Row
	if err := windowsFileScan(context.Background(), env, nil, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var files []evidence.Row
	var summary evidence.Row
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "file":
			files = append(files, row)
		case "summary":
			summary = row
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
	}
	if len(files) != 1 || files[0].Cells["Name"].String() != `\A` || files[0].Cells["Offset"].String() != "0x0000000000000240" {
		t.Fatalf("files %+v", files)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["files"] != "1" || coverage["skipped_name"] != "1" || coverage["windows10"] != "true" || coverage["top_down"] != "true" || coverage["read_failures"] != "0" {
		t.Fatal(coverage)
	}
}

func TestWindowsFileScanBottomUpWithoutCookie(t *testing.T) {
	buf := make(flatMemory, 0x800)
	buf[0x202] = 16
	buf[0x203] = 2
	copy(buf[0x204:], []byte("File"))
	buf[0x208] = 1
	copy(buf[0x300:], fileUTF16Bytes(`\device`))
	putU16(buf, 0x278, uint16(len(fileUTF16Bytes(`\device`))))
	putU64(buf, 0x280, 0x300)
	putU64(buf, 0x188, 0x600)
	putUnicode(buf, 0x610, 0x700, "File")
	table := fileSymbols(false)
	layer := buf
	env := plugin.Environment{Physical: layer, Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows"}
	var names []string
	if err := windowsFileScan(context.Background(), env, nil, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "file" {
			names = append(names, row.Cells["Offset"].String()+" "+row.Cells["Name"].String())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != `0x0000000000000220 \device` {
		t.Fatal(names)
	}
}

func TestPoolPageTypeFollowsVistaBoundary(t *testing.T) {
	if !poolPageOK(2, poolNonPaged|poolFree, true) || poolPageOK(2, poolNonPaged|poolFree, false) {
		t.Fatal("even pool type")
	}
	if !poolPageOK(1, poolNonPaged|poolFree, false) || poolPageOK(1, poolNonPaged|poolFree, true) {
		t.Fatal("odd pool type")
	}
	if !poolPageOK(0, poolNonPaged|poolFree, true) || !poolPageOK(0, poolPaged|poolFree, false) {
		t.Fatal("free pool")
	}
	if poolUTF16([]byte{0x41, 0x00, 0x00}) != "A\uFFFD" || poolUTF16([]byte{0x00, 0xd8}) != "\uFFFD" || poolUTF16([]byte{0x5c, 0x00, 0x41, 0x00, 0x00, 0x00, 0x42, 0x00}) != `\A` {
		t.Fatal(poolUTF16([]byte{0x41, 0x00, 0x00}), poolUTF16([]byte{0x00, 0xd8}))
	}
}
