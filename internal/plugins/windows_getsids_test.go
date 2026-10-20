package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsSIDNamesQuirksAndTokenRows(t *testing.T) {
	raw := append([]byte("C:\\Users\\alice\x00"), 0)
	encoded := make([]byte, 0, len(raw)*2)
	for _, b := range raw {
		encoded = append(encoded, b, 0)
	}
	if profileBasename(encoded) != "alice" {
		t.Fatal(profileBasename(encoded))
	}
	if pythonBytesRepr([]byte{0, 9, 10, 13, 39, 34, 127}) != `b'\x00\t\n\r\'"\x7f'` {
		t.Fatal(pythonBytesRepr([]byte{0, 9, 10, 13, 39, 34, 127}))
	}
	if pythonBytesRepr([]byte("a'b")) != `b"a'b"` {
		t.Fatal(pythonBytesRepr([]byte("a'b")))
	}
	name, ok := sidDisplayName("S-1-5-18", nil)
	if !ok || name != "Local System" {
		t.Fatal(name, ok)
	}
	name, ok = sidDisplayName("S-1-5-21-9-8-500", nil)
	if !ok || name != "Administrator" {
		t.Fatal(name, ok)
	}
	name, ok = sidDisplayName("S-1-5-21-9-8-553", nil)
	if !ok || name != "RAS Servers" {
		t.Fatal(name, ok)
	}
	if _, ok = sidDisplayName("S-1-5-99", nil); ok {
		t.Fatal("unknown sid was named")
	}
	name, ok = sidDisplayName("S-1-5-21-1-1001", map[string]string{"S-1-5-21-1-1001": "alice"})
	if !ok || name != "alice" {
		t.Fatal(name, ok)
	}

	mem := make(flatMemory, 0x520)
	putU64(mem, 0, 0x100)
	putU64(mem, 8, 0x100)
	putU64(mem, 0x20, 0x20)
	putU64(mem, 0x28, 0x20)
	putU64(mem, 0x100, 0)
	putU64(mem, 0x108, 0)
	putU64(mem, 0x110, 4)
	copy(mem[0x118:], []byte("System"))
	putU64(mem, 0x128, 0x300)
	putU64(mem, 0x300, 2)
	putU64(mem, 0x308, 0x400)
	putU64(mem, 0x400, 0x480)
	putU64(mem, 0x410, 0x4c0)
	mem[0x480] = 1
	mem[0x481] = 0
	mem[0x486] = 0x10
	mem[0x487] = 5
	mem[0x4c0] = 0
	mem[0x4c1] = 1

	rows, err := runSIDs(t, mem, sidSymbols(), map[string]string{"max-nodes": "16"})
	if err != nil {
		t.Fatal(err)
	}
	sids := filterSID(rows, "sid")
	if len(sids) != 1 || sids[0].Cells["SID"].String() != "S-1-5" || sids[0].Cells["Name"].String() != "NT Authority" || sids[0].Cells["Process"].String() != "System" {
		t.Fatal(len(sids), sids[0].Cells)
	}

	mem[0x480] = 1
	mem[0x481] = 1
	mem[0x486] = 0
	mem[0x487] = 5
	putU64(mem, 0x488, 18)
	putU64(mem, 0x300, 1)
	rows, err = runSIDs(t, mem, sidSymbols(), map[string]string{"max-nodes": "16"})
	if err != nil {
		t.Fatal(err)
	}
	sids = filterSID(rows, "sid")
	if len(sids) != 1 || sids[0].Cells["SID"].String() != "S-1-5-18" || sids[0].Cells["Name"].String() != "Local System" {
		t.Fatal(sids[0].Cells)
	}

	mem[0x128] = 0
	// Force the token field read to fail by moving the object past a hole.
	rows, err = runSIDs(t, failRange{flatMemory: mem, at: 0x128}, sidSymbols(), map[string]string{"max-nodes": "16"})
	if err != nil {
		t.Fatal(err)
	}
	sids = filterSID(rows, "sid")
	if len(sids) != 1 || sids[0].Cells["SID"].String() != "Token unreadable" || sids[0].Cells["Name"].String() != "" {
		t.Fatal(sids[0].Cells)
	}
}

func sidSymbols() *symbols.ISF {
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	bytes := symbols.TypeRef{Kind: "array", Count: 16, Subtype: &symbols.TypeRef{Kind: "base", Name: "unsigned char"}}
	return &symbols.ISF{
		Bases: map[string]symbols.Type{
			"pointer":       {Size: 8, Endian: "little"},
			"unsigned char": {Size: 1, Endian: "little"},
			"unsigned long": {Size: 4, Endian: "little"},
		},
		Types: map[string]symbols.Type{
			"_LIST_ENTRY":         {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Flink": {Type: ptr}, "Blink": {Offset: 8, Type: ptr}}},
			"_EX_FAST_REF":        {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Object": {Type: ptr}}},
			"_CMHIVE":             {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"HiveList": {Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}}}},
			"_SID_AND_ATTRIBUTES": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Sid": {Type: ptr}, "Attributes": {Offset: 8, Type: u32}}},
			"_EPROCESS": {Kind: "struct", Size: 0x40, Fields: map[string]symbols.Field{
				"ActiveProcessLinks": {Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}},
				"UniqueProcessId":    {Offset: 0x10, Type: ptr},
				"ImageFileName":      {Offset: 0x18, Type: bytes},
				"Token":              {Offset: 0x28, Type: symbols.TypeRef{Kind: "struct", Name: "_EX_FAST_REF"}},
			}},
			"_TOKEN": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
				"UserAndGroupCount": {Type: u32},
				"UserAndGroups":     {Offset: 8, Type: ptr},
			}},
		},
		Symbols: map[string]symbols.Symbol{
			"PsActiveProcessHead": {Address: 0},
			"CmpHiveListHead":     {Address: 0x20},
		},
	}
}

func runSIDs(t *testing.T, layer memory.MemoryLayer, table *symbols.ISF, params map[string]string) ([]evidence.Row, error) {
	t.Helper()
	env := plugin.Environment{Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows", ImageHash: "img"}
	var rows []evidence.Row
	err := windowsGetSIDs(context.Background(), env, params, func(row evidence.Row) error {
		row.Seal()
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	})
	return rows, err
}

func filterSID(rows []evidence.Row, kind string) []evidence.Row {
	var out []evidence.Row
	for _, row := range rows {
		if row.Cells["RecordType"].String() == kind {
			out = append(out, row)
		}
	}
	return out
}
