package plugins

import (
	"context"
	"io"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsPrivilegesBitsFastRefAndLegacyArray(t *testing.T) {
	if maskFastRef(0x1f, 8) != 0x10 || maskFastRef(0x17, 4) != 0x10 {
		t.Fatal(maskFastRef(0x1f, 8), maskFastRef(0x17, 4))
	}
	if privilegeAttributes(true, true, false) != "Present,Enabled" || privilegeAttributes(false, false, false) != "" {
		t.Fatal(privilegeAttributes(true, true, false))
	}

	mem := make(flatMemory, 0x500)
	putU64(mem, 0, 0x100)
	putU64(mem, 8, 0x180)
	putU64(mem, 0x100, 0x180)
	putU64(mem, 0x108, 0)
	putU64(mem, 0x110, 4)
	copy(mem[0x118:], []byte("cmd.exe"))
	putU64(mem, 0x128, 0x300|0xf)
	putU64(mem, 0x180, 0)
	putU64(mem, 0x188, 0x100)
	putU64(mem, 0x190, 8)
	copy(mem[0x198:], []byte("skip.exe"))
	putU64(mem, 0x300, 1<<20)
	putU64(mem, 0x308, 1<<20)
	putU64(mem, 0x310, 1<<20)

	rows, err := runPrivileges(t, mem, privilegeSymbols(true), map[string]string{"pid": "4", "max-nodes": "16"})
	if err != nil {
		t.Fatal(err)
	}
	privs := filterPrivilege(rows, "privilege")
	if len(privs) != len(windowsPrivilegeInfo) {
		t.Fatal(len(privs))
	}
	debug := findPrivilege(t, privs, 20)
	if debug.Cells["Process"].String() != "cmd.exe" || debug.Cells["PID"].String() != "4" || debug.Cells["Attributes"].String() != "Present,Enabled,Default" || debug.Cells["Privilege"].String() != "SeDebugPrivilege" || debug.Cells["Description"].String() != "Debug programs" {
		t.Fatal(debug.Cells)
	}
	token, err := debug.Cells["Token"].Uint()
	if err != nil || token != 0x300 {
		t.Fatal(debug.Cells["Token"], err)
	}
	if findPrivilege(t, privs, 2).Cells["Attributes"].String() != "" {
		t.Fatal(findPrivilege(t, privs, 2).Cells["Attributes"])
	}
	if len(filterPrivilege(rows, "diagnostic")) != 0 || coverage(t, rows)["rows"] != "35" || coverage(t, rows)["skipped"] != "0" {
		t.Fatal(coverage(t, rows))
	}

	skipped, err := runPrivileges(t, failRange{flatMemory: mem, at: 0x1a8}, privilegeSymbols(true), map[string]string{"max-nodes": "16"})
	if err != nil || len(filterPrivilege(skipped, "privilege")) != 35 || len(filterPrivilege(skipped, "diagnostic")) != 1 || coverage(t, skipped)["skipped"] != "1" {
		t.Fatal(err, len(skipped), coverage(t, skipped))
	}

	legacy := make(flatMemory, 0x500)
	putU64(legacy, 0, 0x100)
	putU64(legacy, 8, 0x100)
	putU64(legacy, 0x100, 0)
	putU64(legacy, 0x108, 0)
	putU64(legacy, 0x110, 12)
	copy(legacy[0x118:], []byte("old.exe"))
	putU64(legacy, 0x128, 0x300)
	putU64(legacy, 0x300, 0x400)
	putU64(legacy, 0x308, 1)
	putU64(legacy, 0x400, 20)
	putU64(legacy, 0x408, 3)
	rows, err = runPrivileges(t, legacy, privilegeSymbols(false), map[string]string{"max-nodes": "16"})
	if err != nil {
		t.Fatal(err)
	}
	privs = filterPrivilege(rows, "privilege")
	if len(privs) != 1 || privs[0].Cells["Attributes"].String() != "Present,Enabled,Default" || privs[0].Cells["Value"].String() != "20" || coverage(t, rows)["layout"] != "luid" {
		t.Fatal(len(privs), coverage(t, rows), privs[0].Cells)
	}

	putU64(legacy, 0x308, 1024)
	rows, err = runPrivileges(t, legacy, privilegeSymbols(false), map[string]string{"max-nodes": "16"})
	if err != nil || len(filterPrivilege(rows, "privilege")) != 0 || coverage(t, rows)["broken"] != "1" {
		t.Fatal(err, coverage(t, rows))
	}
}

type failRange struct {
	flatMemory
	at uint64
}

func (m failRange) ReadAt(ctx context.Context, p []byte, addr uint64) (int, error) {
	if addr < m.at+8 && addr+uint64(len(p)) > m.at {
		return 0, io.ErrUnexpectedEOF
	}
	return m.flatMemory.ReadAt(ctx, p, addr)
}
func (m failRange) Name() string { return "flat" }
func (m failRange) Ranges() []memory.Range {
	return []memory.Range{{Length: uint64(len(m.flatMemory))}}
}

func privilegeSymbols(modern bool) *symbols.ISF {
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	u64 := symbols.TypeRef{Kind: "base", Name: "unsigned long long"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	bytes := symbols.TypeRef{Kind: "array", Count: 16, Subtype: &symbols.TypeRef{Kind: "base", Name: "unsigned char"}}
	token := symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{}}
	if modern {
		token.Fields["Privileges"] = symbols.Field{Offset: 0, Type: symbols.TypeRef{Kind: "struct", Name: "_SEP_TOKEN_PRIVILEGES"}}
	} else {
		token.Fields["Privileges"] = symbols.Field{Offset: 0, Type: ptr}
		token.Fields["PrivilegeCount"] = symbols.Field{Offset: 8, Type: u32}
	}
	return &symbols.ISF{
		Bases: map[string]symbols.Type{
			"pointer":            {Size: 8, Endian: "little"},
			"unsigned char":      {Size: 1, Endian: "little"},
			"unsigned long":      {Size: 4, Endian: "little"},
			"unsigned long long": {Size: 8, Endian: "little"},
		},
		Types: map[string]symbols.Type{
			"_LIST_ENTRY":  {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Flink": {Type: ptr}, "Blink": {Offset: 8, Type: ptr}}},
			"_EX_FAST_REF": {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"Object": {Type: ptr}}},
			"_SEP_TOKEN_PRIVILEGES": {Kind: "struct", Size: 24, Fields: map[string]symbols.Field{
				"Present": {Type: u64}, "Enabled": {Offset: 8, Type: u64}, "EnabledByDefault": {Offset: 16, Type: u64},
			}},
			"_LUID": {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"LowPart": {Type: u32}, "HighPart": {Offset: 4, Type: u32}}},
			"_LUID_AND_ATTRIBUTES": {Kind: "struct", Size: 12, Fields: map[string]symbols.Field{
				"Luid": {Type: symbols.TypeRef{Kind: "struct", Name: "_LUID"}}, "Attributes": {Offset: 8, Type: u32},
			}},
			"_EPROCESS": {Kind: "struct", Size: 0x40, Fields: map[string]symbols.Field{
				"ActiveProcessLinks": {Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}},
				"UniqueProcessId":    {Offset: 0x10, Type: ptr},
				"ImageFileName":      {Offset: 0x18, Type: bytes},
				"Token":              {Offset: 0x28, Type: symbols.TypeRef{Kind: "struct", Name: "_EX_FAST_REF"}},
			}},
			"_TOKEN": token,
		},
		Symbols: map[string]symbols.Symbol{"PsActiveProcessHead": {Address: 0}},
	}
}

func runPrivileges(t *testing.T, layer memory.MemoryLayer, table *symbols.ISF, params map[string]string) ([]evidence.Row, error) {
	t.Helper()
	env := plugin.Environment{Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows", ImageHash: "img"}
	var rows []evidence.Row
	err := windowsPrivileges(context.Background(), env, params, func(row evidence.Row) error {
		row.Seal()
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	})
	return rows, err
}

func filterPrivilege(rows []evidence.Row, kind string) []evidence.Row {
	var out []evidence.Row
	for _, row := range rows {
		if row.Cells["RecordType"].String() == kind {
			out = append(out, row)
		}
	}
	return out
}

func findPrivilege(t *testing.T, rows []evidence.Row, value int) evidence.Row {
	t.Helper()
	for _, row := range rows {
		if row.Cells["Value"].String() == strconv.Itoa(value) {
			return row
		}
	}
	t.Fatalf("missing privilege %d", value)
	return evidence.Row{}
}

func coverage(t *testing.T, rows []evidence.Row) map[string]any {
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
