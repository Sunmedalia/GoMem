package plugins

import (
	"context"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestTrueCryptScannerAcceptsPaddedASCII(t *testing.T) {
	data := []byte{
		5, 0, 0, 0,
		'h', 'e', 'l', 'l', 'o',
		0x41, 0, 0, 0,
		0, 0, 0,
	}
	mapped, err := memory.NewMapped(rangeScanSource(data), "data", []memory.Range{{Length: uint64(len(data))}})
	if err != nil {
		t.Fatal(err)
	}
	hits, err := scanTrueCryptData(context.Background(), mapped, 0, uint64(len(data)), 5)
	if err != nil || len(hits) != 1 || hits[0].offset != 4 || hits[0].password != "hello" {
		t.Fatal(hits, err)
	}
	hits, err = scanTrueCryptData(context.Background(), mapped, 0, uint64(len(data)), 6)
	if err != nil || len(hits) != 0 {
		t.Fatal(hits, err)
	}
	data[4] = 0x7f
	hits, err = scanTrueCryptData(context.Background(), mapped, 0, uint64(len(data)), 5)
	if err != nil || len(hits) != 0 {
		t.Fatal("accepted DEL", hits, err)
	}
	data[4] = 'h'
	data[10] = 1
	hits, err = scanTrueCryptData(context.Background(), mapped, 0, uint64(len(data)), 5)
	if err != nil || len(hits) != 0 {
		t.Fatal("accepted nonzero alignment padding", hits, err)
	}
	if _, err = scanTrueCryptData(context.Background(), mapped, 0, 6, 5); err == nil || !strings.Contains(err.Error(), "DWORD-aligned") {
		t.Fatal(err)
	}
}

func TestTrueCryptFindsModuleAndReportsAbsence(t *testing.T) {
	mem := make(flatMemory, 0x2000)
	linkSSDT(mem, 0x100, []uint64{0x200, 0x280}, 8)
	putSSDTModule(mem, 0x200, 0x1000, 0x1000, "ntoskrnl.exe", 0x400)
	putSSDTModule(mem, 0x280, 0x800, 0x800, "TrueCrypt.sys", 0x480)
	writeTrueCryptPE(mem, 0x800, []byte{4, 0, 0, 0, 'a', 'b', 'c', 'd', 0, 0, 0, 0})
	rows := runTrueCrypt(t, mem, map[string]string{"min-length": "4"})
	passwords := filterTrueCrypt(rows, "password")
	if len(passwords) != 1 || passwords[0].Cells["Password"].String() != "abcd" || passwords[0].Cells["Length"].String() != "4" || passwords[0].Cells["ModuleName"].String() != "TrueCrypt.sys" {
		t.Fatalf("%#v", cellText(passwords))
	}
	offset, err := passwords[0].Cells["Offset"].Uint()
	if err != nil || offset != 0x800+0x400+4 {
		t.Fatal(offset, err)
	}
	coverage := trueCryptCoverage(t, rows)
	if coverage["module_found"] != "true" || coverage["passwords"] != "1" || coverage["min_length"] != "4" {
		t.Fatal(coverage)
	}

	mem = make(flatMemory, 0x800)
	linkSSDT(mem, 0x100, []uint64{0x200}, 8)
	putSSDTModule(mem, 0x200, 0x500, 0x100, "filecrypt.sys", 0x400)
	rows = runTrueCrypt(t, mem, nil)
	if len(filterTrueCrypt(rows, "password")) != 0 || trueCryptCoverage(t, rows)["module_found"] != "false" {
		t.Fatal(trueCryptCoverage(t, rows))
	}
}

func TestTrueCryptMissingDataSectionFails(t *testing.T) {
	mem := make(flatMemory, 0x2000)
	linkSSDT(mem, 0x100, []uint64{0x200}, 8)
	putSSDTModule(mem, 0x200, 0x800, 0x800, "truecrypt.sys", 0x400)
	writeTrueCryptPE(mem, 0x800, nil)
	copy(mem[0x800+0x80+24+0x70:], ".text\x00\x00\x00")
	err := windowsTrueCrypt(context.Background(), trueCryptEnvironment(mem), map[string]string{"min-length": "5"}, func(evidence.Row) error { return nil })
	if err == nil || !strings.Contains(err.Error(), ".data") {
		t.Fatal(err)
	}
}

func writeTrueCryptPE(mem flatMemory, base uint64, data []byte) {
	copy(mem[base:], "MZ")
	putU32(mem, base+0x3c, 0x80)
	pe := base + 0x80
	copy(mem[pe:], "PE\x00\x00")
	putU16(mem, pe+4, 0x8664)
	putU16(mem, pe+6, 1)
	putU16(mem, pe+20, 0x70)
	putU16(mem, pe+24, 0x20b)
	section := pe + 24 + 0x70
	copy(mem[section:], ".data")
	if len(data) > 0 {
		putU32(mem, section+8, uint32(len(data)))
	}
	putU32(mem, section+12, 0x400)
	copy(mem[base+0x400:], data)
}

func trueCryptEnvironment(mem flatMemory) plugin.Environment {
	table := ssdtSymbolTable(8)
	table.Symbols = map[string]symbols.Symbol{"PsLoadedModuleList": {Address: 0x100}}
	return plugin.Environment{Physical: mem, Kernel: mem, Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}, OS: "windows", ImageHash: "img"}
}

func runTrueCrypt(t *testing.T, mem flatMemory, params map[string]string) []evidence.Row {
	t.Helper()
	var rows []evidence.Row
	if err := windowsTrueCrypt(context.Background(), trueCryptEnvironment(mem), params, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

func filterTrueCrypt(rows []evidence.Row, kind string) []evidence.Row {
	var out []evidence.Row
	for _, row := range rows {
		if row.Cells["RecordType"].String() == kind {
			out = append(out, row)
		}
	}
	return out
}

func trueCryptCoverage(t *testing.T, rows []evidence.Row) map[string]any {
	t.Helper()
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "summary" {
			coverage, _ := row.Cells["Coverage"].Data.(map[string]any)
			return coverage
		}
	}
	t.Fatal("missing summary")
	return nil
}

func cellText(rows []evidence.Row) []string {
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = row.Cells["Password"].String() + " " + row.Cells["ModuleName"].String()
	}
	return out
}
