package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsUnloadedModulesFiltersAndCap(t *testing.T) {
	f := unloadedModuleFixture(t)
	editWindowsImage(t, f, func(data []byte) {
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		put(0x9000, 0xa000)
		put(0x9008, 5)
		put(0x9010, 0x1000)
		putUnloaded := func(addr, start, end, stamp uint64, name string, buffer uint64) {
			if name == "" {
				return
			}
			putUnicode(data, addr, buffer, name)
			put(addr+16, start)
			put(addr+24, end)
			put(addr+32, stamp)
		}
		putUnloaded(0xa000, 0x2000, 0x3000, 133000000000000000, "null.sys", 0xb000)
		putUnloaded(0xa028, 0x2000, 0x3000, 1024, "old.sys", 0xb100)
		putUnloaded(0xa050, 0x2001, 0x3000, 133000000000000000, "odd.sys", 0xb200)
		putUnloaded(0xa078, 0x800, 0x3000, 133000000000000000, "user.sys", 0xb300)
		binary.LittleEndian.PutUint16(data[0xa0a0:], 8)
		put(0xa0a8, 0x30000)
		put(0xa0b0, 0x4000)
		put(0xa0b8, 0x5000)
		put(0xa0c0, 133000000000000000)
	})
	rows, state, err := unloadedRows(t, f)
	if err != nil || state != "completed" || len(rows) != 2 {
		t.Fatal(state, len(rows), err, unloadedBrief(rows))
	}
	wantTime := time.Unix(133000000000000000/10000000-11644473600, 0).UTC().Format("2006-01-02T15:04:05Z07:00")
	start, err := rows[0].Cells["StartAddress"].Uint()
	end, endErr := rows[0].Cells["EndAddress"].Uint()
	if err != nil || endErr != nil || rows[0].Cells["RecordType"].String() != "module" || rows[0].Cells["Name"].String() != "null.sys" || start != 0x2000 || end != 0x3000 || rows[0].Cells["Time"].String() != wantTime {
		t.Fatal(rows[0].Cells, wantTime, err, endErr)
	}
	coverage := rows[1].Cells["Coverage"].Data.(map[string]any)
	if rows[1].Cells["RecordType"].String() != "summary" || coverage["hits"] != "1" || coverage["skipped"] != "3" || coverage["unreadable"] != "1" || coverage["capped"] != "false" || coverage["count"] != "5" {
		t.Fatal(coverage)
	}

	f = unloadedModuleFixture(t)
	editWindowsImage(t, f, func(data []byte) {
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		put(0x9000, 0xc000)
		put(0x9008, 2000)
		put(0x9010, 0x1000)
		putEdge := func(index int, name string, buffer uint64) {
			addr := 0xc000 + uint64(index)*40
			putUnicode(data, addr, buffer, name)
			put(addr+16, 0x2000)
			put(addr+24, 0x3000)
			put(addr+32, 133000000000000000)
		}
		putEdge(0, "null.sys", 0xb000)
		putEdge(1023, "edge.sys", 0xb100)
		putEdge(1024, "late.sys", 0xb200)
	})
	rows, state, err = unloadedRows(t, f)
	if err != nil || state != "completed" || len(rows) != 3 {
		t.Fatal(state, len(rows), err, unloadedBrief(rows))
	}
	if rows[0].Cells["Name"].String() != "null.sys" || rows[1].Cells["Name"].String() != "edge.sys" {
		t.Fatal(rows[0].Cells["Name"], rows[1].Cells["Name"])
	}
	coverage = rows[2].Cells["Coverage"].Data.(map[string]any)
	if coverage["count"] != "2000" || coverage["visited"] != "1024" || coverage["capped"] != "true" || coverage["hits"] != "2" {
		t.Fatal(coverage)
	}
}

func TestWindowsUnloadedModulesMissingSymbolFails(t *testing.T) {
	f := hiveFixture(t)
	rows, state, err := unloadedRows(t, f)
	if err == nil || state != "failed" || len(rows) != 0 || !strings.Contains(err.Error(), "MmUnloadedDrivers") {
		t.Fatal(state, len(rows), err)
	}
}

func unloadedModuleFixture(t *testing.T) testfixture.Fixture {
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
	table.Symbols["MmUnloadedDrivers"] = symbols.Symbol{Address: 0x5000}
	table.Symbols["MmLastUnloadedDriver"] = symbols.Symbol{Address: 0x5008}
	table.Symbols["MmSystemRangeStart"] = symbols.Symbol{Address: 0x5010}
	encoded, err := json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func unloadedRows(t *testing.T, f testfixture.Fixture) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.unloadedmodules", nil, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}

func unloadedBrief(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Cells["RecordType"].String()+" "+row.Cells["Name"].String())
	}
	return out
}
