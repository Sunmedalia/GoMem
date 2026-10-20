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

func TestWindowsGetCellRoutineSynthetic(t *testing.T) {
	f := cellRoutineFixture(t, 56, 64)
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x30000+56:], 0x4010)
	})
	rows, state, err := cellRoutineRows(t, f)
	if err != nil || state != "completed" || len(rows) != 0 {
		t.Fatal(state, len(rows), err)
	}

	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x30000+56:], 0x14000)
	})
	rows, state, err = cellRoutineRows(t, f)
	if err != nil || state != "completed" || len(rows) != 0 {
		t.Fatal("inclusive kernel end", state, len(rows), err)
	}

	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x30000+56:], 0x14001)
	})
	rows, state, err = cellRoutineRows(t, f)
	if err != nil || state != "completed" || len(rows) != 1 || rows[0].Cells["RecordType"].String() != "unmapped" || rows[0].Cells["Module"].Reason != "not_available" || !mustAddr(rows[0].Cells["Handler"], 0x14001) || rows[0].Cells["HiveName"].String() != `\REGISTRY\MACHINE\SYSTEM` {
		t.Fatal(state, cellSummary(rows), err)
	}

	editWindowsImage(t, f, func(data []byte) {
		linkCellModule(data, "hook.sys", 0x50000, 0x1000)
		binary.LittleEndian.PutUint64(data[0x30000+56:], 0x51000)
	})
	rows, state, err = cellRoutineRows(t, f)
	if err != nil || state != "completed" || len(rows) != 1 || rows[0].Cells["RecordType"].String() != "hook" || rows[0].Cells["Module"].String() != "hook" || !mustAddr(rows[0].Cells["Handler"], 0x51000) {
		t.Fatal(state, cellSummary(rows), err)
	}

	editWindowsImage(t, f, func(data []byte) {
		for i, c := range "NTOSKRNL.EXE" {
			binary.LittleEndian.PutUint16(data[0xb000+i*2:], uint16(c))
		}
		binary.LittleEndian.PutUint64(data[0x30000+56:], 0x4010)
	})
	rows, state, err = cellRoutineRows(t, f)
	if err != nil || state != "completed" || len(rows) != 1 || rows[0].Cells["Module"].String() != "NTOSKRNL" {
		t.Fatal(state, cellSummary(rows), err)
	}
}

func TestWindowsGetCellRoutineUnreadableAndDuplicates(t *testing.T) {
	f := cellRoutineFixture(t, 0x1d0000, 0x1d0008)
	rows, state, err := cellRoutineRows(t, f)
	if err != nil || state != "completed" || len(rows) != 1 || rows[0].Cells["RecordType"].String() != "unreadable" || rows[0].Cells["Error"].Reason != "getcellroutine_unreadable" || rows[0].Cells["Handler"].Reason != "unreadable" {
		t.Fatal(state, cellSummary(rows), err)
	}

	missing := printKeyFixture(t, false)
	result, err := openWindowsImage(t, missing).Run(context.Background(), "windows.getcellroutine", nil, engine.RunOptions{})
	if err == nil || result.Task.State == "completed" || !strings.Contains(err.Error(), "GetCellRoutine") {
		t.Fatal(result.Task.State, err)
	}

	dup := cellRoutineFixture(t, 56, 64)
	editWindowsImage(t, dup, func(data []byte) {
		linkCellModule(data, "ntoskrnl.exe", 0x60000, 0x1000)
	})
	result, err = openWindowsImage(t, dup).Run(context.Background(), "windows.getcellroutine", nil, engine.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "duplicate kernel module stem") {
		t.Fatal(result.Task.State, err)
	}

	badBase := cellRoutineFixture(t, 56, 64)
	raw, err := os.ReadFile(badBase.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table symbols.ISF
	if err = json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	ldr := table.Types["_KLDR_DATA_TABLE_ENTRY"]
	ldr.Size = 0x1e4010
	base := ldr.Fields["DllBase"]
	base.Offset = 0x1e4000
	ldr.Fields["DllBase"] = base
	table.Types["_KLDR_DATA_TABLE_ENTRY"] = ldr
	encoded, err := json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(badBase.Symbols, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	editWindowsImage(t, badBase, func(data []byte) {
		linkCellModule(data, "hook.sys", 0x50000, 0x1000)
	})
	result, err = openWindowsImage(t, badBase).Run(context.Background(), "windows.getcellroutine", nil, engine.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "base") {
		t.Fatal(result.Task.State, err)
	}
}

func cellRoutineFixture(t *testing.T, offset, size uint64) testfixture.Fixture {
	t.Helper()
	f := printKeyFixture(t, false)
	raw, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table symbols.ISF
	if err = json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	hive := table.Types["_HHIVE"]
	if size > hive.Size {
		hive.Size = size
	}
	hive.Fields["GetCellRoutine"] = symbols.Field{Offset: offset, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["_HHIVE"] = hive
	cm := table.Types["_CMHIVE"]
	if hive.Size > cm.Size {
		cm.Size = hive.Size
		table.Types["_CMHIVE"] = cm
	}
	encoded, err := json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func linkCellModule(data []byte, name string, base, size uint64) {
	const module = 0x1c000
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put(0x6010+8, module)
	put(0xa000, module)
	put(module, 0x6010)
	put(module+8, 0xa000)
	put(module+16, base)
	binary.LittleEndian.PutUint32(data[module+24:], uint32(size))
	putUnicode(data, module+32, 0x1d000, name)
}

func cellRoutineRows(t *testing.T, f testfixture.Fixture) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.getcellroutine", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}})
	return rows, result.Task.State, err
}

func cellSummary(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Cells["RecordType"].String()+" "+row.Cells["Module"].String()+" "+row.Cells["Handler"].String()+" "+row.Cells["Error"].Reason)
	}
	return out
}

func mustAddr(v evidence.Value, want uint64) bool {
	n, err := v.Uint()
	return err == nil && n == want
}
