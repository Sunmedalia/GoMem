package engine_test

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestModernVADFieldsIdentityAndInclusiveFilters(t *testing.T) {
	e, _ := openFixture(t, "windows")
	var processID string
	if _, err := e.Run(context.Background(), "windows.pslist", map[string]string{"pid": "104"}, engine.RunOptions{Emit: func(row evidence.Row) error { processID = row.Cells["Identity"].String(); return nil }}); err != nil {
		t.Fatal(err)
	}
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "windows.vadinfo", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
	if err != nil || result.Task.Rows != 2 {
		t.Fatal(result, err)
	}
	for _, row := range rows {
		if row.Verify() != nil || row.Cells["ProcessIdentity"].String() != processID || row.Cells["CommitCharge"].String() != "16" {
			t.Fatal(row)
		}
	}
	if rows[0].Cells["Protection"].String() != "PAGE_EXECUTE_READ" || rows[1].Cells["Protection"].String() != "PAGE_EXECUTE_READWRITE" || rows[1].Cells["PrivateMemory"].String() != "1" || rows[1].Cells["Path"].Reason != "not_file_backed" {
		t.Fatal(rows)
	}
	for _, tc := range []struct {
		params map[string]string
		rows   int64
	}{{map[string]string{"address": "0x700000"}, 1}, {map[string]string{"address": "0x70ffff"}, 1}, {map[string]string{"address": "0x710000"}, 0}, {map[string]string{"pid": "4"}, 0}, {map[string]string{"max-regions": "2"}, 2}, {map[string]string{"pid": "4,104"}, 2}} {
		result, err := e.Run(context.Background(), "windows.vadinfo", tc.params, engine.RunOptions{})
		if err != nil || result.Task.Rows != tc.rows {
			t.Fatal(tc, result, err)
		}
	}
	for _, params := range []map[string]string{{"address": "bad"}, {"max-regions": "0"}, {"max-regions": "1"}, {"max-nodes": "1"}, {"dump": "true"}} {
		result, err := e.Run(context.Background(), "windows.vadinfo", params, engine.RunOptions{})
		if err == nil {
			t.Fatal("unsupported parameter or incomplete traversal became success", params, result)
		}
	}
}

func TestVADCorruptionAndProtectionReadFailures(t *testing.T) {
	for _, scenario := range []string{"cycle", "overlap", "table-unreadable", "unknown-protection", "file-unreadable"} {
		t.Run(scenario, func(t *testing.T) {
			f, err := testfixture.Write(t.TempDir(), "windows")
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "cycle":
				binary.LittleEndian.PutUint64(data[0x16008:], 0x15000)
			case "overlap":
				binary.LittleEndian.PutUint32(data[0x16018:], 0x700)
			case "unknown-protection":
				binary.LittleEndian.PutUint32(data[0x6200+3*4:], 0x80000000)
			case "file-unreadable":
				binary.LittleEndian.PutUint64(data[0x17208:], 0x300000)
			case "table-unreadable":
				table, err := symbols.Load(f.Symbols)
				if err != nil {
					t.Fatal(err)
				}
				table.Symbols["MmProtectToValue"] = symbols.Symbol{Address: 0x300000}
				encoded, err := table.Encode()
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "windows.vadinfo", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			if scenario == "cycle" || scenario == "overlap" {
				if err == nil || result.Task.State != "failed" {
					t.Fatal("invalid index emitted clean evidence", result, err)
				}
				return
			}
			field := "Protection"
			if scenario == "file-unreadable" {
				field = "Path"
			}
			if err != nil || len(rows) != 2 || rows[0].Cells[field].Kind != "missing" || rows[0].Cells[field].Error == "" {
				t.Fatal(rows, result, err)
			}
		})
	}
}
