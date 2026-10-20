package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsHandles(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 handle table; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-handles.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.handles", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, len(rows), err)
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	out, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(out)
	handles := 0
	pids := map[string]struct{}{}
	var maxHandle uint64
	nullNames := 0
	reasons := map[string]int{}
	var coverage map[string]any
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "summary" {
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
			continue
		}
		if row.Cells["RecordType"].String() != "handle" {
			continue
		}
		handles++
		pids[row.Cells["PID"].String()] = struct{}{}
		value, err := row.Cells["HandleValue"].Uint()
		if err != nil {
			t.Fatal(err)
		}
		if value > maxHandle {
			maxHandle = value
		}
		if row.Cells["Name"].Kind == "missing" {
			if row.Cells["Name"].Error != "" {
				t.Fatalf("name error leaked into the compared cell: %s", row.Cells["Name"].Error)
			}
			nullNames++
			reasons[row.Cells["Name"].Reason]++
		}
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.handles.json"), "--output", reportPath)
	if output, err := cmd.CombinedOutput(); err != nil && len(output) > 0 {
		t.Logf("%s", output)
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Matched       bool             `json:"matched"`
		NativeRows    int              `json:"native_rows"`
		ReferenceRows int              `json:"reference_rows"`
		Missing       []map[string]any `json:"missing"`
		Extra         []map[string]any `json:"extra"`
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Matched {
		limit := 3
		if len(report.Missing) < limit {
			limit = len(report.Missing)
		}
		extraLimit := 3
		if len(report.Extra) < extraLimit {
			extraLimit = len(report.Extra)
		}
		t.Fatalf("handles %d pids %d nulls %d max %#x native %d reference %d missing %d extra %d\nmissing %v\nextra %v", handles, len(pids), nullNames, maxHandle, report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra), report.Missing[:limit], report.Extra[:extraLimit])
	}
	if handles != 50967 || len(pids) != 109 || nullNames != 37914 || maxHandle != 12200 || reasons["not_available"] != 37909 || reasons["unreadable"] != 5 {
		t.Fatalf("handles %d pids %d nulls %d max %#x reasons %v", handles, len(pids), nullNames, maxHandle, reasons)
	}
	if coverage["mode"] != "pslist" || coverage["processes"] != "120" || coverage["handles"] != "50967" || coverage["level0"] != "41" || coverage["level1"] != "76" || coverage["level2"] != "0" || coverage["level3plus"] != "0" || coverage["skipped_handle_tables"] != "3" || coverage["skipped_object_tables"] != "0" || coverage["cycles"] != "0" || coverage["pages"] != "38517" || coverage["slots"] != "78848" {
		t.Fatalf("coverage %v", coverage)
	}
	t.Logf("handles %d pids %d nulls %d max %#x reasons %v coverage %v", handles, len(pids), nullNames, maxHandle, reasons, coverage)
}
