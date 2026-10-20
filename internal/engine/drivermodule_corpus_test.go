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

func TestOfficialWindowsDriverModule(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 hidden-driver rows; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-drivermodule.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.drivermodule", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	drivers := 0
	known := 0
	var coverage map[string]any
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "summary" {
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
			if err = enc.Encode(row); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if row.Cells["RecordType"].String() != "driver" {
			t.Fatalf("unexpected %s", row.Cells["RecordType"])
		}
		drivers++
		if row.Cells["KnownException"].Kind != "bool" {
			t.Fatal(row.Cells["KnownException"])
		}
		if row.Cells["KnownException"].Data == true {
			known++
		}
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.drivermodule.json"), "--output", reportPath)
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
		t.Fatalf("drivers %d known %d coverage %v native %d reference %d missing %d extra %d\nmissing %v\nextra %v", drivers, known, coverage, report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra), report.Missing[:limit], report.Extra[:extraLimit])
	}
	if drivers != 1 || known != 1 {
		t.Fatalf("drivers %d known %d coverage %v", drivers, known, coverage)
	}
	if coverage["passed_start"] != "142" || coverage["in_module"] != "141" || coverage["unnamed"] != "0" || coverage["hidden"] != "1" || coverage["known_exceptions"] != "1" {
		t.Fatal(coverage)
	}
	t.Logf("drivers %d known %d coverage %v", drivers, known, coverage)
}
