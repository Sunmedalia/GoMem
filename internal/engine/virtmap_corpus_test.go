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

func TestOfficialWindowsVirtMap(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 system VA map; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-virtmap.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.virtmap", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	regions := 0
	var coverage map[string]any
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "summary" {
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
			if err = enc.Encode(row); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if row.Cells["RecordType"].String() != "region" {
			t.Fatalf("unexpected %s", row.Cells["RecordType"])
		}
		regions++
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.virtmap.json"), "--output", reportPath)
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
		limit := 2
		if len(report.Missing) < limit {
			limit = len(report.Missing)
		}
		extraLimit := 2
		if len(report.Extra) < extraLimit {
			extraLimit = len(report.Extra)
		}
		t.Fatalf("regions %d coverage %v native %d reference %d missing %d extra %d\nmissing %v\nextra %v", regions, coverage, report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra), report.Missing[:limit], report.Extra[:extraLimit])
	}
	if regions != 13 || coverage["path"] != "system_va_regions" || coverage["examined"] != "13" || coverage["count"] != "13" || coverage["rows"] != "13" || coverage["names"] != "13" || coverage["large_page"] != "2097152" {
		t.Fatalf("regions %d coverage %v", regions, coverage)
	}
	t.Logf("regions %d coverage %v", regions, coverage)
}
