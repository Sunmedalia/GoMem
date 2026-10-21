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

func TestOfficialWindowsSvcScan(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 service-scan differential; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-svcscan.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
		t.Fatal("official image drift", e.Hash)
	}
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.svcscan", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	var coverage map[string]any
	services := 0
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "summary":
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
		case "service":
			services++
		default:
			t.Fatalf("unexpected %s", row.Cells["RecordType"])
		}
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.svcscan.json"), "--output", reportPath)
	output, cmdErr := cmd.CombinedOutput()
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(cmdErr, string(output), err)
	}
	var report struct {
		Matched       bool              `json:"matched"`
		NativeRows    int               `json:"native_rows"`
		ReferenceRows int               `json:"reference_rows"`
		Missing       []json.RawMessage `json:"missing"`
		Extra         []json.RawMessage `json:"extra"`
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err, string(raw))
	}
	if !report.Matched || report.NativeRows != report.ReferenceRows || services != report.ReferenceRows {
		sample := func(items []json.RawMessage) string {
			if len(items) == 0 {
				return ""
			}
			if len(items[0]) > 500 {
				return string(items[0][:500])
			}
			return string(items[0])
		}
		t.Fatalf("services %d coverage %v matched %v native %d reference %d missing %d extra %d\nmissing %s\nextra %s\n%s", services, coverage, report.Matched, report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra), sample(report.Missing), sample(report.Extra), output)
	}
	t.Logf("coverage %v", coverage)
}
