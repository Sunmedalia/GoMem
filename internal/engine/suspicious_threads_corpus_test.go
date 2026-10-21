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

func TestOfficialWindowsSuspiciousThreads(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 suspicious-thread differential; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-suspicious-threads.json")
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
	result, err := e.Run(ctx, "windows.suspicious_threads", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	findings := 0
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "summary":
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
		case "finding":
			findings++
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
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.suspicious_threads.json"), "--output", reportPath)
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
	if !report.Matched || report.NativeRows != report.ReferenceRows || findings != report.ReferenceRows {
		sample := func(items []json.RawMessage) string {
			if len(items) == 0 {
				return ""
			}
			if len(items[0]) > 500 {
				return string(items[0][:500])
			}
			return string(items[0])
		}
		t.Fatalf("findings %d coverage %v matched %v native %d reference %d missing %d extra %d\nmissing %s\nextra %s\n%s", findings, coverage, report.Matched, report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra), sample(report.Missing), sample(report.Extra), output)
	}
	for key, want := range map[string]string{"processes": "120", "short_vad_sets": "3", "threads": "1749", "gather_skipped": "0", "findings": "0", "path_read_errors": "0"} {
		if coverage[key] != want {
			t.Fatal(key, coverage)
		}
	}
	t.Logf("coverage %v", coverage)
}
