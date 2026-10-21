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

func TestOfficialWindowsTrueCrypt(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 TrueCrypt scan; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-truecrypt.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.truecrypt", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	passwords := 0
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "summary":
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
		case "password":
			passwords++
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
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.truecrypt.json"), "--output", reportPath)
	if output, err := cmd.CombinedOutput(); err != nil && len(output) > 0 {
		t.Logf("%s", output)
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Matched       bool `json:"matched"`
		NativeRows    int  `json:"native_rows"`
		ReferenceRows int  `json:"reference_rows"`
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err, string(raw))
	}
	if !report.Matched || report.NativeRows != 0 || report.ReferenceRows != 0 || passwords != 0 || coverage["module_found"] != "false" || coverage["passwords"] != "0" || coverage["min_length"] != "5" {
		t.Fatalf("passwords %d coverage %v report %+v", passwords, coverage, report)
	}
	t.Logf("coverage %v", coverage)
}
