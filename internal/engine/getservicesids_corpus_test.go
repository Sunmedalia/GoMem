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

func TestOfficialWindowsGetServiceSIDs(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 service SID rows; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-getservicesids.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.getservicesids", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	for _, row := range rows {
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.getservicesids.json"))
	report, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diff failed: %v\n%s", err, report)
	}
	services := 0
	var coverage any
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "service" {
			services++
		}
		if row.Cells["RecordType"].String() == "summary" {
			coverage = row.Cells["Coverage"].Data
		}
	}
	t.Logf("services %d coverage %#v\n%s", services, coverage, report)
}
