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

func TestOfficialWindowsSessions(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 session rows; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-sessions.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.sessions", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	native := filepath.Join(t.TempDir(), "native.jsonl")
	out, createErr := os.Create(native)
	if createErr != nil {
		t.Fatal(createErr)
	}
	enc := json.NewEncoder(out)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.sessions.json"))
	report, diffErr := cmd.CombinedOutput()
	sessions := 0
	var build string
	var coverage any
	for _, row := range rows {
		build = row.Provenance.EngineBuild
		if row.Cells["RecordType"].Data == "session" {
			sessions++
		}
		if row.Cells["RecordType"].Data == "summary" {
			coverage = row.Cells["Coverage"].Data
		}
	}
	if diffErr != nil || err == nil || result.Task.State != "failed" || sessions != 120 {
		t.Fatalf("state %s sessions %d err %v build %s coverage %#v\n%s", result.Task.State, sessions, err, build, coverage, report)
	}
	data, _ := coverage.(map[string]any)
	if data["processes"] != "120" || data["failures"] != "26" {
		t.Fatalf("state %s sessions %d err %v build %s coverage %#v\n%s", result.Task.State, sessions, err, build, coverage, report)
	}
	t.Logf("state %s sessions %d build %s coverage %#v\n%s", result.Task.State, sessions, build, coverage, report)
}
