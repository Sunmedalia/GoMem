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

func TestOfficialWindowsEnvars(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 environment rows; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-envars.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.envars", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.envars.json"))
	report, diffErr := cmd.CombinedOutput()
	var variables, diagnostics int
	var build string
	reasons := map[string]int{}
	var coverage any
	for _, row := range rows {
		build = row.Provenance.EngineBuild
		switch row.Cells["RecordType"].Data {
		case "variable":
			variables++
		case "diagnostic":
			diagnostics++
			reasons[row.Cells["Error"].Reason]++
		case "summary":
			coverage = row.Cells["Coverage"].Data
		}
	}
	wantReasons := map[string]int{"no_process_peb": 3, "process_parameters_pointer_unreadable": 14, "environment_size_unreadable": 5, "environment_pointer_unreadable": 1, "environment_buffer_unreadable": 6}
	if diffErr != nil || err == nil || result.Task.State != "failed" || variables != 2960 || diagnostics != 29 || len(reasons) != len(wantReasons) {
		t.Fatalf("state %s variables %d diagnostics %d reasons %v err %v coverage %#v\n%s", result.Task.State, variables, diagnostics, reasons, err, coverage, report)
	}
	for key, value := range wantReasons {
		if reasons[key] != value {
			t.Fatalf("state %s variables %d diagnostics %d reasons %v err %v coverage %#v\n%s", result.Task.State, variables, diagnostics, reasons, err, coverage, report)
		}
	}
	t.Logf("state %s build %s variables %d diagnostics %d reasons %v coverage %#v\n%s", result.Task.State, build, variables, diagnostics, reasons, coverage, report)
}
