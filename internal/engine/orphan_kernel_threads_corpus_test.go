package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsOrphanKernelThreads(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 orphan kernel threads; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-orphan-kernel-threads.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.orphan_kernel_threads", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
	threads := 0
	var coverage map[string]any
	for _, row := range rows {
		kind := row.Cells["RecordType"].String()
		if kind == "summary" {
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
		}
		if kind == "thread" {
			threads++
		} else if kind != "summary" && kind != "diagnostic" {
			t.Fatalf("unexpected %s", kind)
		}
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.orphan-kernel-threads.json"), "--output", reportPath)
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
		t.Fatalf("threads %d coverage %v native %d reference %d missing %d extra %d\nmissing %v\nextra %v", threads, coverage, report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra), report.Missing, report.Extra)
	}
	if threads != 0 || coverage["orphans"] != "0" || coverage["gather_skipped"] != "0" || coverage["owner_unreadable"] != "0" {
		t.Fatalf("threads %d coverage %v", threads, coverage)
	}
	sum := 0
	for _, key := range []string{"not_kernel", "exited", "user_start", "in_module", "orphans", "owner_unreadable", "gather_skipped"} {
		n := 0
		if _, err = fmt.Sscan(fmt.Sprint(coverage[key]), &n); err != nil {
			t.Fatal(coverage)
		}
		sum += n
	}
	examined := 0
	if _, err = fmt.Sscan(fmt.Sprint(coverage["examined"]), &examined); err != nil || examined != 1752 || sum != examined {
		t.Fatalf("threads %d sum %d coverage %v", threads, sum, coverage)
	}
	t.Logf("threads %d coverage %v", threads, coverage)
}
