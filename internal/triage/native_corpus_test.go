package triage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
)

func TestOfficialWindowsNativeTriageCoverage(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 native triage control; not release acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
		t.Fatal("official image drift", e.Hash)
	}
	for attempt := 0; attempt < 2; attempt++ {
		summary, err := Run(ctx, e, nil)
		if !errors.Is(err, ErrIncomplete) {
			t.Fatal(summary, err)
		}
		seen := 0
		for _, check := range summary.Checks {
			switch check.Rule {
			case "suspicious-thread-start":
				seen++
				if check.State != "completed" || check.Findings != 0 || check.Coverage["threads"] != "1749" {
					t.Fatal(check)
				}
			case "hollow-process-mapping":
				seen++
				if check.State != "incomplete" || check.Findings != 0 || check.Coverage["checked"] != "99" || check.Coverage["diagnostics"] != "330" {
					t.Fatal(check)
				}
			}
		}
		if seen != 2 {
			t.Fatal("native triage rules were not evaluated", summary)
		}
		for _, task := range summary.Tasks {
			if task.Task.State != "completed" || attempt > 0 && !task.Reused {
				t.Fatal(task)
			}
		}
		t.Logf("attempt %d findings %d native checks evaluated %d", attempt, summary.Findings, seen)
	}
}
