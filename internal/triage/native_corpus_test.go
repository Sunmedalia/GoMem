package triage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
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
		if summary.Findings != 31 {
			t.Fatal("unexpected findings", summary.Findings)
		}
		seen := 0
		for _, check := range summary.Checks {
			switch check.Rule {
			case "hidden-process":
				seen++
				if check.State != "completed" || check.Findings != 1 || check.Coverage["pslist"] != "113" || check.Coverage["psscan"] != "114" || check.Coverage["thrdscan"] != "112" || check.Coverage["csrss"] != "103" {
					t.Fatal(check)
				}
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
		if seen != 3 {
			t.Fatal("native triage rules were not evaluated", summary)
		}

		findings, queryErr := e.Store.Query(ctx, evidence.Query{TaskID: summary.FindingTask, Limit: 100})
		if queryErr != nil {
			t.Fatal(queryErr)
		}
		hidden := 0
		for _, finding := range findings {
			if finding.Cells["Rule"].String() != "hidden-process" {
				continue
			}
			hidden++
			refs := finding.Cells["EvidenceIDs"].Data.([]any)
			source, sourceErr := e.Store.Find(ctx, refs[0].(string))
			pid, pidErr := finding.Cells["PID"].Uint()
			if finding.Verify() != nil || sourceErr != nil || source.Verify() != nil || pidErr != nil || pid != 408 || finding.Cells["Severity"].String() != "info" || finding.Cells["Name"].String() != "MpCmdRun.exe" || source.Provenance.Plugin != "windows.psxview" || source.Cells["pslist"].Data != false || source.Cells["ExitTime"].String() == "" || source.Cells["Identity"].String() != finding.Cells["Entity"].String() || source.Provenance.Offset != finding.Provenance.Offset {
				t.Fatal(finding, source, sourceErr)
			}
		}
		if hidden != 1 {
			t.Fatal("missing residual process evidence", hidden)
		}
		for _, task := range summary.Tasks {
			if task.Task.State != "completed" || attempt > 0 && !task.Reused {
				t.Fatal(task)
			}
		}
		t.Logf("attempt %d findings %d native checks evaluated %d", attempt, summary.Findings, seen)
	}
}
