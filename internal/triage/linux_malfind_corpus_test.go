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

func TestOfficialLinuxMalfindTriageCoverage(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("requires optional Debian corpus; negative control is not acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	result, err := e.Run(ctx, "linux.malfind", map[string]string{"show-all-dirty-pages": "true"}, engine.RunOptions{})
	if err == nil || result.Task.State != "failed" {
		t.Fatal(result, err)
	}
	for _, rule := range Rules {
		if rule.Kind != "linux-malfind" {
			continue
		}
		m := malfindEvaluator{rule: rule, source: &result.Task}
		for off := 0; ; off += 500 {
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Offset: off, Limit: 500})
			if err != nil {
				t.Fatal(err)
			}
			if err = m.consume(ctx, rows, func(evidence.Row) error { t.Fatal("negative control emitted finding"); return nil }); err != nil {
				t.Fatal(err)
			}
			if len(rows) < 500 {
				break
			}
		}
		coverage, err := m.finish()
		if !errors.Is(err, ErrIncomplete) || m.scans != 3192 || m.probes != 210847 || m.missing != 149562 || m.diagnostics != 2880 || m.invalid != 0 {
			t.Fatal(coverage, err)
		}
		t.Log(rule.ID, coverage)
	}
}
