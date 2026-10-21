package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxKthreadsUnsupported(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian 3.2 applicability test; not a positive kernel-thread differential")
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("corpus drift", e.Hash)
	}
	for i := 0; i < 2; i++ {
		result, err := e.Run(context.Background(), "linux.kthreads", nil, engine.RunOptions{})
		if err == nil || !strings.Contains(err.Error(), "Linux >= 5.8") || result.Task.State != "failed" || result.Reused {
			t.Fatal(result, err)
		}
		rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1})
		if err != nil || len(rows) != 0 {
			t.Fatal(rows, err)
		}
	}
	t.Log("Debian 3.2 rejected as unsupported with a persisted failed task; no successful empty result or cached success")
}
