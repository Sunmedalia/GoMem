package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
)

// Unsupported input is not a clean negative ftrace result or an accepted differential.
func TestOfficialLinuxFtraceUnsupportedKernel(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_FTRACE_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional Debian corpus and pinned ftrace reference; not acceptance")
	}
	raw, err := os.ReadFile(prefix + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline   struct{ Commit string }
		Image      string `json:"image_sha256"`
		Output     string `json:"output_sha256"`
		Plugin     string
		Parameters []string
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.tracing.ftrace" || len(manifest.Parameters) != 0 {
		t.Fatal(err, manifest)
	}
	raw, err = os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != manifest.Output {
		t.Fatal("reference digest")
	}
	var reference []json.RawMessage
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 0 {
		t.Fatal(err, len(reference))
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	if _, err := e.Env.Symbols.Lookup("ftrace_ops_list"); err == nil {
		t.Fatal("expected unsupported count symbol")
	}
	first := ""
	for attempt := 0; attempt < 2; attempt++ {
		result, err := e.Run(context.Background(), "linux.check_ftrace", nil, engine.RunOptions{})
		if err == nil || !strings.Contains(err.Error(), "unsupported ftrace") || result.Task.State != "failed" || result.Task.Rows != 0 || result.Reused || result.Task.ID == first {
			t.Fatal(result, err)
		}
		first = result.Task.ID
	}
}
