package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxCheckModules(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian check_modules differential")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var original, replay bytes.Buffer
	encoder := json.NewEncoder(io.MultiWriter(file, &original))
	hidden, summaries := 0, 0
	result, err := e.Run(ctx, "linux.check_modules", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		if err := encoder.Encode(r); err != nil {
			return err
		}
		if r.Cells["Source"].String() == "Scanner" {
			t.Fatal("unexpected allocation scan", r)
		}
		if r.Cells["RecordType"].String() == "summary" {
			summaries++
			raw, err := json.Marshal(r.Cells["Coverage"].Data)
			if err != nil {
				t.Fatal(err)
			}
			var coverage map[string]string
			if err = json.Unmarshal(raw, &coverage); err != nil || coverage["lsmod"] != "79" || coverage["sysfs"] != "79" || coverage["read_layout_errors"] != "0" {
				t.Fatal(coverage, err)
			}
		}
		if r.Cells["RecordType"].String() == "kset_only" {
			hidden++
		}
		return nil
	}})
	if err != nil || result.Task.State != "completed" || hidden != 0 || result.Task.Rows < 2 || summaries != 1 {
		t.Fatal(result, err, hidden)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-check-modules.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.check_modules.json")).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	cached, err := e.Run(ctx, "linux.check_modules", nil, engine.RunOptions{Emit: func(r evidence.Row) error { return json.NewEncoder(&replay).Encode(r) }})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID || !bytes.Equal(original.Bytes(), replay.Bytes()) {
		t.Fatal(cached, err)
	}
	t.Logf("0 kset-only modules match; %d native rows retained; cache reused", result.Task.Rows)
}
