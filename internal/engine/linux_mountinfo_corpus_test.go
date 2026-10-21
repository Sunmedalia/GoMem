package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialLinuxMountInfo(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian mountinfo differential")
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
	encoder := json.NewEncoder(file)
	mounts, captures := 0, 0
	result, err := e.Run(ctx, "linux.mountinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		if err := encoder.Encode(r); err != nil {
			return err
		}
		if r.Cells["RecordType"].String() == "mount" {
			mounts++
		}
		if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
			for _, proof := range fields {
				c, ok := proof.Data.(map[string]evidence.Value)
				if !ok || c["Raw"].Kind != "bytes" || c["ReadComplete"].Data != true {
					continue
				}
				at, err := c["Address"].Uint()
				raw := c["Raw"].Data.([]byte)
				actual, readErr := memory.Read(ctx, e.Env.Kernel, at, len(raw))
				if err != nil || readErr != nil || !bytes.Equal(raw, actual) {
					t.Fatal(err, readErr)
				}
				captures++
			}
		}
		return nil
	}})
	if err != nil || result.Task.State != "completed" || mounts != 13 || captures == 0 {
		t.Fatal(result, err, mounts, captures)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-mountinfo.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.mountinfo.json")).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	cached, err := e.Run(ctx, "linux.mountinfo", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
		t.Fatal(cached, err)
	}
	t.Logf("13 mounts match detailed fields and order; %d raw captures reread; cache reused", captures)
}
