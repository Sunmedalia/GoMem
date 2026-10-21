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

func TestOfficialLinuxTTY(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian tty differential")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-tty.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []struct {
		Name, Module, Symbol string
		Address              uint64
	}
	if err = json.Unmarshal(raw, &expected); err != nil || len(expected) != 7 {
		t.Fatal(err, len(expected))
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	selected, captures := 0, 0
	result, err := e.Run(ctx, "linux.tty_check", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		if err := encoder.Encode(r); err != nil {
			return err
		}
		if r.Cells["RecordType"].String() == "tty" {
			want := expected[selected]
			selected++
			at, _ := r.Cells["Address"].Uint()
			if r.Cells["Name"].String() != want.Name || r.Cells["Module"].String() != want.Module || r.Cells["Symbol"].String() != want.Symbol || at&0xffffffffffff != want.Address {
				t.Fatal(want, r.Cells["Name"], r.Cells["Module"], r.Cells["Symbol"], at)
			}
		}
		if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
			for _, proof := range fields {
				if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" && c["ReadComplete"].Data == true {
					at, err := c["Address"].Uint()
					raw := c["Raw"].Data.([]byte)
					actual, readErr := memory.Read(ctx, e.Env.Kernel, at, len(raw))
					if err != nil || readErr != nil || !bytes.Equal(raw, actual) {
						t.Fatal(err, readErr)
					}
					captures++
				}
			}
		}
		return nil
	}})
	if err != nil || result.Task.State != "completed" || selected != 7 || captures == 0 {
		t.Fatal(result, err, selected, captures)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-tty.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.tty_check.json")).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	cached, err := e.Run(ctx, "linux.tty_check", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
		t.Fatal(cached, err)
	}
	t.Logf("7 tty handlers match four fields and order; %d raw captures reread; cache reused", captures)
}
