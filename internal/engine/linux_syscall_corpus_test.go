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

func TestOfficialLinuxSyscall(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian syscall differential without capstone; not complete acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("corpus drift", e.Hash)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-syscall.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []struct {
		Table        string `json:"Table Name"`
		TableAddress uint64 `json:"Table Address"`
		Index        uint64
		Handler      uint64 `json:"Handler Address"`
		Symbol       string `json:"Handler Symbol"`
	}
	if err = json.Unmarshal(raw, &expected); err != nil || len(expected) != 661 {
		t.Fatal(err, len(expected))
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	selected, captures := 0, 0
	result, err := e.Run(ctx, "linux.check_syscall", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		if err := encoder.Encode(r); err != nil {
			return err
		}
		if r.Cells["RecordType"].String() == "syscall" {
			if selected >= len(expected) {
				t.Fatal("extra syscall")
			}
			want := expected[selected]
			selected++
			table, _ := r.Cells["Table Address"].Uint()
			at, _ := r.Cells["Handler Address"].Uint()
			idx, _ := r.Cells["Index"].Uint()
			if table&0xffffffffffff != want.TableAddress || at&0xffffffffffff != want.Handler || idx != want.Index || r.Cells["Table Name"].String() != want.Table || r.Cells["Handler Symbol"].String() != want.Symbol {
				t.Fatal(want, table, at, idx, r.Cells["Table Name"], r.Cells["Handler Symbol"])
			}
		}
		if r.Cells["RecordType"].String() == "summary" {
			coverage := r.Cells["Coverage"].Data.(map[string]any)
			for k, v := range map[string]string{"tables_present": "2", "entry_visits": "661", "unknown_exact_symbols": "0", "diagnostics": "0", "read_layout_errors": "0", "native_disassembly": "unavailable"} {
				if coverage[k] != v {
					t.Fatal(k, coverage)
				}
			}
		}
		if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
			for key, proof := range fields {
				if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" {
					at, err := c["Address"].Uint()
					raw := c["Raw"].Data.([]byte)
					actual, readErr := memory.Read(ctx, e.Env.Kernel, at, len(raw))
					if err != nil || readErr != nil || !bytes.Equal(raw, actual) || c["ReadComplete"].Data != true {
						t.Fatal(key, err, readErr)
					}
					captures++
				}
			}
		}
		return nil
	}})
	if err != nil || result.Task.State != "completed" || selected != 661 || captures != 661 {
		t.Fatal(result, err, selected, captures)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-syscall.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.check_syscall.json")).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	cached, err := e.Run(ctx, "linux.check_syscall", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
		t.Fatal(cached, err)
	}
	t.Log("661 entries match five fields and order under the low48 mask; 661 pointer captures reread; no-capstone sizing; cache reused")
}
