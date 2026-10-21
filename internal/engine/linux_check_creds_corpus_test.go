package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxCheckCreds(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Debian credential-sharing negative control; not release acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("corpus drift", e.Hash)
	}
	result, err := e.Run(ctx, "linux.check_creds", nil, engine.RunOptions{})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result, err)
	}
	rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 500})
	if err != nil || len(rows) != 134 {
		t.Fatal(len(rows), err)
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(file)
	for i, row := range rows {
		if err = row.Verify(); err != nil {
			t.Fatal(err)
		}
		if i < 133 && (row.Cells["RecordType"].String() != "process" || row.Cells["CredRaw"].Kind != "bytes" || row.Cells["Error"].Kind != "missing") {
			t.Fatal(row)
		}
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	coverage := rows[133].Cells["Coverage"].Data.(map[string]any)
	for key, want := range map[string]string{"processes": "133", "checked": "133", "credential_objects": "133", "shared_groups": "0", "diagnostics": "0"} {
		if coverage[key] != want {
			t.Fatal(coverage)
		}
	}
	report := filepath.Join(t.TempDir(), "diff.json")
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-check-creds.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.check_creds.json"), "--output", report).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var diff struct {
		Matched       bool
		NativeRows    int `json:"native_rows"`
		ReferenceRows int `json:"reference_rows"`
	}
	if err = json.Unmarshal(raw, &diff); err != nil || !diff.Matched || diff.NativeRows != 0 || diff.ReferenceRows != 0 {
		t.Fatal(string(raw), err)
	}
	again, err := e.Run(ctx, "linux.check_creds", nil, engine.RunOptions{})
	if err != nil || !again.Reused {
		t.Fatal(again, err)
	}
	t.Log("133 readable distinct credentials, zero shared groups match unmodified reference; positive corpus still pending")
}
