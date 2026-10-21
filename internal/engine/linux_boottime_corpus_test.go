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

func TestOfficialLinuxBoottime(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian root boot time differential; not full capability acceptance")
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
	result, err := e.Run(ctx, "linux.boottime", nil, engine.RunOptions{})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result, err)
	}
	rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 10})
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	c := rows[0].Cells
	if c["Boot Time"].String() != "2014-06-24T10:22:33.691776Z" || c["BootTimeExact"].String() != "2014-06-24T10:22:33.691776031Z" || c["BootEpochNS"].String() != "1403605353691776031" || c["TIME NS"].Reason != "not_available" || c["NamespaceState"].String() != "legacy_no_time_namespace" || c["TimelineType"].String() != "CREATED" || c["TimelineDescription"].String() != "System boot time for time namespace None" {
		t.Fatal(c)
	}
	coverage := rows[1].Cells["Coverage"].Data.(map[string]any)
	for k, want := range map[string]string{"tasks": "133", "namespaces": "1", "times_read": "1", "duplicates": "132", "diagnostics": "0", "unparsable_times": "0"} {
		if coverage[k] != want {
			t.Fatal(coverage)
		}
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(file)
	for _, r := range rows {
		if err = r.Verify(); err != nil {
			t.Fatal(err)
		}
		if err = enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "diff.json")
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-boottime.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.boottime.json"), "--output", report).CombinedOutput()
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
	if err = json.Unmarshal(raw, &diff); err != nil || !diff.Matched || diff.NativeRows != 1 || diff.ReferenceRows != 1 {
		t.Fatal(string(raw), err)
	}
	again, err := e.Run(ctx, "linux.boottime", nil, engine.RunOptions{})
	if err != nil || !again.Reused {
		t.Fatal(again, err)
	}
	t.Log("one legacy namespace, exact epoch 1403605353691776031 ns; display matches unmodified reference at microsecond precision")
}
