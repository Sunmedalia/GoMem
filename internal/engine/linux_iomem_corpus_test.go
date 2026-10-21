package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialLinuxIOMem(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian resource tree differential; not full capability acceptance")
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
	result, err := e.Run(ctx, "linux.iomem", nil, engine.RunOptions{})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result, err)
	}
	rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
	if err != nil || len(rows) != 117 {
		t.Fatal(err, len(rows))
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	known := map[string]bool{}
	captures := 0
	check := func(c map[string]evidence.Value) {
		address, err := c["Address"].Uint()
		if err != nil {
			t.Fatal(c)
		}
		encoded, ok := c["Raw"].Data.(string)
		if !ok {
			t.Fatal(c)
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := memory.Read(ctx, e.Env.Kernel, address, len(raw))
		if err != nil || !bytes.Equal(raw, actual) || c["ReadComplete"].Data != true {
			t.Fatal(c, err)
		}
		captures++
	}
	for _, r := range rows {
		if err = r.Verify(); err != nil {
			t.Fatal(err)
		}
		if err = encoder.Encode(r); err != nil {
			t.Fatal(err)
		}
		switch r.Cells["RecordType"].String() {
		case "resource":
			if r.ParentID != "" && !known[r.ParentID] {
				t.Fatal("missing parent", r)
			}
			known[r.ID] = true
			if r.Cells["Error"].Reason != "not_applicable" {
				t.Fatal(r)
			}
			raw, err := json.Marshal(r.Cells["FieldEvidence"])
			if err != nil {
				t.Fatal(err)
			}
			var fields struct {
				Value map[string]struct{ Value map[string]evidence.Value }
			}
			if err = json.Unmarshal(raw, &fields); err != nil || len(fields.Value) != 5 {
				t.Fatal(err, string(raw))
			}
			for _, c := range fields.Value {
				check(c.Value)
			}
			raw, err = json.Marshal(r.Cells["NameEvidence"])
			if err != nil {
				t.Fatal(err)
			}
			var name struct{ Value map[string]evidence.Value }
			if err = json.Unmarshal(raw, &name); err != nil {
				t.Fatal(err)
			}
			check(name.Value)
		case "summary":
			coverage := r.Cells["Coverage"].Data.(map[string]any)
			if coverage["resources"] != "116" || coverage["diagnostics"] != "0" || coverage["visits"] != "116" {
				t.Fatal(coverage)
			}
		default:
			t.Fatal("unexpected record", r)
		}
	}
	if captures != 696 {
		t.Fatal(captures)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "diff.json")
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-iomem.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.iomem.json"), "--output", report).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	again, err := e.Run(ctx, "linux.iomem", nil, engine.RunOptions{})
	if err != nil || !again.Reused {
		t.Fatal(again, err)
	}
	t.Log("116 resources; Name/Start/End/depth and complete ancestor paths match; 696 raw captures reread; no diagnostics")
}
