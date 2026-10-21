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
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	rawReference, err := os.ReadFile(filepath.Join(dir, "reference-linux-mountinfo.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reference []struct {
		ID     int64  `json:"MOUNT ID"`
		Parent int64  `json:"PARENT_ID"`
		Point  string `json:"MOUNT_POINT"`
	}
	if err = json.Unmarshal(rawReference, &reference); err != nil || len(reference) != 13 {
		t.Fatal(err, len(reference))
	}
	var fresh, replay bytes.Buffer
	encoder := json.NewEncoder(file)
	mounts, captures := 0, 0
	verify := func(r evidence.Row) {
		if r.Cells["RecordType"].String() != "mount" {
			return
		}
		if mounts >= len(reference) {
			t.Fatal("extra mount", r)
		}
		ref := reference[mounts]
		id, err := r.Cells["MOUNT ID"].Int()
		if err != nil {
			t.Fatal(err)
		}
		parent, err := r.Cells["PARENT_ID"].Int()
		if err != nil {
			t.Fatal(err)
		}
		if id != ref.ID || parent != ref.Parent || r.Cells["MOUNT_POINT"].String() != ref.Point {
			t.Fatal("ordered mount mismatch", r, ref)
		}
		mounts++
		count := verifyModuleParameterWireCaptures(t, e, r.Cells["FieldEvidence"])
		if count < 7 {
			t.Fatal("mount captures not verified", count, r)
		}
		captures += count
	}
	result, err := e.Run(ctx, "linux.mountinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		verify(r)
		if err := json.NewEncoder(&fresh).Encode(r); err != nil {
			return err
		}
		return encoder.Encode(r)
	}})
	if err != nil || result.Task.State != "completed" || mounts != 13 || captures < 91 {
		t.Fatal(result, err, mounts, captures)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-mountinfo.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.mountinfo.json"), "--output", reportPath).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	reportRaw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Matched bool `json:"matched"`
	}
	if err = json.Unmarshal(reportRaw, &report); err != nil || !report.Matched {
		t.Fatal(string(reportRaw), err)
	}
	freshCaptures := captures
	mounts, captures = 0, 0
	cached, err := e.Run(ctx, "linux.mountinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error { verify(r); return json.NewEncoder(&replay).Encode(r) }})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID || !bytes.Equal(fresh.Bytes(), replay.Bytes()) || mounts != 13 || captures != freshCaptures {
		t.Fatal(cached, err)
	}
	t.Logf("13 mounts match detailed fields and order; %d raw captures reread; cache reused", captures)
}
