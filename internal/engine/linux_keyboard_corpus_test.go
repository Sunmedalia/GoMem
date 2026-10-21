package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxKeyboardNotifiers(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian empty keyboard-notifier applicability check")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("corpus drift")
	}
	ref, err := os.ReadFile(filepath.Join(dir, "reference-linux-keyboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []any
	if err = json.Unmarshal(ref, &expected); err != nil || len(expected) != 0 {
		t.Fatal(err, len(expected))
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	nulls := 0
	result, err := e.Run(ctx, "linux.keyboard_notifiers", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		if err := encoder.Encode(r); err != nil {
			return err
		}
		if r.Cells["RecordType"].String() == "notifier" && r.Cells["Status"].String() == "null_callback_unreadable" {
			nulls++
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || nulls != 1 {
		t.Fatal(result, err, nulls)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := e.Run(ctx, "linux.keyboard_notifiers", nil, engine.RunOptions{})
	if err == nil || again.Reused || again.Task.State != "failed" {
		t.Fatal(again, err)
	}
	t.Log("empty reference table matches; native records the unreadable zero callback and does not cache failure as success")
}
