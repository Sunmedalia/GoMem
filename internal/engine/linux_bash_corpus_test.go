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
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// Decode through the wire format: sealing/persistence can turn nested Values
// into generic JSON maps. A failed type assertion must never skip a capture.
func bashProofFields(t *testing.T, v evidence.Value) map[string]evidence.Value {
	t.Helper()
	raw, err := json.Marshal(v.Data)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]evidence.Value
	if err = json.Unmarshal(raw, &fields); err != nil || len(fields) == 0 {
		t.Fatal(v, err)
	}
	return fields
}

func bashVerifyProcessCaptures(t *testing.T, ctx context.Context, e *engine.Engine, r evidence.Row) int {
	t.Helper()
	task, err := r.Cells["Task"].Uint()
	if err != nil {
		t.Fatal(err)
	}
	mm, err := e.Env.Objects.Uint(ctx, task, "task_struct", "mm")
	if err != nil {
		t.Fatal(err)
	}
	pgd, err := e.Env.Objects.Uint(ctx, mm, "mm_struct", "pgd")
	if err != nil {
		t.Fatal(err)
	}
	kernel, ok := e.Env.Kernel.(*memory.Virtual)
	if !ok {
		t.Fatal("missing kernel translator")
	}
	root, err := kernel.Translator.Translate(ctx, pgd)
	if err != nil {
		t.Fatal(err)
	}
	translator, err := memory.NewIntelForOS(e.Env.Physical, root.Physical, e.Env.Architecture, e.Env.OS, 1024)
	if err != nil {
		t.Fatal(err)
	}
	layer := &memory.Virtual{Physical: e.Env.Physical, Translator: translator, ID: r.Provenance.Layer}
	if layer.Name() != "process:"+r.Cells["ProcessIdentity"].String() {
		t.Fatal("process identity mismatch", r)
	}
	fields := bashProofFields(t, r.Cells["FieldEvidence"])
	if len(fields) != 3 {
		t.Fatal("missing history captures", fields)
	}
	for _, name := range []string{"EntryPointers", "Line", "Timestamp"} {
		c := bashProofFields(t, fields[name])
		at, err := c["Address"].Uint()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(c["Raw"].String())
		if err != nil || len(raw) == 0 {
			t.Fatal(c, err)
		}
		captured, err := c["CapturedBytes"].Uint()
		if err != nil || captured != uint64(len(raw)) {
			t.Fatal(c, err)
		}
		requested, err := c["RequestedBytes"].Uint()
		if err != nil || requested != captured || c["ReadComplete"].Data != true {
			t.Fatal(c, err)
		}
		actual, err := memory.Read(ctx, layer, at, len(raw))
		if err != nil || !bytes.Equal(raw, actual) {
			t.Fatalf("%s at %#x: capture differs from process memory: %v", name, at, err)
		}
	}
	return len(fields)
}

func TestOfficialLinuxBash(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian bash differential")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	type displayed struct {
		PID                           uint64
		Process, CommandTime, Command string
	}
	var reference []displayed
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-bash.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 27 {
		t.Fatal(len(reference), err)
	}
	for i := range reference {
		when, err := time.Parse(time.RFC3339, reference[i].CommandTime)
		if err != nil {
			t.Fatal(err)
		}
		reference[i].CommandTime = when.UTC().Format(time.RFC3339)
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var fresh, cachedBytes bytes.Buffer
	history, captures, coverage := 0, 0, 0
	verify := func(r evidence.Row) {
		switch r.Cells["RecordType"].String() {
		case "history":
			if history >= len(reference) {
				t.Fatal("extra history row", r)
			}
			pid, err := r.Cells["PID"].Uint()
			if err != nil {
				t.Fatal(err)
			}
			got := displayed{pid, r.Cells["Process"].String(), r.Cells["CommandTime"].String(), r.Cells["Command"].String()}
			if got != reference[history] {
				t.Fatalf("ordered row %d: got %+v; want %+v", history, got, reference[history])
			}
			history++
			captures += bashVerifyProcessCaptures(t, ctx, e, r)
		case "coverage":
			coverage++
			raw, err := json.Marshal(r.Cells["Coverage"].Data)
			if err != nil {
				t.Fatal(err)
			}
			var c map[string]string
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			if c["unmapped_bytes"] != "0" {
				t.Fatal("incomplete heap coverage", c)
			}
		case "summary":
		default:
			t.Fatal("unexpected record", r)
		}
	}
	result, err := e.Run(ctx, "linux.bash", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		verify(r)
		if err := json.NewEncoder(file).Encode(r); err != nil {
			return err
		}
		return json.NewEncoder(&fresh).Encode(r)
	}})
	if err != nil || result.Task.State != "completed" || history != 27 || captures != 81 || coverage != 3 {
		t.Fatal(result, err, history, captures, coverage)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-bash.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.bash.json")).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	history, captures, coverage = 0, 0, 0
	cached, err := e.Run(ctx, "linux.bash", nil, engine.RunOptions{Emit: func(r evidence.Row) error { verify(r); return json.NewEncoder(&cachedBytes).Encode(r) }})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID || !bytes.Equal(fresh.Bytes(), cachedBytes.Bytes()) || history != 27 || captures != 81 || coverage != 3 {
		t.Fatal(cached, err, history, captures, coverage)
	}
	t.Log("27 ordered history rows match; 81 captures re-read in process space on fresh and cached results; cached JSONL identical")
}
