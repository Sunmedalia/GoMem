package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialLinuxPtrace(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian ptrace negative and instrumented enumeration differential; not positive or full acceptance")
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
	result, err := e.Run(ctx, "linux.ptrace", nil, engine.RunOptions{})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result, err)
	}
	rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
	if err != nil || len(rows) != 317 {
		t.Fatal(err, len(rows))
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	identities := map[string]bool{}
	processes := map[string]bool{}
	captures, threads := 0, 0
	for _, r := range rows {
		if err = r.Verify(); err != nil {
			t.Fatal(err)
		}
		if err = encoder.Encode(r); err != nil {
			t.Fatal(err)
		}
		switch r.Cells["RecordType"].String() {
		case "task":
			for _, name := range []string{"Tracer TID", "Tracee TID", "Flags"} {
				if r.Cells[name].Reason != "not_available" {
					t.Fatal(r)
				}
			}
			if r.Cells["IsBeingTraced"].Data != false || r.Cells["IsTracer"].Data != false || r.Cells["PtraceRaw"].String() != "0" || r.Cells["Error"].Reason != "not_applicable" {
				t.Fatal(r)
			}
			identity := r.Cells["TaskIdentity"].String()
			if identities[identity] {
				t.Fatal("duplicate identity", r)
			}
			identities[identity] = true
			processes[r.Cells["ProcessOffset"].String()] = true
			if r.Cells["ProcessOffset"].String() != r.Cells["Offset"].String() {
				threads++
			}
			raw, err := json.Marshal(r.Cells["FieldEvidence"])
			if err != nil {
				t.Fatal(err)
			}
			var fields struct {
				Value map[string]struct{ Value map[string]evidence.Value }
			}
			if err = json.Unmarshal(raw, &fields); err != nil || len(fields.Value) < 6 {
				t.Fatal(err, string(raw))
			}
			for _, field := range fields.Value {
				address, err := field.Value["Address"].Uint()
				if err != nil {
					t.Fatal(err)
				}
				encoded, ok := field.Value["Raw"].Data.(string)
				if !ok {
					t.Fatal(field)
				}
				capture, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := memory.Read(ctx, e.Env.Kernel, address, len(capture))
				if err != nil || !bytes.Equal(capture, actual) || field.Value["ReadComplete"].Data != true {
					t.Fatal(field, err)
				}
				captures++
			}
		case "summary":
			coverage := r.Cells["Coverage"].Data.(map[string]any)
			for key, want := range map[string]string{"tasks": "316", "checked": "316", "selected": "0", "traced_tasks": "0", "tracer_tasks": "0", "relationships": "0", "tracee_entries": "0", "diagnostics": "0"} {
				if coverage[key] != want {
					t.Fatal(coverage)
				}
			}
		default:
			t.Fatal("unexpected record", r)
		}
	}
	if len(identities) != 316 || len(processes) != 133 || threads != 183 || captures != 2262 {
		t.Fatal(len(identities), len(processes), threads, captures)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ptrace", "ptrace-observations"} {
		output, err := exec.Command("python3", "../../tools/diff_results.py", "--native", native, "--reference", filepath.Join(dir, "reference-linux-"+name+".json"), "--mapping", "../../docs/diff/linux."+name+".json", "--output", filepath.Join(t.TempDir(), "diff.json")).CombinedOutput()
		if err != nil {
			t.Fatal(string(output), err)
		}
	}
	var manifest struct {
		Probe  string `json:"probe_sha256"`
		Output string `json:"output_sha256"`
		Calls  int    `json:"listing_calls"`
		Tasks  int    `json:"observed_tasks"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-ptrace-observations.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Calls != 1 || manifest.Tasks != 316 {
		t.Fatal(string(raw), err)
	}
	for path, want := range map[string]string{"../../tools/reference_ptrace_observations.py": manifest.Probe, filepath.Join(dir, "reference-linux-ptrace-observations.json"): manifest.Output} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("probe or output drift", path)
		}
	}
	again, err := e.Run(ctx, "linux.ptrace", nil, engine.RunOptions{})
	if err != nil || !again.Reused {
		t.Fatal(again, err)
	}
	t.Log("negative control: zero relationships, 133 leaders + 183 threads; all 316 observations match instrumented task yields; 2262 raw captures reread")
}
