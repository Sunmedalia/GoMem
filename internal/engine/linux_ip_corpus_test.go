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

func TestOfficialLinuxIP(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian IP differential; not full capability acceptance")
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
	for _, name := range []string{"link", "addr"} {
		t.Run(name, func(t *testing.T) {
			result, err := e.Run(ctx, "linux.ip."+name, nil, engine.RunOptions{})
			if err != nil || result.Task.State != "completed" {
				t.Fatal(result, err)
			}
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			reference, err := os.ReadFile(filepath.Join(dir, "reference-linux-ip-"+name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var expected []map[string]any
			if err = json.Unmarshal(reference, &expected); err != nil {
				t.Fatal(err)
			}
			native := filepath.Join(t.TempDir(), "native.jsonl")
			file, err := os.Create(native)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			encoder := json.NewEncoder(file)
			entities, captures := 0, 0
			for _, r := range rows {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
				if err = encoder.Encode(r); err != nil {
					t.Fatal(err)
				}
				if kind := r.Cells["RecordType"].String(); kind == "diagnostic" {
					t.Fatal(r)
				} else if kind == "interface" || kind == "address" {
					if entities >= len(expected) {
						t.Fatal("extra entity", r)
					}
					ref := expected[entities]
					if r.Cells["Interface"].String() != ref["Interface"].(string) {
						t.Fatal("order differs", r)
					}
					if name == "addr" && r.Cells["IP"].String() != ref["IP"].(string) {
						t.Fatal("address order differs", r)
					}
					entities++
				}
				if r.Cells["Error"].Reason != "not_applicable" {
					t.Fatal(r)
				}
				if r.Cells["FieldEvidence"].Kind == "structure" {
					encoded, err := json.Marshal(r.Cells["FieldEvidence"])
					if err != nil {
						t.Fatal(err)
					}
					var fields struct {
						Value map[string]struct{ Value map[string]evidence.Value }
					}
					if err = json.Unmarshal(encoded, &fields); err != nil {
						t.Fatal(err)
					}
					for key, proof := range fields.Value {
						c := proof.Value
						address, err := c["Address"].Uint()
						if err != nil {
							t.Fatal(key, c, err)
						}
						raw, err := base64.StdEncoding.DecodeString(c["Raw"].Data.(string))
						if err != nil {
							t.Fatal(err)
						}
						got, err := memory.Read(ctx, e.Env.Kernel, address, len(raw))
						if err != nil || !bytes.Equal(raw, got) || c["ReadComplete"].Data != true {
							t.Fatal(key, c, err)
						}
						captures++
					}
				}
			}
			if entities != len(expected) {
				t.Fatal(entities, len(expected))
			}
			if captures == 0 {
				t.Fatal("no raw evidence")
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-ip-"+name+".json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.ip."+name+".json"), "--output", filepath.Join(t.TempDir(), "diff.json")).CombinedOutput()
			if err != nil {
				t.Fatal(string(output), err)
			}
			cached, err := e.Run(ctx, "linux.ip."+name, nil, engine.RunOptions{})
			if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
				t.Fatal(cached, err)
			}
			t.Logf("%s: %d entities match all upstream columns and order; %d raw captures reread; cache reused", name, entities, captures)
		})
	}
}
