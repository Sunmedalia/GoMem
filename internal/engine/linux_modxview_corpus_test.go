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

func TestOfficialLinuxModxview(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian module-source differential; not full capability acceptance")
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
	for _, plain := range []bool{false, true} {
		name := "default"
		reference := "reference-linux-modxview.json"
		params := map[string]string{}
		if plain {
			name = "plain"
			reference = "reference-linux-modxview-plain.json"
			params["plain-taints"] = "true"
		}
		t.Run(name, func(t *testing.T) {
			result, err := e.Run(ctx, "linux.modxview", params, engine.RunOptions{})
			if err != nil || result.Task.State != "completed" {
				t.Fatal(result, err)
			}
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
			if err != nil || len(rows) != 627 {
				t.Fatal(len(rows), err)
			}
			data, err := os.ReadFile(filepath.Join(dir, reference))
			if err != nil {
				t.Fatal(err)
			}
			var expected []struct {
				Name    string
				Address uint64
			}
			if err = json.Unmarshal(data, &expected); err != nil || len(expected) != 79 {
				t.Fatal(err, len(expected))
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
				if r.Cells["Error"].Reason != "not_applicable" {
					t.Fatal(r)
				}
				switch r.Cells["RecordType"].String() {
				case "module":
					if entities >= len(expected) {
						t.Fatal(r)
					}
					ref := expected[entities]
					address, _ := r.Cells["Address"].Uint()
					if ref.Name != r.Cells["Name"].String() || ref.Address != address&0xffffffffffff {
						t.Fatal("entity order differs", r, ref)
					}
					entities++
				case "summary":
					coverage := r.Cells["Coverage"].Data.(map[string]any)
					for k, v := range map[string]string{"modules": "79", "lsmod": "79", "sysfs": "79", "scanner": "79", "scan_positions": "587805", "scan_unreadable": "79919", "scan_self_matches": "101", "scan_rejected": "22", "diagnostics": "0", "read_layout_errors": "0"} {
						if coverage[k] != v {
							t.Fatal(k, coverage)
						}
					}
				case "module_observation", "source_observation", "sysfs_candidate", "source_selection", "scan_candidate":
				default:
					t.Fatal("unexpected record", r)
				}
				if r.Cells["FieldEvidence"].Kind == "structure" {
					raw, err := json.Marshal(r.Cells["FieldEvidence"])
					if err != nil {
						t.Fatal(err)
					}
					var fields struct {
						Value map[string]struct{ Value map[string]evidence.Value }
					}
					if err = json.Unmarshal(raw, &fields); err != nil {
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
						actual, err := memory.Read(ctx, e.Env.Kernel, address, len(raw))
						if err != nil || !bytes.Equal(raw, actual) || c["ReadComplete"].Data != true {
							t.Fatal(key, c, err)
						}
						captures++
					}
				}
			}
			if entities != 79 || captures != 1973 {
				t.Fatal(entities, captures)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, reference), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.modxview.json"), "--output", filepath.Join(t.TempDir(), "diff.json")).CombinedOutput()
			if err != nil {
				t.Fatal(string(output), err)
			}
			cached, err := e.Run(ctx, "linux.modxview", params, engine.RunOptions{})
			if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
				t.Fatal(cached, err)
			}
			t.Log("79 modules match all six columns and order; all three sources agree; 1973 raw captures reread; 22 rejected scan candidates retained; cache reused")
		})
	}
}
