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

func TestOfficialLinuxPsTree(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian hierarchy differential; not full capability acceptance")
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
	for _, tc := range []struct {
		name            string
		params          map[string]string
		count, captures int
	}{{"pstree", nil, 133, 665}, {"pstree-threads", map[string]string{"threads": "true", "decorate-comm": "true"}, 316, 2262}, {"pstree-filtered", map[string]string{"threads": "true", "decorate-comm": "true", "pid": "3924"}, 3, 22}} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := e.Run(ctx, "linux.pstree", tc.params, engine.RunOptions{})
			if err != nil || result.Task.State != "completed" {
				t.Fatal(result, err)
			}
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
			if err != nil || len(rows) != tc.count*3+1 {
				t.Fatal(err, len(rows))
			}
			native := filepath.Join(t.TempDir(), "native.jsonl")
			file, err := os.Create(native)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			encoder := json.NewEncoder(file)
			captures := 0
			known := map[string]bool{}
			var tids []string
			for _, r := range rows {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
				if err = encoder.Encode(r); err != nil {
					t.Fatal(err)
				}
				switch r.Cells["RecordType"].String() {
				case "observation":
					if r.Cells["Error"].Reason != "not_applicable" || r.Cells["HierarchyState"].String() != "candidate" {
						t.Fatal(r)
					}
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
				case "selection":
					if r.Cells["HierarchyState"].String() != "included" {
						t.Fatal(r)
					}
				case "process":
					if r.ParentID != "" && !known[r.ParentID] {
						t.Fatal("parent absent", r)
					}
					known[r.ID] = true
					tids = append(tids, r.Cells["TID"].String())
					if tc.name == "pstree-filtered" && len(tids) == 1 && (r.ParentID != "" || r.Cells["TID"].String() != "3924" || r.Cells["Depth"].String() != "0") {
						t.Fatal("filtered group should start at a new root", r)
					}
				case "summary":
					coverage := r.Cells["Coverage"].Data.(map[string]any)
					if coverage["diagnostics"] != "0" || coverage["excluded_tids"] != "0" || coverage["duplicates"] != "0" {
						t.Fatal(coverage)
					}
				default:
					t.Fatal("unexpected record", r)
				}
			}
			if captures != tc.captures {
				t.Fatal(captures, tc.captures)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			reference := filepath.Join(dir, "reference-linux-"+tc.name+".json")
			raw, err := os.ReadFile(reference)
			if err != nil {
				t.Fatal(err)
			}
			var tree []map[string]json.RawMessage
			if err = json.Unmarshal(raw, &tree); err != nil {
				t.Fatal(err)
			}
			var order []string
			var walk func([]map[string]json.RawMessage)
			walk = func(nodes []map[string]json.RawMessage) {
				for _, n := range nodes {
					var tid json.Number
					if err = json.Unmarshal(n["TID"], &tid); err != nil {
						t.Fatal(err)
					}
					order = append(order, string(tid))
					var children []map[string]json.RawMessage
					if err = json.Unmarshal(n["__children"], &children); err != nil {
						t.Fatal(err)
					}
					walk(children)
				}
			}
			walk(tree)
			if len(order) != len(tids) {
				t.Fatal(order, tids)
			}
			for i, tid := range tids {
				if order[i] != tid {
					t.Fatal("enumeration order differs", i, order[i], tid)
				}
			}
			output, err := exec.Command("python3", "../../tools/diff_results.py", "--native", native, "--reference", reference, "--mapping", "../../docs/diff/linux.pstree.json", "--output", filepath.Join(t.TempDir(), "diff.json")).CombinedOutput()
			if err != nil {
				t.Fatal(string(output), err)
			}
			again, err := e.Run(ctx, "linux.pstree", tc.params, engine.RunOptions{})
			if err != nil || !again.Reused {
				t.Fatal(again, err)
			}
			t.Logf("%d ordered tree rows and full ancestor paths match; %d raw captures reread", tc.count, captures)
		})
	}
}
