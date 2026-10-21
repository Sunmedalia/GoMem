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

func TestOfficialVMCoreInfo(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional VMCOREINFO physical-layer differential; not full capability acceptance")
	}
	for _, tc := range []struct {
		name, image, hash, reference string
		count                        int
	}{
		{"debian", filepath.Join(dir, "linux-sample-1.bin"), "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc", "reference-linux-vmcoreinfo-physical.json", 47},
		{"kali", os.Getenv("GOMEM_KALI_IMAGE"), "cf04d76ab9177d7ee355cc96020d29ae194c065c692304ff25e594ab510c639d", "reference-kali-vmcoreinfo.json", 111},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.image == "" {
				t.Skip("set GOMEM_KALI_IMAGE for the ARM64 LiME physical scan")
			}
			e := openVMCore(t, tc.image)
			if e.Hash != tc.hash {
				t.Fatal("corpus drift", e.Hash)
			}
			ctx := context.Background()
			result, err := e.Run(ctx, "linux.vmcoreinfo", nil, engine.RunOptions{})
			if err != nil || result.Task.State != "completed" {
				t.Fatal(result, err)
			}
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			reference, err := os.ReadFile(filepath.Join(dir, tc.reference))
			if err != nil {
				t.Fatal(err)
			}
			var expected []struct {
				Offset     uint64
				Key, Value string
			}
			if err = json.Unmarshal(reference, &expected); err != nil {
				t.Fatal(err)
			}
			if len(expected) != tc.count {
				t.Fatal(len(expected))
			}
			native := filepath.Join(t.TempDir(), "native.jsonl")
			file, err := os.Create(native)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			encoder := json.NewEncoder(file)
			entries, captures := 0, 0
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
				case "entry":
					if entries >= len(expected) {
						t.Fatal("extra entry", r)
					}
					ref := expected[entries]
					address, _ := r.Cells["Offset"].Uint()
					if address != ref.Offset || r.Cells["Key"].String() != ref.Key || r.Cells["Value"].String() != ref.Value {
						t.Fatal("ordered fields differ", r, ref)
					}
					entries++
					line, _ := r.Cells["LineOffset"].Uint()
					length, _ := r.Cells["LineLength"].Uint()
					raw, err := memory.Read(ctx, e.Env.Physical, line, int(length))
					if err != nil || !bytes.HasPrefix(raw, []byte(ref.Key+"=")) {
						t.Fatal(r, err)
					}
				case "note_observation":
					for _, key := range []string{"HeaderEvidence", "DescriptorEvidence"} {
						if r.Cells[key].Kind == "missing" {
							if key == "DescriptorEvidence" && r.Cells["Status"].String() == "header_mismatch" {
								continue
							}
							t.Fatal(r)
						}
						encoded, err := json.Marshal(r.Cells[key])
						if err != nil {
							t.Fatal(err)
						}
						var proof struct{ Value map[string]evidence.Value }
						if err = json.Unmarshal(encoded, &proof); err != nil {
							t.Fatal(err)
						}
						c := proof.Value
						address, err := c["Address"].Uint()
						if err != nil {
							t.Fatal(err)
						}
						raw, err := base64.StdEncoding.DecodeString(c["Raw"].Data.(string))
						if err != nil {
							t.Fatal(err)
						}
						got, err := memory.Read(ctx, e.Env.Physical, address, len(raw))
						if err != nil || !bytes.Equal(raw, got) || c["ReadComplete"].Data != true {
							t.Fatal(c, err)
						}
						captures++
					}
				case "summary":
					coverage := r.Cells["Coverage"].Data.(map[string]any)
					if coverage["candidates"] != map[string]string{"debian": "1", "kali": "3"}[tc.name] || coverage["rejected"] != map[string]string{"debian": "0", "kali": "2"}[tc.name] || coverage["tables"] != "1" || coverage["diagnostics"] != "0" {
						t.Fatal(coverage)
					}
				default:
					t.Fatal("unexpected record", r)
				}
			}
			if entries != tc.count || captures != map[string]int{"debian": 2, "kali": 4}[tc.name] {
				t.Fatal(entries, captures)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, tc.reference), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.vmcoreinfo.json"), "--output", filepath.Join(t.TempDir(), "diff.json")).CombinedOutput()
			if err != nil {
				t.Fatal(string(output), err)
			}
			cached, err := e.Run(ctx, "linux.vmcoreinfo", nil, engine.RunOptions{})
			if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
				t.Fatal(cached, err)
			}
			t.Logf("%s: %d entries match Offset/Key/Value and order; %d note captures and all raw lines reread; cache reused", tc.name, entries, captures)
		})
	}
}
