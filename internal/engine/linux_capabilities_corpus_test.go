package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// The reference run requires an explicit legacy typedef adapter. This verifies
// helper/field agreement, never unmodified plugin or full release acceptance.
func TestOfficialLinuxCapabilitiesLayoutAdapter(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian capability helper comparison with explicit layout adapter; not unmodified plugin parity")
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
	for _, filtered := range []bool{false, true} {
		t.Run(fmt.Sprint(filtered), func(t *testing.T) {
			params := map[string]string{}
			reference := "adapter-linux-capabilities.json"
			count := 133
			if filtered {
				params["pids"] = "1,2388,2575,3754,8503"
				reference = "adapter-linux-capabilities-filtered.json"
				count = 5
			}
			manifestBytes, err := os.ReadFile(filepath.Join(dir, reference[:len(reference)-5]+".manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Scope       string
				ImageSHA    string `json:"image_sha256"`
				OutputSHA   string `json:"output_sha256"`
				Rows        int
				Adaptations int
				AdapterSHA  string `json:"adapter_sha256"`
				Baseline    struct {
					Commit  string
					TreeSHA string `json:"python_tree_sha256"`
				}
			}
			if err = json.Unmarshal(manifestBytes, &manifest); err != nil || manifest.Scope != "explicit legacy capability layout adapter; NOT unmodified plugin parity" || manifest.Rows != count || manifest.Adaptations == 0 || manifest.ImageSHA != e.Hash {
				t.Fatal(manifest, err)
			}
			adapterBytes, err := os.ReadFile(filepath.Join("..", "..", "tools", "reference_capabilities_layout_adapter.py"))
			if err != nil {
				t.Fatal(err)
			}
			adapterSum := sha256.Sum256(adapterBytes)
			if hex.EncodeToString(adapterSum[:]) != manifest.AdapterSHA || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Baseline.TreeSHA != "3da726508f5b4dedf56f3ce83063ab66944b973af2504d10816f9d824ad5530d" {
				t.Fatal("adapter/baseline identity drift", manifest)
			}
			referenceBytes, err := os.ReadFile(filepath.Join(dir, reference))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(referenceBytes)
			if hex.EncodeToString(sum[:]) != manifest.OutputSHA {
				t.Fatal("adapted reference drift")
			}
			result, err := e.Run(ctx, "linux.capabilities", params, engine.RunOptions{})
			if err != nil || result.Task.State != "completed" {
				t.Fatal(result, err)
			}
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 500})
			if err != nil || len(rows) != count+1 {
				t.Fatal(len(rows), err)
			}
			native := filepath.Join(t.TempDir(), "native.jsonl")
			file, err := os.Create(native)
			if err != nil {
				t.Fatal(err)
			}
			enc := json.NewEncoder(file)
			effectiveFull := 0
			for _, row := range rows {
				if err = row.Verify(); err != nil {
					t.Fatal(err)
				}
				if err = enc.Encode(row); err != nil {
					t.Fatal(err)
				}
				if row.Cells["RecordType"].String() == "summary" {
					continue
				}
				if row.Cells["CapLast"].String() != "35" || row.Cells["cap_ambient"].Reason != "not_available" || row.Cells["Error"].Kind != "missing" {
					t.Fatal(row)
				}
				if row.Cells["cap_effective"].String() == "all" {
					effectiveFull++
				}
				var captures map[string]evidence.Value
				raw, err := json.Marshal(row.Cells["CapabilityEvidence"].Data)
				if err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(raw, &captures); err != nil {
					t.Fatal(err)
				}
				if len(captures) != 4 {
					t.Fatal(captures)
				}
				for _, entry := range captures {
					var capture map[string]evidence.Value
					rawEntry, err := json.Marshal(entry.Data)
					if err != nil {
						t.Fatal(err)
					}
					if err = json.Unmarshal(rawEntry, &capture); err != nil {
						t.Fatal(err)
					}
					encoded, ok := capture["Raw"].Data.(string)
					if !ok {
						t.Fatal(capture)
					}
					raw, err := base64.StdEncoding.DecodeString(encoded)
					if err != nil || len(raw) != 8 {
						t.Fatal(capture, err)
					}
					address, err := capture["Address"].Uint()
					if err != nil {
						t.Fatal(err)
					}
					actual, err := memory.Read(ctx, e.Env.Kernel, address, 8)
					if err != nil || string(actual) != string(raw) {
						t.Fatal("raw bitmap differs from image", err)
					}
					value, err := capture["Unmasked"].Uint()
					if err != nil || value != binary.LittleEndian.Uint64(actual) {
						t.Fatal(capture, err)
					}
					masked, err := capture["Masked"].Uint()
					if err != nil || masked != value&0xfffffffff {
						t.Fatal(capture, err)
					}
				}
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			if !filtered && effectiveFull != 85 {
				t.Fatal(effectiveFull)
			}
			coverage := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
			if coverage["processes"] != fmt.Sprint(count) || coverage["sets_read"] != fmt.Sprint(count*4) || coverage["ambient_not_available"] != fmt.Sprint(count) || coverage["diagnostics"] != "0" {
				t.Fatal(coverage)
			}
			report := filepath.Join(t.TempDir(), "diff.json")
			output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, reference), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.capabilities-layout-adapter.json"), "--output", report).CombinedOutput()
			if err != nil {
				t.Fatal(string(output), err)
			}
			data, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var diff struct {
				Matched       bool
				NativeRows    int `json:"native_rows"`
				ReferenceRows int `json:"reference_rows"`
			}
			if err = json.Unmarshal(data, &diff); err != nil || !diff.Matched || diff.NativeRows != count || diff.ReferenceRows != count {
				t.Fatal(string(data), err)
			}
			again, err := e.Run(ctx, "linux.capabilities", params, engine.RunOptions{})
			if err != nil || !again.Reused {
				t.Fatal(again, err)
			}
			t.Logf("%d tasks, %d sets match adapted helpers; unmodified plugin parity remains unverified", count, count*4)
		})
	}
}
