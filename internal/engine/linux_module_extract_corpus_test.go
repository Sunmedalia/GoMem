package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxModuleExtract(t *testing.T) {
	dir, referenceDir := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_MODULE_EXTRACT_REFERENCE_DIR")
	if dir == "" || referenceDir == "" {
		t.Skip("optional direct module extraction requires GOMEM_CORPUS_DIR and GOMEM_MODULE_EXTRACT_REFERENCE_DIR; not full acceptance")
	}
	raw, err := os.ReadFile(filepath.Join(referenceDir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	var profiles []struct{ Label, Module, Base string }
	if err = json.Unmarshal(raw, &profiles); err != nil || len(profiles) != 3 {
		t.Fatal(err, len(profiles))
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	for _, profile := range profiles {
		t.Run(profile.Label, func(t *testing.T) {
			base, err := strconv.ParseUint(profile.Base, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(referenceDir, profile.Label+".manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Baseline   struct{ Commit string }
				Image      string `json:"image_sha256"`
				Plugin     string
				Parameters []string
				Files      []struct{ Name, Size, SHA256 string } `json:"extracted_files"`
			}
			if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Image != e.Hash || manifest.Plugin != "linux.module_extract" || len(manifest.Files) != 1 || len(manifest.Parameters) != 2 || manifest.Parameters[0] != "--base" || manifest.Parameters[1] != profile.Base {
				t.Fatal(manifest, err)
			}
			ref := manifest.Files[0]
			refData, err := os.ReadFile(filepath.Join(referenceDir, profile.Label+"-files", ref.Name))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(refData)
			if hex.EncodeToString(sum[:]) != ref.SHA256 || strconv.Itoa(len(refData)) != ref.Size {
				t.Fatal(ref)
			}
			var fresh, replay bytes.Buffer
			check := func(row evidence.Row) {
				if err := row.Verify(); err != nil {
					t.Fatal(err)
				}
				got, err := row.Cells["Base"].Uint()
				if err != nil || got != base || row.Cells["Name"].String() != profile.Module {
					t.Fatal(row, err)
				}
				if count := verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"]); count != 2 {
					t.Fatal("probe/name", count)
				}
				fields := bashProofFields(t, row.Cells["DumpEvidence"])
				if count := verifyModuleParameterWireCaptures(t, e, fields["SymbolTableRaw"]); count != 1 {
					t.Fatal("original symbols", count)
				}
			}
			result, err := e.Run(context.Background(), "linux.module_extract", map[string]string{"base": profile.Base}, engine.RunOptions{Emit: func(row evidence.Row) error { check(row); return json.NewEncoder(&fresh).Encode(row) }})
			if err != nil || result.Task.State != "completed" || result.Task.Rows != 1 {
				t.Fatal(result, err)
			}
			artifacts, err := e.Store.Artifacts(context.Background(), result.Task.ID)
			if err != nil || len(artifacts) != 1 {
				t.Fatal(artifacts, err)
			}
			a := artifacts[0]
			if a.Name != ref.Name || a.Size != ref.Size || a.SHA256 != ref.SHA256 || a.State != "completed_with_gaps" {
				t.Fatal(a, ref)
			}
			data, err := os.ReadFile(filepath.Join(e.Config.CaseDir, a.Path))
			if err != nil || !bytes.Equal(data, refData) {
				t.Fatal("extracted bytes differ", err)
			}
			if err = e.Store.VerifyTaskArtifacts(context.Background(), result.Task.ID); err != nil {
				t.Fatal(err)
			}
			native := filepath.Join(t.TempDir(), "native.jsonl")
			if err = os.WriteFile(native, fresh.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			reportPath := filepath.Join(t.TempDir(), "diff.json")
			output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(referenceDir, profile.Label+".json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.module_extract.json"), "--output", reportPath).CombinedOutput()
			if err != nil {
				t.Fatal(string(output), err)
			}
			reportRaw, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var report struct{ Matched bool }
			if err = json.Unmarshal(reportRaw, &report); err != nil || !report.Matched {
				t.Fatal(string(reportRaw), err)
			}
			cached, err := e.Run(context.Background(), "linux.module_extract", map[string]string{"base": profile.Base}, engine.RunOptions{Emit: func(row evidence.Row) error { check(row); return json.NewEncoder(&replay).Encode(row) }})
			if err != nil || !cached.Reused || !bytes.Equal(fresh.Bytes(), replay.Bytes()) {
				t.Fatal(cached, err)
			}
			t.Logf("Base, size, filename and %s ELF bytes match; artifact/probe/name/symbol evidence verified; cache identical", a.Size)
		})
	}
}
