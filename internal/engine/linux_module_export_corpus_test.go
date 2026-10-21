package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxModuleELFExports(t *testing.T) {
	dir, referenceDir := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_MODULE_ELF_REFERENCE_DIR")
	if dir == "" || referenceDir == "" {
		t.Skip("optional Debian module ELF differential requires GOMEM_CORPUS_DIR and GOMEM_MODULE_ELF_REFERENCE_DIR; not full acceptance")
	}
	raw, err := os.ReadFile(filepath.Join(referenceDir, "reference.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline    struct{ Commit string }
		ImageSHA256 string `json:"image_sha256"`
		Parameters  []string
		Files       []struct{ Name, Size, SHA256 string } `json:"extracted_files"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(manifest.Files) != 79 || len(manifest.Parameters) != 1 || manifest.Parameters[0] != "--dump" {
		t.Fatal(err, manifest)
	}
	reference := map[string]struct {
		size, sum string
		data      []byte
	}{}
	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(referenceDir, "reference-files", file.Name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 || strconv.Itoa(len(data)) != file.Size {
			t.Fatal("reference file integrity", file)
		}
		reference[file.Name] = struct {
			size, sum string
			data      []byte
		}{file.Size, file.SHA256, data}
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.ImageSHA256 || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash, manifest.ImageSHA256)
	}
	captures := 0
	result, err := e.Run(context.Background(), "linux.lsmod", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["File Output"].Kind != "artifact" {
			t.Fatal(row)
		}
		fields := bashProofFields(t, row.Cells["DumpEvidence"])
		captures += verifyModuleParameterWireCaptures(t, e, fields["SymbolTableRaw"])
		return row.Verify()
	}})
	// Six pre-existing parameter-array displays fail independently of ELF output.
	if err == nil || result.Task.State != "failed" || result.Task.Rows != 79 || captures != 79 {
		t.Fatal(result, err, captures)
	}
	artifacts, err := e.Store.Artifacts(context.Background(), result.Task.ID)
	if err != nil || len(artifacts) != 79 {
		t.Fatal(len(artifacts), err)
	}
	totalGaps, totalMissing := 0, uint64(0)
	seen := map[string]bool{}
	for _, a := range artifacts {
		ref, ok := reference[a.Name]
		if !ok || seen[a.Name] || a.Size != ref.size || a.SHA256 != ref.sum || a.State != "completed_with_gaps" || a.Provenance.ImageSHA256 != e.Hash {
			t.Fatal(a, ok)
		}
		seen[a.Name] = true
		data, err := os.ReadFile(filepath.Join(e.Config.CaseDir, a.Path))
		if err != nil || !bytes.Equal(data, ref.data) {
			t.Fatal("extracted bytes", a.Name, err)
		}
		gapRaw, err := os.ReadFile(filepath.Join(e.Config.CaseDir, a.GapsPath))
		if err != nil {
			t.Fatal(err)
		}
		missing := uint64(0)
		gapCount := 0
		end := uint64(0)
		for _, line := range bytes.Split(bytes.TrimSpace(gapRaw), []byte{'\n'}) {
			var gap evidence.ArtifactGap
			if err = json.Unmarshal(line, &gap); err != nil {
				t.Fatal(err)
			}
			offset, err := strconv.ParseUint(gap.Offset, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			length, err := strconv.ParseUint(gap.Length, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			address, err := strconv.ParseUint(gap.Address, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			if length == 0 || offset < end || offset > uint64(len(data)) || length > uint64(len(data))-offset || gap.Layer != e.Env.Kernel.Name() || gap.Error == "" {
				t.Fatal(gap)
			}
			if !bytes.Equal(data[offset:offset+length], make([]byte, length)) {
				t.Fatal("padding is not zero", gap)
			}
			buf := make([]byte, length)
			got, readErr := e.Env.Kernel.ReadAt(context.Background(), buf, address)
			if got != 0 || readErr == nil {
				t.Fatal("gap source is readable", gap, got, readErr)
			}
			missing += length
			end = offset + length
			gapCount++
		}
		if strconv.FormatUint(missing, 10) != a.MissingBytes || strconv.Itoa(gapCount) != a.GapCount {
			t.Fatal(a, missing, gapCount)
		}
		totalMissing += missing
		totalGaps += gapCount
	}
	if err = e.Store.VerifyTaskArtifacts(context.Background(), result.Task.ID); err != nil {
		t.Fatal(err)
	}
	t.Logf("79 reference files byte-identical; 79 original symbol tables independently reread; %d gap ranges/%d missing bytes independently verified", totalGaps, totalMissing)
}
