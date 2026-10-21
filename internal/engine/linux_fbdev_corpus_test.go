package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// A zero-framebuffer real control validates traversal and acquisition, not detection
// of actual framebuffer pixels or complete plugin acceptance.
func TestOfficialLinuxFbdevEmptyControlEvidenceAndCache(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_FBDEV_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional corpus and pinned fbdev reference; skipped test is not acceptance")
	}
	raw, err := os.ReadFile(prefix + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline   struct{ Commit string }
		Image      string `json:"image_sha256"`
		Output     string `json:"output_sha256"`
		Plugin     string
		Parameters []string
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.graphics.fbdev" || len(manifest.Parameters) != 0 {
		t.Fatal(err, manifest)
	}
	raw, err = os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != manifest.Output {
		t.Fatal("reference digest mismatch")
	}
	var reference []json.RawMessage
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 0 {
		t.Fatal(err, len(reference))
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	reads, selected := 0, 0
	var fresh, cached bytes.Buffer
	result, err := e.Run(context.Background(), "linux.fbdev", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Verify() != nil {
			t.Fatal("invalid evidence seal")
		}
		switch row.Cells["RecordType"].String() {
		case "framebuffer":
			selected++
		case "framebuffer_read":
			reads++
			verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
		default:
			t.Fatal(row)
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || selected != 0 || reads != 1 {
		t.Fatal(result, err, reads, selected)
	}
	for offset := 0; offset < int(result.Task.Rows); {
		rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
		if err != nil || len(rows) == 0 {
			t.Fatal(err, offset)
		}
		for _, row := range rows {
			if row.Verify() != nil {
				t.Fatal("stored seal")
			}
		}
		offset += len(rows)
	}
	again, err := e.Run(context.Background(), "linux.fbdev", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
	if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
		t.Fatal(again, err)
	}
}

// The fixed baseline has no ARM64 translation layer. This positive native
// smoke test verifies acquisition/export, and is not an upstream differential.
func TestKaliARM64FbdevPositiveAcquisitionExportAndCache(t *testing.T) {
	imagePath, symbolPath := os.Getenv("GOMEM_FBDEV_KALI_IMAGE"), os.Getenv("GOMEM_FBDEV_KALI_SYMBOLS")
	if imagePath == "" || symbolPath == "" {
		t.Skip("requires optional Kali ARM64 image and symbols; not full acceptance")
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: imagePath, Symbols: symbolPath, Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "cf04d76ab9177d7ee355cc96020d29ae194c065c692304ff25e594ab510c639d" || e.Config.Arch != "arm64" {
		t.Fatal(e.Hash, e.Config.Arch)
	}
	reads, selected := 0, 0
	var fresh, cached bytes.Buffer
	result, err := e.Run(context.Background(), "linux.fbdev", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Verify() != nil {
			t.Fatal("seal")
		}
		switch row.Cells["RecordType"].String() {
		case "framebuffer_read":
			reads++
			verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
		case "framebuffer":
			selected++
			if row.Cells["ID"].String() != "virtio_gpudrmfb" || row.Cells["Device"].String() != "fb0" || row.Cells["Virtual resolution"].String() != "1024x768" || row.Cells["State"].String() != "RUNNING" {
				t.Fatal(row)
			}
		default:
			t.Fatal(row)
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || selected != 1 || reads != 28 {
		t.Fatal(result, err, reads, selected)
	}
	artifacts, err := e.Store.Artifacts(context.Background(), result.Task.ID)
	if err != nil || len(artifacts) != 1 || artifacts[0].State != "completed" || artifacts[0].MissingBytes != "0" {
		t.Fatal(artifacts, err)
	}
	if err = e.Store.VerifyTaskArtifacts(context.Background(), result.Task.ID); err != nil {
		t.Fatal(err)
	}
	// Verify original bytes separately, then derive expected RGBA without PNG encoding.
	source, err := memory.Read(context.Background(), e.Env.Kernel, 0xffff800082cb9000, 3145728)
	if err != nil {
		t.Fatal(err)
	}
	sourceHash := sha256.Sum256(source)
	if hex.EncodeToString(sourceHash[:]) != "b0078e539a764cab6234dc21344e639e0309929d8b109555e9ca1c8ff8e46360" {
		t.Fatal("source hash")
	}
	raw, err := os.ReadFile(filepath.Join(e.Config.CaseDir, artifacts[0].Path))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil || img.Bounds().Dx() != 1024 || img.Bounds().Dy() != 768 {
		t.Fatal(err)
	}
	// XRGB8888: baseline ignores the unused source alpha byte and defaults to 255.
	for y := 0; y < 768; y++ {
		for x := 0; x < 1024; x++ {
			at := (y*1024 + x) * 4
			v := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			if v.R != source[at+2] || v.G != source[at+1] || v.B != source[at] || v.A != 255 {
				t.Fatal("pixel differs", x, y)
			}
		}
	}
	rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
	if err != nil || len(rows) != 29 {
		t.Fatal(err, len(rows))
	}
	for _, row := range rows {
		if row.Verify() != nil {
			t.Fatal("stored seal")
		}
	}
	again, err := e.Run(context.Background(), "linux.fbdev", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
	if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
		t.Fatal(again, err)
	}
}
