package report

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestExportsPreserveEvidenceAndEscapeHTML(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := evidence.Provenance{ImageSHA256: "image", Plugin: "fixture", Layer: "physical"}
	task, _ := s.Begin(ctx, "key", "fixture", p)
	r := evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Text(`<script>alert("evidence")</script>`), "Address": evidence.Address(^uint64(0))}, Provenance: p}
	r.Seal()
	if err = s.Append(ctx, task.ID, []evidence.Row{r}); err != nil {
		t.Fatal(err)
	}
	s.Finish(ctx, task.ID, "completed", nil)
	html, err := Export(ctx, s, "html", "report.html", "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(html)
	if strings.Contains(string(body), "<script>") || !strings.Contains(string(body), r.ID) {
		t.Fatal("unescaped or missing evidence")
	}
	if _, err = Export(ctx, s, "html", "report.html", ""); err == nil {
		t.Fatal("overwrote report")
	}
	if _, err = Export(ctx, s, "html", "../outside.html", ""); err == nil {
		t.Fatal("accepted path escape")
	}
	bundle, err := Export(ctx, s, "bundle", "evidence.zip", "")
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var manifest Manifest
	var data []byte
	for _, f := range z.File {
		stream, _ := f.Open()
		b, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		if f.Name == "manifest.json" {
			if err = json.Unmarshal(b, &manifest); err != nil {
				t.Fatal(err)
			}
		} else {
			data = b
		}
	}
	if len(manifest.Entries) != 1 || len(manifest.Tasks) != 1 {
		t.Fatal(manifest)
	}
	sum := sha256.Sum256(data)
	if manifest.Entries[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("bad bundle checksum")
	}
	var back evidence.Row
	if err = json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != r.ID || back.Cells["Address"].String() != r.Cells["Address"].String() {
		t.Fatal("evidence changed")
	}
}
