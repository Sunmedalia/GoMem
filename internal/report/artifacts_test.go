package report

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestArtifactExportsIncludeDataPaddingAndMetadata(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	task, err := s.Begin(ctx, "extract", "extract", evidence.Provenance{ImageSHA256: "image", Plugin: "extract"})
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.TaskArtifacts(task).Create(ctx, evidence.ArtifactRequest{Name: "x.bin", Size: 4})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("AB"))
	w.PadZero(ctx, 2, 2, "physical", io.EOF)
	a, err := w.Finish(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := evidence.Row{Cells: map[string]evidence.Value{"File": {Kind: "artifact", Data: a}}, Provenance: task.Provenance}
	row.Seal()
	s.Append(ctx, task.ID, []evidence.Row{row})
	s.Finish(ctx, task.ID, "completed", nil)
	file, err := Export(ctx, s, "bundle", "artifacts.zip", "")
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	members := map[string][]byte{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		members[f.Name] = b
	}
	var m Manifest
	if err = json.Unmarshal(members["manifest.json"], &m); err != nil || m.Schema != "gomem.evidence/v2" || m.ArtifactIndex == nil || m.ArtifactIndex.Rows != 1 {
		t.Fatal(m, err)
	}
	if string(members[a.Path]) != "AB\x00\x00" || len(members[a.GapsPath]) == 0 {
		t.Fatal("extraction or padding log omitted")
	}
	var record artifactRecord
	if err = json.Unmarshal(members["artifacts.jsonl"], &record); err != nil || !record.Included || record.Artifact.ID != a.ID {
		t.Fatal(record, err)
	}
	for _, format := range []string{"jsonl", "html"} {
		name, err := Export(ctx, s, format, "artifact."+format, "")
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(name)
		if err != nil || !strings.Contains(string(b), a.ID) || !strings.Contains(string(b), "completed_with_gaps") {
			t.Fatal(string(b), err)
		}
	}
	if err = os.WriteFile(filepath.Join(s.Dir, filepath.FromSlash(a.Path)), []byte("bad!"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Export(ctx, s, "bundle", "corrupt.zip", ""); err == nil {
		t.Fatal("corrupt file exported")
	}
	if _, err = os.Stat(filepath.Join(s.Dir, "exports", "corrupt.zip")); !os.IsNotExist(err) {
		t.Fatal("failed export left a misleading ZIP", err)
	}
}
