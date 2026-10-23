package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func verificationFixture(t *testing.T, count int) (*Store, evidence.Task, []evidence.Row) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p := evidence.Provenance{ImageSHA256: "image", Engine: "0.1.0-dev", EngineBuild: "build", Plugin: "test", Layer: "kernel", Parameters: map[string]string{"mode": "test"}}
	task, err := s.Begin(context.Background(), "key", p.Plugin, p)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]evidence.Row, count)
	for i := range rows {
		rows[i] = evidence.Row{Cells: map[string]evidence.Value{"N": evidence.Number(uint64(i))}, Provenance: p}
		rows[i].Provenance.Layer = "process:1" // per-row spaces are legitimate
		if i > 0 {
			rows[i].ParentID = rows[i-1].ID
		}
		rows[i].Seal()
	}
	if err := s.Append(context.Background(), task.ID, rows); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(context.Background(), task.ID, "failed", errors.New("source page absent")); err != nil {
		t.Fatal(err)
	}
	return s, task, rows
}

func replaceVerificationRow(t *testing.T, s *Store, original string, row evidence.Row) {
	t.Helper()
	body, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE results SET row_id=?,body=? WHERE row_id=?", row.ID, body, original); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCasePagedFailedTaskAndCancellation(t *testing.T) {
	s, task, _ := verificationFixture(t, 1001)
	r, err := s.VerifyCase(context.Background(), task.ID)
	if err != nil || !r.Verified || r.Rows != 1001 || r.Tasks != 1 || r.TaskStates["failed"] != 1 {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err := s.VerifyCase(ctx, ""); !errors.Is(err, context.Canceled) || r.Verified {
		t.Fatal(r, err)
	}
	if r, err := s.VerifyCase(context.Background(), "absent"); err == nil || r.Verified {
		t.Fatal(r, err)
	}
}

func TestVerifyCaseRejectsTamperedRowsAndMetadata(t *testing.T) {
	for _, mode := range []string{"body", "index", "owner", "parent", "references", "terminal", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			s, task, rows := verificationFixture(t, 2)
			row := rows[1]
			switch mode {
			case "body":
				row.Cells["N"] = evidence.Number(999)
				replaceVerificationRow(t, s, row.ID, row)
			case "index":
				_, err := s.db.Exec("UPDATE results SET row_id='different'")
				if err != nil {
					t.Fatal(err)
				}
			case "owner":
				original := row.ID
				row.Provenance.EngineBuild = "different"
				row.Seal()
				replaceVerificationRow(t, s, original, row)
			case "parent":
				original := row.ID
				row.ParentID = "absent"
				row.Seal()
				replaceVerificationRow(t, s, original, row)
			case "references":
				original := row.ID
				row.Cells["EvidenceIDs"] = evidence.Value{Kind: "references", Data: []string{"absent"}}
				row.Seal()
				replaceVerificationRow(t, s, original, row)
			case "terminal":
				_, err := s.db.Exec("UPDATE tasks SET finished=NULL WHERE id=?", task.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "orphan":
				_, err := s.db.Exec("PRAGMA foreign_keys=OFF; UPDATE results SET task_id='absent'; PRAGMA foreign_keys=ON")
				if err != nil {
					t.Fatal(err)
				}
			}
			if r, err := s.VerifyCase(context.Background(), ""); err == nil || r.Verified {
				t.Fatal("corruption passed", r, err)
			}
		})
	}
}

func TestVerifyCaseTriageReferencesPreserveSourceProvenance(t *testing.T) {
	s, source, rows := verificationFixture(t, 1)
	p := source.Provenance
	p.Plugin, p.Parameters = "triage", map[string]string{"rules": "v8"}
	task, err := s.Begin(context.Background(), "triage", "triage", p)
	if err != nil {
		t.Fatal(err)
	}
	row := evidence.Row{Provenance: source.Provenance, Cells: map[string]evidence.Value{"EvidenceIDs": {Kind: "references", Data: []string{rows[0].ID}}}}
	row.Provenance.Plugin = "triage.example"
	row.Seal()
	if err := s.Append(context.Background(), task.ID, []evidence.Row{row}); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(context.Background(), task.ID, "completed", nil); err != nil {
		t.Fatal(err)
	}
	r, err := s.VerifyCase(context.Background(), task.ID)
	if err != nil || !r.Verified || r.References != 1 {
		t.Fatal(r, err)
	}
	// A sealed finding must not point at a different acquisition.
	original := rows[0].ID
	rows[0].Provenance.ImageSHA256 = "other-image"
	// Keep the index identity to exercise referenced seal checking.
	replaceVerificationRow(t, s, original, rows[0])
	if r, err := s.VerifyCase(context.Background(), task.ID); err == nil || r.Verified {
		t.Fatal(r, err)
	}
	// Even with valid replacement seals, cross-image correlation is rejected.
	rows[0].Seal()
	replaceVerificationRow(t, s, original, rows[0])
	originalFinding := row.ID
	row.Cells["EvidenceIDs"] = evidence.Value{Kind: "references", Data: []string{rows[0].ID}}
	row.Seal()
	replaceVerificationRow(t, s, originalFinding, row)
	if r, err := s.VerifyCase(context.Background(), task.ID); err == nil || r.Verified || !strings.Contains(err.Error(), "reference image") {
		t.Fatal(r, err)
	}
}

func TestVerifyCaseArtifactsEmptyAndActiveScope(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if r, err := s.VerifyCase(ctx, ""); err == nil || r.Verified {
		t.Fatal(r, err)
	}
	task := artifactTask(t, s)
	if r, err := s.VerifyCase(ctx, task.ID); err == nil || r.Verified {
		t.Fatal(r, err)
	}
	sink := s.TaskArtifacts(task)
	w, err := sink.Create(ctx, evidence.ArtifactRequest{Name: "data.bin", Size: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	a, err := w.Finish(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx, task.ID, "completed", nil); err != nil {
		t.Fatal(err)
	}
	r, err := s.VerifyCase(ctx, task.ID)
	if err != nil || !r.Verified || r.Artifacts != 1 {
		t.Fatal(r, err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, filepath.FromSlash(a.Path)), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if r, err := s.VerifyCase(ctx, task.ID); err == nil || r.Verified || !strings.Contains(err.Error(), "checksum") {
		t.Fatal(r, err)
	}
}
