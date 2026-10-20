package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func artifactTask(t *testing.T, s *Store) evidence.Task {
	t.Helper()
	task, err := s.Begin(context.Background(), "artifact-test", "extract", evidence.Provenance{ImageSHA256: "image", EngineBuild: "build", SymbolsSHA256: "symbols", Plugin: "extract", Layer: "kernel", Parameters: map[string]string{"dump": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestArtifactDataPaddingChecksumsAndReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	task := artifactTask(t, s)
	sink := s.TaskArtifacts(task)
	w, err := sink.Create(ctx, evidence.ArtifactRequest{Name: "range.dmp", Size: 6, Layer: "process:identity", Offset: "0xffff800000001000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("AB")); err != nil {
		t.Fatal(err)
	}
	if err = w.PadZero(ctx, 2, 0xffff800000001002, "process:identity", errors.New("page is not captured")); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("CD")); err != nil {
		t.Fatal(err)
	}
	a, err := w.Finish(ctx, nil)
	if err != nil || a.State != "completed_with_gaps" || a.Size != "6" || a.MissingBytes != "2" || a.GapCount != "1" {
		t.Fatal(a, err)
	}
	if a.Provenance.ImageSHA256 != "image" || a.Provenance.Layer != "process:identity" || a.Provenance.Offset != "0xffff800000001000" {
		t.Fatal(a)
	}
	if err = sink.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = sink.Create(ctx, evidence.ArtifactRequest{Name: "late", Size: 1}); err == nil {
		t.Fatal("closed task sink accepted an artifact")
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(a.Path)))
	if err != nil || string(data) != "AB\x00\x00CD" {
		t.Fatal(data, err)
	}
	h := sha256.Sum256(data)
	if a.SHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("data hash mismatch")
	}
	gaps, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(a.GapsPath)))
	if err != nil {
		t.Fatal(err)
	}
	var gap evidence.ArtifactGap
	if err = json.Unmarshal(gaps, &gap); err != nil || gap.Offset != "0x2" || gap.Address != "0xffff800000001002" || gap.Length != "2" || gap.Error == "" {
		t.Fatal(gap, err)
	}
	if err = s.VerifyTaskArtifacts(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(ctx, task.ID, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.VerifyTaskArtifacts(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Cached(ctx, "artifact-test"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	file, err := s.OpenArtifactMember(ctx, a, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(got) != string(data) {
		t.Fatal(got, err)
	}
	if err = os.WriteFile(filepath.Join(dir, filepath.FromSlash(a.Path)), []byte("ABCDEF"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyTaskArtifacts(ctx, task.ID); err == nil {
		t.Fatal("same-size artifact tampering went undetected")
	}
}

func TestArtifactCancellationErrorsAndForgottenWriters(t *testing.T) {
	for _, scenario := range []string{"cancel", "overrun", "gap-write", "forgotten", "ignored-error"} {
		t.Run(scenario, func(t *testing.T) {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			task := artifactTask(t, s)
			sink := s.TaskArtifacts(task)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w, err := sink.Create(ctx, evidence.ArtifactRequest{Name: "partial.bin", Size: 6})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = w.Write([]byte("AB")); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "cancel":
				cancel()
				if _, err = w.Write([]byte("CD")); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "overrun":
				if _, err = w.Write([]byte("12345")); err == nil {
					t.Fatal("overrun accepted")
				}
			case "gap-write":
				w.(*artifactWriter).gaps.Close()
				if err = w.PadZero(ctx, 2, 2, "physical", io.EOF); err == nil {
					t.Fatal("gap log error disappeared")
				}
			case "ignored-error":
				_, _ = w.Write([]byte("too large"))
				_, _ = w.Write([]byte("CDEF"))
			case "forgotten":
				if err = sink.Finalize(context.Background()); err == nil {
					t.Fatal("forgotten writer became a successful task")
				}
				a, err := s.Artifact(context.Background(), w.(*artifactWriter).info.ID)
				if err != nil || a.State != "partial" {
					t.Fatal(a, err)
				}
				return
			}
			a, err := w.Finish(ctx, nil)
			if err == nil || a.State != "partial" || a.Error == "" || a.SHA256 == "" {
				t.Fatal(a, err)
			}
			if err = sink.Finalize(context.Background()); err == nil {
				t.Fatal("ignored file failure became task success")
			}
		})
	}
}

func TestArtifactPathsOwnershipAndPersistentCaseRequirement(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	task := artifactTask(t, s)
	sink := s.TaskArtifacts(task)
	for _, name := range []string{"../image.raw", "/tmp/escape", "a/b", "a\\b", "NUL", "CON.txt", "x:stream", "bad\x00name", "trailing.", "trailing ", "bad\xffname"} {
		if _, err = sink.Create(ctx, evidence.ArtifactRequest{Name: name, Size: 1}); err == nil {
			t.Fatal("unsafe name accepted", name)
		}
	}
	w, err := sink.Create(ctx, evidence.ArtifactRequest{Name: "good.bin", Size: 1})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte{1})
	a, err := w.Finish(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	forged := a
	forged.Provenance.ImageSHA256 = "other-image"
	if f, err := s.OpenArtifactMember(ctx, forged, false); err == nil {
		f.Close()
		t.Fatal("forged provenance accepted")
	}
	forged = a
	forged.Path = "case.db"
	if f, err := s.OpenArtifactMember(ctx, forged, false); err == nil {
		f.Close()
		t.Fatal("forged path accepted")
	}
	mem, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	mt := artifactTask(t, mem)
	if _, err = mem.TaskArtifacts(mt).Create(ctx, evidence.ArtifactRequest{Name: "x", Size: 1}); err == nil {
		t.Fatal("nonpersistent extraction accepted")
	}
	other, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	outside := t.TempDir()
	if err = os.Symlink(outside, filepath.Join(other.Dir, "artifacts")); err != nil {
		t.Skip("symlinks unavailable")
	}
	ot := artifactTask(t, other)
	if _, err = other.TaskArtifacts(ot).Create(ctx, evidence.ArtifactRequest{Name: "escape", Size: 1}); err == nil {
		t.Fatal("artifact escaped case root")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
}

func TestCaseSchemaMigrationAndInterruptedArtifactRecovery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an existing v1 case before extraction support, preserving its task.
	task := artifactTask(t, s)
	if _, err = s.db.Exec("DROP TABLE artifacts; UPDATE schema_version SET version=1"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 2 {
		t.Fatal(version, err)
	}
	tasks, err := s.Tasks(ctx)
	if err != nil || len(tasks) != 1 || tasks[0].ID != task.ID {
		t.Fatal(tasks, err)
	}
	task = artifactTask(t, s)
	writer, err := s.TaskArtifacts(task).Create(ctx, evidence.ArtifactRequest{Name: "interrupted.bin", Size: 9})
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("ABC"))
	w := writer.(*artifactWriter)
	// A process crash bypasses finalization; deliberately leave its DB record writing.
	w.file.Close()
	w.gaps.Close()
	w.root.Close()
	s.artifactMu.Lock()
	delete(s.artifactWriters, w.info.ID)
	s.artifactMu.Unlock()
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.Artifact(ctx, w.info.ID)
	if err != nil || a.State != "interrupted" || a.Size != "" || a.SHA256 != "" || a.Error == "" {
		t.Fatal(a, err)
	}
	if err = s.VerifyTaskArtifacts(ctx, task.ID); err == nil {
		t.Fatal("interrupted extraction verified as complete")
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(a.Path)))
	if err != nil || string(data) != "ABC" {
		t.Fatal("partial acquisition lost", data, err)
	}
}
