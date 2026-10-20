package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func (s *Store) initArtifacts() error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(id),state TEXT NOT NULL,body BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS artifacts_task ON artifacts(task_id,id);
UPDATE schema_version SET version=2;`)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	// Preserve unfinished files. Their unfinalized sizes/checksums remain unknown,
	// and they cannot be reused or silently exported as complete captures.
	rows, err := s.db.Query("SELECT body FROM artifacts WHERE state='writing'")
	if err != nil {
		return err
	}
	var interrupted []evidence.Artifact
	for rows.Next() {
		var body []byte
		if err = rows.Scan(&body); err != nil {
			break
		}
		var a evidence.Artifact
		if err = json.Unmarshal(body, &a); err != nil {
			break
		}
		a.State = "interrupted"
		a.GapsSize = ""
		a.Size, a.SHA256, a.GapsSHA256, a.MissingBytes, a.GapCount = "", "", "", "", ""
		a.Error = "interrupted before file finalization; size and checksums unverified"
		interrupted = append(interrupted, a)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	for _, a := range interrupted {
		if err = s.saveArtifact(context.Background(), a); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) saveArtifact(ctx context.Context, a evidence.Artifact) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE artifacts SET state=?,body=? WHERE id=?", a.State, b, a.ID)
	return err
}

func artifactName(name string) bool {
	if name == "" || !utf8.ValidString(name) || len(name) > 160 || name == "." || name == ".." || strings.ContainsAny(name, "/\\:*?\"<>|\x00") || strings.TrimRight(name, " .") != name {
		return false
	}
	for _, c := range name {
		if c < 32 {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return false
	}
	return true
}

func artifactID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && strings.ToLower(id) == id
}

func validateArtifact(a evidence.Artifact) error {
	if !artifactID(a.ID) || !artifactID(a.TaskID) || !artifactName(a.Name) || a.Path != path.Join("artifacts", a.TaskID, a.ID, a.Name) || a.GapsPath != a.Path+".gaps.jsonl" {
		return fmt.Errorf("invalid artifact identity or path")
	}
	expected, err := strconv.ParseUint(a.ExpectedSize, 10, 64)
	if err != nil || expected > math.MaxInt64 {
		return fmt.Errorf("invalid artifact expected size")
	}
	if a.State == "writing" || a.State == "interrupted" {
		return fmt.Errorf("artifact %s is not finalized (%s)", a.ID, a.State)
	}
	size, err := strconv.ParseUint(a.Size, 10, 64)
	if err != nil || size > expected {
		return fmt.Errorf("invalid artifact size")
	}
	missing, err := strconv.ParseUint(a.MissingBytes, 10, 64)
	if err != nil || missing > size {
		return fmt.Errorf("invalid padding size")
	}
	count, err := strconv.ParseUint(a.GapCount, 10, 64)
	if err != nil || count > missing {
		return fmt.Errorf("invalid padding count")
	}
	gapSize, err := strconv.ParseUint(a.GapsSize, 10, 64)
	if err != nil || gapSize > math.MaxInt64 {
		return fmt.Errorf("invalid padding log size")
	}
	for _, sum := range []string{a.SHA256, a.GapsSHA256} {
		b, err := hex.DecodeString(sum)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("invalid artifact checksum")
		}
	}
	switch a.State {
	case "completed":
		if size != expected || missing != 0 || count != 0 {
			return fmt.Errorf("inconsistent complete artifact")
		}
	case "completed_with_gaps":
		if size != expected || missing == 0 || count == 0 {
			return fmt.Errorf("inconsistent padded artifact")
		}
	case "partial", "failed":
		if a.Error == "" {
			return fmt.Errorf("failed artifact lacks reason")
		}
	default:
		return fmt.Errorf("unknown artifact state %q", a.State)
	}
	return nil
}

func (s *Store) Artifact(ctx context.Context, id string) (evidence.Artifact, error) {
	var a evidence.Artifact
	var b []byte
	var task, state string
	err := s.db.QueryRowContext(ctx, "SELECT task_id,state,body FROM artifacts WHERE id=?", id).Scan(&task, &state, &b)
	if err != nil {
		return a, err
	}
	if err = json.Unmarshal(b, &a); err != nil {
		return a, err
	}
	if a.ID != id || a.TaskID != task || a.State != state {
		return a, fmt.Errorf("artifact metadata identity mismatch")
	}
	return a, nil
}

// OpenArtifactMember verifies the bytes before returning a rewound reader. Bundle
// writers also hash their actual copy, detecting changes during the later read.
func (s *Store) OpenArtifactMember(ctx context.Context, a evidence.Artifact, gaps bool) (*os.File, error) {
	if s.Dir == "" {
		return nil, fmt.Errorf("artifact requires a persistent case")
	}
	if err := validateArtifact(a); err != nil {
		return nil, err
	}
	if err := s.VerifyArtifactOwner(ctx, a); err != nil {
		return nil, err
	}
	name, sum := a.Path, a.SHA256
	if gaps {
		name, sum = a.GapsPath, a.GapsSHA256
	}
	root, err := os.OpenRoot(s.Dir)
	if err != nil {
		return nil, err
	}
	f, err := root.Open(name)
	root.Close()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { f.Close(); return nil, err }
	stat, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !stat.Mode().IsRegular() {
		return fail(fmt.Errorf("artifact is not a regular file"))
	}
	size, _ := strconv.ParseInt(a.Size, 10, 64)
	if gaps {
		size, _ = strconv.ParseInt(a.GapsSize, 10, 64)
	}
	if stat.Size() != size {
		return fail(fmt.Errorf("artifact size mismatch"))
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		if err = ctx.Err(); err != nil {
			return fail(err)
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fail(readErr)
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != sum {
		return fail(fmt.Errorf("artifact checksum mismatch: %s", a.ID))
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return f, nil
}

func (s *Store) VerifyTaskArtifacts(ctx context.Context, taskID string) error {
	if taskID != "" {
		var found int
		if err := s.db.QueryRowContext(ctx, "SELECT 1 FROM tasks WHERE id=?", taskID).Scan(&found); err != nil {
			return err
		}
	}
	for offset := 0; ; offset += 500 {
		artifacts, err := s.ArtifactPage(ctx, taskID, offset, 500)
		if err != nil {
			return err
		}
		for _, a := range artifacts {
			for _, gap := range []bool{false, true} {
				f, err := s.OpenArtifactMember(ctx, a, gap)
				if err != nil {
					return err
				}
				if err = f.Close(); err != nil {
					return err
				}
			}
		}
		if len(artifacts) < 500 {
			return nil
		}
	}
}

type TaskArtifacts struct {
	s      *Store
	task   evidence.Task
	mu     sync.Mutex
	closed bool
}

func (s *Store) TaskArtifacts(task evidence.Task) *TaskArtifacts {
	return &TaskArtifacts{s: s, task: task}
}

func (t *TaskArtifacts) Create(ctx context.Context, r evidence.ArtifactRequest) (evidence.ArtifactWriter, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, fmt.Errorf("task artifact sink is closed")
	}
	w, err := t.s.createArtifact(ctx, t.task, r)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// Finalize prevents late plugin writes. A forgotten writer fails the task even
// if its data happens to have the expected size.
func (t *TaskArtifacts) Finalize(ctx context.Context) error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.s.artifactMu.Lock()
	var pending []*artifactWriter
	for _, w := range t.s.artifactWriters {
		if w.info.TaskID == t.task.ID {
			pending = append(pending, w)
		}
	}
	t.s.artifactMu.Unlock()
	var result error
	for _, w := range pending {
		_, err := w.Finish(ctx, fmt.Errorf("plugin returned before artifact finalization"))
		result = errors.Join(result, err)
	}
	var state string
	err := t.s.db.QueryRowContext(ctx, "SELECT state FROM artifacts WHERE task_id=? AND state NOT IN ('completed','completed_with_gaps') LIMIT 1", t.task.ID).Scan(&state)
	if err == nil {
		result = errors.Join(result, fmt.Errorf("task contains an artifact in state %s", state))
	} else if !errors.Is(err, sql.ErrNoRows) {
		result = errors.Join(result, err)
	}
	return result
}

func artifactIdentity(a evidence.Artifact, id, task, state string) error {
	if a.ID != id || a.TaskID != task || a.State != state {
		return fmt.Errorf("artifact metadata identity mismatch")
	}
	return nil
}

func (s *Store) VerifyArtifactOwner(ctx context.Context, a evidence.Artifact) error {
	var b []byte
	if err := s.db.QueryRowContext(ctx, "SELECT provenance FROM tasks WHERE id=?", a.TaskID).Scan(&b); err != nil {
		return err
	}
	var original evidence.Provenance
	if err := json.Unmarshal(b, &original); err != nil {
		return err
	}
	claimed := a.Provenance
	claimed.Layer, claimed.Offset = original.Layer, original.Offset
	x, err := json.Marshal(original)
	if err != nil {
		return err
	}
	y, err := json.Marshal(claimed)
	if err != nil {
		return err
	}
	if !bytes.Equal(x, y) {
		return fmt.Errorf("artifact task provenance mismatch")
	}
	return nil
}

func (s *Store) ArtifactPage(ctx context.Context, taskID string, offset, limit int) ([]evidence.Artifact, error) {
	if offset < 0 || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("invalid artifact page")
	}
	query := "SELECT id,task_id,state,body FROM artifacts"
	var args []any
	if taskID != "" {
		query += " WHERE task_id=?"
		args = append(args, taskID)
	}
	query += " ORDER BY task_id,id LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []evidence.Artifact
	for rows.Next() {
		var id, task, state string
		var b []byte
		if err = rows.Scan(&id, &task, &state, &b); err != nil {
			return nil, err
		}
		var a evidence.Artifact
		if err = json.Unmarshal(b, &a); err != nil {
			return nil, err
		}
		if err = artifactIdentity(a, id, task, state); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) Artifacts(ctx context.Context, taskID string) ([]evidence.Artifact, error) {
	var out []evidence.Artifact
	for offset := 0; ; offset += 500 {
		page, err := s.ArtifactPage(ctx, taskID, offset, 500)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < 500 {
			return out, nil
		}
	}
}

type artifactWriter struct {
	mu                                sync.Mutex
	s                                 *Store
	ctx                               context.Context
	root                              *os.Root
	file, gaps                        *os.File
	hash, gapHash                     hash.Hash
	info                              evidence.Artifact
	expected, written, missing, count uint64
	gapWritten                        uint64
	finished                          bool
	finishErr                         error
	writeErr                          error
}

func (s *Store) createArtifact(ctx context.Context, task evidence.Task, r evidence.ArtifactRequest) (*artifactWriter, error) {
	if s.Dir == "" {
		return nil, fmt.Errorf("extraction requires a persistent --case directory")
	}
	if !artifactName(r.Name) || r.Size > math.MaxInt64 || !artifactID(task.ID) {
		return nil, fmt.Errorf("invalid artifact filename or expected size")
	}
	var state string
	var body []byte
	if err := s.db.QueryRowContext(ctx, "SELECT state,provenance FROM tasks WHERE id=?", task.ID).Scan(&state, &body); err != nil {
		return nil, err
	}
	if state != "running" {
		return nil, fmt.Errorf("artifact owner task is not running")
	}
	var provenance evidence.Provenance
	if err := json.Unmarshal(body, &provenance); err != nil {
		return nil, err
	}
	if r.Layer != "" {
		provenance.Layer = r.Layer
	}
	if r.Offset != "" {
		offset, err := strconv.ParseUint(r.Offset, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("artifact source offset: %w", err)
		}
		r.Offset = fmt.Sprintf("0x%x", offset)
	}
	provenance.Offset = r.Offset
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	a := evidence.Artifact{ID: hex.EncodeToString(id[:]), TaskID: task.ID, Name: r.Name, State: "writing", ExpectedSize: strconv.FormatUint(r.Size, 10), MissingBytes: "0", GapCount: "0", Provenance: provenance}
	dir := path.Join("artifacts", task.ID, a.ID)
	a.Path = path.Join(dir, r.Name)
	a.GapsPath = a.Path + ".gaps.jsonl"
	root, err := os.OpenRoot(s.Dir)
	if err != nil {
		return nil, err
	}
	if err = root.MkdirAll(dir, 0700); err != nil {
		root.Close()
		return nil, err
	}
	f, err := root.OpenFile(a.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		root.Close()
		return nil, err
	}
	g, err := root.OpenFile(a.GapsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		f.Close()
		root.Remove(a.Path)
		root.Close()
		return nil, err
	}
	b, err := json.Marshal(a)
	if err == nil {
		_, err = s.db.ExecContext(ctx, "INSERT INTO artifacts(id,task_id,state,body) VALUES(?,?,?,?)", a.ID, task.ID, a.State, b)
	}
	if err != nil {
		f.Close()
		g.Close()
		root.Remove(a.Path)
		root.Remove(a.GapsPath)
		root.Close()
		return nil, err
	}
	w := &artifactWriter{s: s, ctx: ctx, root: root, file: f, gaps: g, hash: sha256.New(), gapHash: sha256.New(), info: a, expected: r.Size}
	s.artifactMu.Lock()
	if s.artifactWriters == nil {
		s.artifactWriters = map[string]*artifactWriter{}
	}
	s.artifactWriters[a.ID] = w
	s.artifactMu.Unlock()
	return w, nil
}

func (w *artifactWriter) writeLocked(p []byte) (int, error) {
	if w.finished {
		return 0, fmt.Errorf("artifact is finalized")
	}
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 16<<20 || uint64(len(p)) > w.expected-w.written {
		return 0, fmt.Errorf("artifact write exceeds declared size or chunk bound")
	}
	n, err := w.file.Write(p)
	if n > 0 {
		w.hash.Write(p[:n])
		w.written += uint64(n)
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (w *artifactWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.writeLocked(p)
	w.writeErr = errors.Join(w.writeErr, err)
	return n, err
}

func (w *artifactWriter) PadZero(ctx context.Context, length, address uint64, layer string, cause error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cause == nil || length == 0 || length > w.expected-w.written || length-1 > ^uint64(0)-address {
		err := fmt.Errorf("invalid padding source/range")
		w.writeErr = errors.Join(w.writeErr, err)
		return err
	}
	start := w.written
	var result error
	zero := make([]byte, 64<<10)
	for left := length; left > 0; {
		if result = ctx.Err(); result != nil {
			break
		}
		n, err := w.writeLocked(zero[:min(uint64(len(zero)), left)])
		left -= uint64(n)
		if err != nil {
			result = err
			break
		}
	}
	actual := w.written - start
	if actual > 0 {
		gap := evidence.ArtifactGap{Offset: fmt.Sprintf("0x%x", start), Length: strconv.FormatUint(actual, 10), Address: fmt.Sprintf("0x%x", address), Layer: layer, Error: cause.Error()}
		b, err := json.Marshal(gap)
		if err == nil {
			b = append(b, '\n')
			var n int
			n, err = w.gaps.Write(b)
			if n > 0 {
				w.gapHash.Write(b[:n])
				w.gapWritten += uint64(n)
			}
			if err == nil && n != len(b) {
				err = io.ErrShortWrite
			}
		}
		result = errors.Join(result, err)
		w.missing += actual
		w.count++
	}
	w.writeErr = errors.Join(w.writeErr, result)
	return result
}

func (w *artifactWriter) Finish(ctx context.Context, cause error) (evidence.Artifact, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return w.info, w.finishErr
	}
	w.finished = true
	cause = errors.Join(cause, w.writeErr)
	if cause == nil && w.written != w.expected {
		cause = io.ErrUnexpectedEOF
	}
	cause = errors.Join(cause, w.file.Sync(), w.gaps.Sync(), w.file.Close(), w.gaps.Close(), w.root.Close())
	w.info.Size = strconv.FormatUint(w.written, 10)
	w.info.SHA256 = hex.EncodeToString(w.hash.Sum(nil))
	w.info.GapsSHA256 = hex.EncodeToString(w.gapHash.Sum(nil))
	w.info.GapsSize = strconv.FormatUint(w.gapWritten, 10)
	w.info.MissingBytes = strconv.FormatUint(w.missing, 10)
	w.info.GapCount = strconv.FormatUint(w.count, 10)
	w.info.State = "completed"
	if w.count > 0 {
		w.info.State = "completed_with_gaps"
	}
	if cause != nil {
		w.info.State = "failed"
		if w.written > 0 {
			w.info.State = "partial"
		}
		w.info.Error = cause.Error()
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	w.finishErr = errors.Join(cause, w.s.saveArtifact(cleanup, w.info))
	w.s.artifactMu.Lock()
	delete(w.s.artifactWriters, w.info.ID)
	w.s.artifactMu.Unlock()
	return w.info, w.finishErr
}

func (s *Store) abortArtifacts() error {
	s.artifactMu.Lock()
	var writers []*artifactWriter
	for _, w := range s.artifactWriters {
		writers = append(writers, w)
	}
	s.artifactMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var result error
	for _, w := range writers {
		_, err := w.Finish(ctx, fmt.Errorf("case closed before artifact finalization"))
		result = errors.Join(result, err)
	}
	return result
}
