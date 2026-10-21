package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/gofrs/flock"
	_ "modernc.org/sqlite"
)

type Store struct {
	artifactMu      sync.Mutex
	artifactWriters map[string]*artifactWriter
	db              *sql.DB
	Dir             string
	lock            *flock.Flock
	closeOnce       sync.Once
	closeErr        error
}

func Open(dir string) (*Store, error) {
	name := ":memory:"
	var lock *flock.Flock
	if dir != "" {
		abs, e := filepath.Abs(dir)
		if e != nil {
			return nil, e
		}
		dir = abs
		if e := os.MkdirAll(dir, 0700); e != nil {
			return nil, e
		}
		name = filepath.Join(dir, "case.db")
		lock = flock.New(filepath.Join(dir, "case.lock"), flock.SetPermissions(0600))
		ok, e := lock.TryLock()
		if e != nil {
			return nil, e
		}
		if !ok {
			return nil, fmt.Errorf("case is already open by another GoMem process")
		}
	}
	db, e := sql.Open("sqlite", name)
	if e != nil {
		if lock != nil {
			lock.Close()
		}
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Dir: dir, lock: lock}
	if e = s.init(); e != nil {
		s.Close()
		return nil, e
	}
	if dir != "" {
		if e := os.Chmod(name, 0600); e != nil {
			s.Close()
			return nil, e
		}
	}
	return s, nil
}
func (s *Store) init() error {
	var tables int
	if err := s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_version'").Scan(&tables); err != nil {
		return err
	}
	if tables > 0 {
		var v int
		if err := s.db.QueryRow("SELECT version FROM schema_version").Scan(&v); err != nil {
			return err
		}
		if v != 1 && v != 2 {
			return fmt.Errorf("unsupported case schema %d", v)
		}
	} else {
		var count int
		if err := s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("existing SQLite database is not a GoMem case")
		}
	}
	_, e := s.db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
 INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
 CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,cache_key TEXT NOT NULL,plugin TEXT NOT NULL,state TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',started TEXT NOT NULL,finished TEXT,provenance BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS tasks_cache ON tasks(cache_key,state,started);
 CREATE TABLE IF NOT EXISTS results(seq INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT NOT NULL REFERENCES tasks(id),row_id TEXT NOT NULL,body BLOB NOT NULL,search TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS results_page ON results(task_id,seq);
 CREATE INDEX IF NOT EXISTS results_id ON results(row_id);
 CREATE TABLE IF NOT EXISTS bookmarks(row_id TEXT PRIMARY KEY,note TEXT NOT NULL,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY,command TEXT NOT NULL,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS whitelist(rule TEXT NOT NULL,entity TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(rule,entity));`)
	if e != nil {
		return e
	}
	var v int
	if e = s.db.QueryRow("SELECT version FROM schema_version").Scan(&v); e != nil {
		return e
	}
	if v != 1 && v != 2 {
		return fmt.Errorf("unsupported case schema %d", v)
	}
	_, e = s.db.Exec("CREATE TABLE IF NOT EXISTS images(sha256 TEXT PRIMARY KEY,path TEXT NOT NULL,size TEXT NOT NULL,format TEXT NOT NULL,first_seen TEXT NOT NULL)")
	if e != nil {
		return e
	}
	if e = s.initArtifacts(); e != nil {
		return e
	}
	_, e = s.db.Exec("UPDATE tasks SET state='failed',error='interrupted before terminal state; partial evidence retained',finished=? WHERE state='running'", time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.abortArtifacts(), s.db.Close())
		if s.lock != nil {
			s.closeErr = errors.Join(s.closeErr, s.lock.Close())
		}
	})
	return s.closeErr
}
func (s *Store) Begin(ctx context.Context, key, plugin string, p evidence.Provenance) (evidence.Task, error) {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return evidence.Task{}, e
	}
	t := evidence.Task{ID: hex.EncodeToString(id[:]), CacheKey: key, Plugin: plugin, State: "running", Started: time.Now().UTC(), Provenance: p}
	b, e := json.Marshal(p)
	if e != nil {
		return t, e
	}
	_, e = s.db.ExecContext(ctx, "INSERT INTO tasks(id,cache_key,plugin,state,started,provenance) VALUES(?,?,?,?,?,?)", t.ID, key, plugin, t.State, t.Started.Format(time.RFC3339Nano), b)
	return t, e
}
func (s *Store) Append(ctx context.Context, id string, rows []evidence.Row) error {
	if len(rows) == 0 {
		return nil
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	stmt, e := tx.PrepareContext(ctx, "INSERT INTO results(task_id,row_id,body,search) VALUES(?,?,?,?)")
	if e != nil {
		return e
	}
	defer stmt.Close()
	for _, r := range rows {
		b, e := json.Marshal(r)
		if e != nil {
			return e
		}
		cells, e := json.Marshal(r.Cells)
		if e != nil {
			return e
		}
		if _, e = stmt.ExecContext(ctx, id, r.ID, b, string(cells)); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) Finish(ctx context.Context, id, state string, cause error) error {
	if state != "completed" && state != "failed" && state != "canceled" {
		return fmt.Errorf("invalid terminal task state")
	}
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	_, e := s.db.ExecContext(ctx, "UPDATE tasks SET state=?,error=?,finished=? WHERE id=? AND state='running'", state, msg, time.Now().UTC().Format(time.RFC3339Nano), id)
	return e
}

const taskSelect = `SELECT t.id,t.cache_key,t.plugin,t.state,t.error,t.started,t.finished,t.provenance,(SELECT count(*) FROM results r WHERE r.task_id=t.id) FROM tasks t`

func taskScan(scan func(...any) error) (evidence.Task, error) {
	var t evidence.Task
	var started string
	var finished sql.NullString
	var p []byte
	e := scan(&t.ID, &t.CacheKey, &t.Plugin, &t.State, &t.Error, &started, &finished, &p, &t.Rows)
	if e != nil {
		return t, e
	}
	t.Started, e = time.Parse(time.RFC3339Nano, started)
	if e != nil {
		return t, e
	}
	if finished.Valid {
		v, e := time.Parse(time.RFC3339Nano, finished.String)
		if e != nil {
			return t, e
		}
		t.Finished = &v
	}
	e = json.Unmarshal(p, &t.Provenance)
	return t, e
}
func (s *Store) Cached(ctx context.Context, key string) (evidence.Task, bool, error) {
	t, e := taskScan(s.db.QueryRowContext(ctx, taskSelect+" WHERE cache_key=? AND state='completed' ORDER BY started DESC LIMIT 1", key).Scan)
	if errors.Is(e, sql.ErrNoRows) {
		return t, false, nil
	}
	return t, e == nil, e
}
func (s *Store) Tasks(ctx context.Context) ([]evidence.Task, error) {
	r, e := s.db.QueryContext(ctx, taskSelect+" ORDER BY started DESC")
	if e != nil {
		return nil, e
	}
	defer r.Close()
	var out []evidence.Task
	for r.Next() {
		t, e := taskScan(r.Scan)
		if e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, r.Err()
}
func (s *Store) Query(ctx context.Context, q evidence.Query) ([]evidence.Row, error) {
	if q.Limit < 1 || q.Limit > 1000 || q.Offset < 0 {
		return nil, fmt.Errorf("page limit must be 1..1000 and offset nonnegative")
	}
	order := "ASC"
	if q.Desc {
		order = "DESC"
	}
	var r *sql.Rows
	var e error
	if q.Sort == "" {
		r, e = s.db.QueryContext(ctx, "SELECT body FROM results WHERE task_id=? AND (?='' OR instr(lower(search),lower(?))>0) ORDER BY seq "+order+" LIMIT ? OFFSET ?", q.TaskID, q.Filter, q.Filter, q.Limit, q.Offset)
	} else {
		if strings.ContainsAny(q.Sort, "\"\\") {
			return nil, fmt.Errorf("sort column %q is not addressable", q.Sort)
		}
		// Cell values are text; unsigned decimals order by length first so
		// values above the int64 range stay exact, signed decimals cast exactly,
		// and fixed-width addresses order lexically. seq keeps paging stable.
		path := `$.cells."` + q.Sort + `"`
		r, e = s.db.QueryContext(ctx, "SELECT body FROM (SELECT seq,body,json_extract(CAST(body AS TEXT),?||'.kind') AS k,json_extract(CAST(body AS TEXT),?||'.value') AS v FROM results WHERE task_id=? AND (?='' OR instr(lower(search),lower(?))>0)) ORDER BY CASE WHEN k='uint64' THEN length(v) END "+order+",CASE WHEN k='int64' THEN CAST(v AS INTEGER) END "+order+",v "+order+",seq "+order+" LIMIT ? OFFSET ?", path, path, q.TaskID, q.Filter, q.Filter, q.Limit, q.Offset)
	}
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := make([]evidence.Row, 0, q.Limit)
	for r.Next() {
		var b []byte
		if e := r.Scan(&b); e != nil {
			return nil, e
		}
		var row evidence.Row
		if e := json.Unmarshal(b, &row); e != nil {
			return nil, e
		}
		out = append(out, row)
	}
	return out, r.Err()
}
func (s *Store) Bookmark(ctx context.Context, id, note string) error {
	_, e := s.db.ExecContext(ctx, "INSERT INTO bookmarks VALUES(?,?,?) ON CONFLICT(row_id) DO UPDATE SET note=excluded.note", id, note, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) History(ctx context.Context, cmd string) error {
	_, e := s.db.ExecContext(ctx, "INSERT INTO history(command,created) VALUES(?,?)", cmd, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}

// TaskRows counts the rows a task has stored so far.
func (s *Store) TaskRows(ctx context.Context, id string) (int64, error) {
	var n int64
	e := s.db.QueryRowContext(ctx, "SELECT count(*) FROM results WHERE task_id=?", id).Scan(&n)
	return n, e
}

// Commands returns up to limit recorded commands, oldest first.
func (s *Store) Commands(ctx context.Context, limit int) ([]string, error) {
	r, e := s.db.QueryContext(ctx, "SELECT command FROM (SELECT seq,command FROM history ORDER BY seq DESC LIMIT ?) ORDER BY seq", limit)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	var out []string
	for r.Next() {
		var c string
		if e := r.Scan(&c); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, r.Err()
}
func (s *Store) Allow(ctx context.Context, rule, entity, reason string) error {
	if reason == "" {
		return fmt.Errorf("whitelist requires a reason")
	}
	_, e := s.db.ExecContext(ctx, "INSERT INTO whitelist VALUES(?,?,?) ON CONFLICT(rule,entity) DO UPDATE SET reason=excluded.reason", rule, entity, reason)
	return e
}
func (s *Store) Allowed(ctx context.Context, rule, entity string) (bool, error) {
	var one int
	e := s.db.QueryRowContext(ctx, "SELECT 1 FROM whitelist WHERE rule=? AND entity=?", rule, entity).Scan(&one)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	return e == nil, e
}

func (s *Store) Find(ctx context.Context, id string) (evidence.Row, error) {
	var b []byte
	var row evidence.Row
	e := s.db.QueryRowContext(ctx, "SELECT body FROM results WHERE row_id=? ORDER BY seq DESC LIMIT 1", id).Scan(&b)
	if errors.Is(e, sql.ErrNoRows) {
		return row, fmt.Errorf("unknown evidence ID %s", id)
	}
	if e != nil {
		return row, e
	}
	e = json.Unmarshal(b, &row)
	return row, e
}

func (s *Store) Investigation(ctx context.Context) (map[string]any, error) {
	out := make(map[string]any)
	for _, table := range []string{"bookmarks", "history", "whitelist", "images"} {
		r, e := s.db.QueryContext(ctx, "SELECT * FROM "+table)
		if e != nil {
			return nil, e
		}
		cols, e := r.Columns()
		if e != nil {
			r.Close()
			return nil, e
		}
		var records []map[string]string
		for r.Next() {
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if e := r.Scan(dest...); e != nil {
				r.Close()
				return nil, e
			}
			row := make(map[string]string)
			for i, n := range cols {
				row[n] = fmt.Sprint(values[i])
			}
			records = append(records, row)
		}
		e = r.Err()
		r.Close()
		if e != nil {
			return nil, e
		}
		out[table] = records
	}
	return out, nil
}

// ImageRecord is an image this case has opened.
type ImageRecord struct {
	SHA256, Path, Format, FirstSeen string
	Size                            uint64
}

// Images lists the images this case has opened, most recently first seen first.
func (s *Store) Images(ctx context.Context) ([]ImageRecord, error) {
	r, e := s.db.QueryContext(ctx, "SELECT sha256,path,size,format,first_seen FROM images ORDER BY first_seen DESC")
	if e != nil {
		return nil, e
	}
	defer r.Close()
	var out []ImageRecord
	for r.Next() {
		var rec ImageRecord
		var size string
		if e := r.Scan(&rec.SHA256, &rec.Path, &size, &rec.Format, &rec.FirstSeen); e != nil {
			return nil, e
		}
		rec.Size, _ = strconv.ParseUint(size, 10, 64)
		out = append(out, rec)
	}
	return out, r.Err()
}

func (s *Store) RecordImage(ctx context.Context, hash, path, format string, size uint64) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO images VALUES(?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET path=excluded.path", hash, path, fmt.Sprint(size), format, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
