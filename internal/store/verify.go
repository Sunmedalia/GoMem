package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// Verification checks stored consistency, not the completeness of an analysis
// or authenticity against a separately signed acquisition manifest.
type Verification struct {
	Verified   bool           `json:"verified"`
	TaskID     string         `json:"task_id,omitempty"`
	Tasks      int            `json:"tasks"`
	Rows       int64          `json:"rows"`
	References int64          `json:"references"`
	Artifacts  int            `json:"artifacts"`
	TaskStates map[string]int `json:"task_states"`
	Scope      string         `json:"scope"`
}

// VerifyCase uses bounded result pages. The caller must keep the case exclusive
// and quiescent for the whole verification, as the CLI's case lock does.
func (s *Store) VerifyCase(ctx context.Context, taskID string) (Verification, error) {
	r := Verification{TaskID: taskID, TaskStates: map[string]int{},
		Scope: "SQLite integrity, sealed evidence, task provenance, parent/reference links and extraction files; analysis completeness is separate"}
	var check string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return r, err
	}
	if check != "ok" {
		return r, fmt.Errorf("SQLite integrity: %s", check)
	}
	fk, err := s.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return r, err
	}
	broken := fk.Next()
	err = fk.Err()
	fk.Close()
	if err != nil {
		return r, err
	}
	if broken {
		return r, fmt.Errorf("case has orphaned records")
	}
	tasks, err := s.Tasks(ctx)
	if err != nil {
		return r, err
	}
	for _, task := range tasks {
		if taskID != "" && task.ID != taskID {
			continue
		}
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if task.State != "completed" && task.State != "failed" && task.State != "canceled" {
			return r, fmt.Errorf("task %s is not terminal", task.ID)
		}
		if task.Finished == nil || task.Plugin != task.Provenance.Plugin {
			return r, fmt.Errorf("task %s has inconsistent terminal metadata", task.ID)
		}
		n, refs, err := s.verifyTaskRows(ctx, task)
		r.Rows += n
		r.References += refs
		if err != nil {
			return r, fmt.Errorf("task %s: %w", task.ID, err)
		}
		if n != task.Rows {
			return r, fmt.Errorf("task %s changed during verification", task.ID)
		}
		if err := s.VerifyTaskArtifacts(ctx, task.ID); err != nil {
			return r, fmt.Errorf("task %s extraction: %w", task.ID, err)
		}
		var count int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM artifacts WHERE task_id=?", task.ID).Scan(&count); err != nil {
			return r, err
		}
		r.Artifacts += count
		r.Tasks++
		r.TaskStates[task.State]++
	}
	if r.Tasks == 0 {
		return r, fmt.Errorf("no tasks in verification scope %q", taskID)
	}
	r.Verified = true
	return r, nil
}

func (s *Store) verifyTaskRows(ctx context.Context, task evidence.Task) (count, refs int64, err error) {
	type stored struct {
		seq  int64
		id   string
		body []byte
	}
	var after int64
	for {
		rows, err := s.db.QueryContext(ctx, "SELECT seq,row_id,body FROM results WHERE task_id=? AND seq>? ORDER BY seq LIMIT 500", task.ID, after)
		if err != nil {
			return count, refs, err
		}
		page := make([]stored, 0, 500)
		for rows.Next() {
			var v stored
			if err = rows.Scan(&v.seq, &v.id, &v.body); err != nil {
				break
			}
			page = append(page, v)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close() // release the single connection before reference queries
		if err != nil {
			return count, refs, err
		}
		for _, v := range page {
			if err := ctx.Err(); err != nil {
				return count, refs, err
			}
			var row evidence.Row
			if err := json.Unmarshal(v.body, &row); err != nil {
				return count, refs, fmt.Errorf("result %d: %w", v.seq, err)
			}
			if v.id != row.ID {
				return count, refs, fmt.Errorf("result %d index identity mismatch", v.seq)
			}
			if err := row.Verify(); err != nil {
				return count, refs, fmt.Errorf("result %d: %w", v.seq, err)
			}
			if err := verifyRowOwner(task, row); err != nil {
				return count, refs, err
			}
			if row.ParentID != "" {
				var exists bool
				if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM results WHERE task_id=? AND row_id=? AND seq<?)", task.ID, row.ParentID, v.seq).Scan(&exists); err != nil {
					return count, refs, err
				}
				if !exists {
					return count, refs, fmt.Errorf("result %d has absent or forward parent", v.seq)
				}
			}
			for _, cell := range row.Cells {
				if cell.Kind != "references" {
					continue
				}
				body, err := json.Marshal(cell.Data)
				if err != nil {
					return count, refs, err
				}
				var ids []string
				if err := json.Unmarshal(body, &ids); err != nil || len(ids) == 0 {
					return count, refs, fmt.Errorf("result %d has malformed references", v.seq)
				}
				for _, id := range ids {
					ref, err := s.Find(ctx, id)
					if err != nil {
						return count, refs, fmt.Errorf("result %d reference %s: %w", v.seq, id, err)
					}
					if err := ref.Verify(); err != nil {
						return count, refs, err
					}
					if ref.ID != id || ref.Provenance.ImageSHA256 != row.Provenance.ImageSHA256 {
						return count, refs, fmt.Errorf("result %d reference image or identity mismatch", v.seq)
					}
					refs++
				}
			}
			count++
			after = v.seq
		}
		if len(page) < 500 {
			return count, refs, nil
		}
	}
}

func verifyRowOwner(task evidence.Task, row evidence.Row) error {
	claimed := row.Provenance
	if task.Plugin == "triage" {
		// Findings intentionally inherit the source plugin's symbols/parameters
		// and use triage.<rule> rather than pretending to be raw triage output.
		if !strings.HasPrefix(claimed.Plugin, "triage.") || claimed.Plugin == "triage." ||
			claimed.ImageSHA256 != task.Provenance.ImageSHA256 || claimed.Engine != task.Provenance.Engine ||
			claimed.EngineBuild != task.Provenance.EngineBuild {
			return fmt.Errorf("finding %s task provenance mismatch", row.ID)
		}
		return nil
	}
	claimed.Layer, claimed.Offset = task.Provenance.Layer, task.Provenance.Offset
	x, err := json.Marshal(claimed)
	if err != nil {
		return err
	}
	y, err := json.Marshal(task.Provenance)
	if err != nil {
		return err
	}
	if !bytes.Equal(x, y) {
		return fmt.Errorf("result %s task provenance mismatch", row.ID)
	}
	return nil
}
