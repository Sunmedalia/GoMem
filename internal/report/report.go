// Package report exports persisted evidence without loading all results into RAM.
package report

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/internal/version"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Rows   int64  `json:"rows"`
}
type Manifest struct {
	Schema        string          `json:"schema"`
	Engine        string          `json:"engine"`
	Baseline      string          `json:"baseline"`
	Commit        string          `json:"baseline_commit"`
	Created       time.Time       `json:"created"`
	Tasks         []evidence.Task `json:"tasks"`
	Entries       []Entry         `json:"entries,omitempty"`
	Investigation map[string]any  `json:"investigation"`
	ArtifactIndex *Entry          `json:"artifact_index,omitempty"`
}

func Export(ctx context.Context, s *store.Store, format, name, taskID string) (path string, err error) {
	if s.Dir == "" {
		return "", fmt.Errorf("export requires a persistent --case directory")
	}
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return "", fmt.Errorf("--output must be a filename inside the case exports directory")
	}
	if format != "html" && format != "jsonl" && format != "bundle" && format != "arrow" {
		return "", fmt.Errorf("export format must be html, jsonl, bundle or arrow")
	}
	tasks, err := s.Tasks(ctx)
	if err != nil {
		return "", err
	}
	if taskID != "" {
		found := false
		for _, t := range tasks {
			if t.ID == taskID {
				tasks = []evidence.Task{t}
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("unknown task %s", taskID)
		}
	}
	if len(tasks) == 0 {
		return "", fmt.Errorf("case has no tasks")
	}
	for _, t := range tasks {
		if t.State == "running" {
			return "", fmt.Errorf("finish or cancel running tasks before exporting a consistent case")
		}
	}
	investigation, err := s.Investigation(ctx)
	if err != nil {
		return "", err
	}
	m := Manifest{Schema: "gomem.evidence/v1", Engine: version.Version, Baseline: version.Baseline, Commit: version.BaselineCommit, Created: time.Now().UTC(), Tasks: tasks, Investigation: investigation}
	for _, task := range tasks {
		page, e := s.ArtifactPage(ctx, task.ID, 0, 1)
		if e != nil {
			return "", e
		}
		if len(page) > 0 {
			m.Schema = "gomem.evidence/v2"
			break
		}
	}
	dir := filepath.Join(s.Dir, "exports")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	path = filepath.Join(dir, name)
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			_ = root.Remove(name)
		}
	}()
	switch format {
	case "arrow":
		err = arrowReport(ctx, s, f, m)
	case "bundle":
		err = bundle(ctx, s, f, &m)
	case "html":
		err = htmlReport(ctx, s, f, m)
	case "jsonl":
		enc := json.NewEncoder(f)
		err = enc.Encode(map[string]any{"record_type": "manifest", "manifest": m})
		if err == nil {
			for _, t := range tasks {
				if err = each(ctx, s, t.ID, func(row evidence.Row) error {
					return enc.Encode(map[string]any{"record_type": "evidence", "task_id": t.ID, "row": row})
				}); err != nil {
					break
				}
			}
		}
		if err == nil && m.Schema == "gomem.evidence/v2" {
			err = artifactsJSONL(ctx, s, f, tasks)
		}
	}
	if err == nil {
		err = f.Sync()
	}
	return path, err
}
func each(ctx context.Context, s *store.Store, id string, emit func(evidence.Row) error) error {
	for off := 0; ; off += 500 {
		rows, err := s.Query(ctx, evidence.Query{TaskID: id, Offset: off, Limit: 500})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err = emit(r); err != nil {
				return err
			}
		}
		if len(rows) < 500 {
			return nil
		}
	}
}
func bundle(ctx context.Context, s *store.Store, w io.Writer, m *Manifest) error {
	z := zip.NewWriter(w)
	for _, t := range m.Tasks {
		name := "results/" + t.ID + ".jsonl"
		part, err := z.Create(name)
		if err != nil {
			z.Close()
			return err
		}
		hash := sha256.New()
		enc := json.NewEncoder(io.MultiWriter(part, hash))
		var n int64
		if err = each(ctx, s, t.ID, func(r evidence.Row) error { n++; return enc.Encode(r) }); err != nil {
			z.Close()
			return err
		}
		m.Entries = append(m.Entries, Entry{name, hex.EncodeToString(hash.Sum(nil)), n})
	}
	if m.Schema == "gomem.evidence/v2" {
		if err := bundleArtifacts(ctx, s, z, m); err != nil {
			z.Close()
			return err
		}
	}
	f, err := z.Create("manifest.json")
	if err == nil {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		err = enc.Encode(m)
	}
	return errors.Join(err, z.Close())
}

var head = template.Must(template.New("head").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>GoMem Investigation</title><style>body{font:15px system-ui;max-width:1200px;margin:3rem auto;padding:0 1rem;color:#172b3a;background:#f3f6f8}h1{letter-spacing:-.05em;font-size:3rem}section{background:white;padding:1.5rem;margin:1.5rem 0;border:1px solid #cad5de}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px monospace}td,th{text-align:left;padding:.5rem;border-bottom:1px solid #ddd;vertical-align:top}table{width:100%;border-collapse:collapse}.state{font-weight:bold;color:#7c3212}</style><h1>GoMem / Investigation</h1><p>Development preview · {{.Engine}} · Volatility baseline {{.Baseline}}</p><p>Generated {{.Created}}. Task states and errors below determine coverage. This report does not certify an image as clean.</p>`))
var taskTemplate = template.Must(template.New("task").Parse(`<section><h2>{{.Plugin}}</h2><p class="state">{{.State}} · {{.Rows}} rows · {{.ID}}</p>{{if .Error}}<pre>{{.Error}}</pre>{{end}}<pre>Image SHA-256: {{.Provenance.ImageSHA256}}
Symbols SHA-256: {{.Provenance.SymbolsSHA256}}</pre><table><tr><th>Evidence / provenance</th><th>Typed values</th></tr>`))
var rowTemplate = template.Must(template.New("row").Parse(`<tr><td><pre>{{.ID}}
Parent: {{.ParentID}}
{{.Provenance.Layer}}
{{.Provenance.Offset}}</pre></td><td><pre>{{.Cells}}</pre></td></tr>`))
var manifestTemplate = template.Must(template.New("manifest").Parse(`<section><h2>Manifest</h2><pre>{{.}}</pre></section></html>`))
var artifactTemplate = template.Must(template.New("artifact").Parse(`<section><h2>Extracted file</h2><pre>{{.}}</pre></section>`))

func htmlReport(ctx context.Context, s *store.Store, w io.Writer, m Manifest) error {
	if err := head.Execute(w, m); err != nil {
		return err
	}
	for _, t := range m.Tasks {
		if err := taskTemplate.Execute(w, t); err != nil {
			return err
		}
		if err := each(ctx, s, t.ID, func(r evidence.Row) error {
			cells, err := json.MarshalIndent(r.Cells, "", "  ")
			if err != nil {
				return err
			}
			return rowTemplate.Execute(w, struct {
				ID, ParentID string
				Provenance   evidence.Provenance
				Cells        string
			}{r.ID, r.ParentID, r.Provenance, string(cells)})
		}); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "</table></section>"); err != nil {
			return err
		}
	}
	if m.Schema == "gomem.evidence/v2" {
		if err := artifactsHTML(ctx, s, w, m.Tasks); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return manifestTemplate.Execute(w, string(b))
}
