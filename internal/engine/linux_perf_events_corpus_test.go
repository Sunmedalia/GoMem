package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// A zero-event real control validates traversal and acquisition, not detection
// of actual perf/eBPF programs or complete plugin acceptance.
func TestOfficialLinuxPerfEventsEmptyControlEvidenceAndCache(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_PERF_EVENTS_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional corpus and pinned perf-events reference; skipped test is not acceptance")
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
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.tracing.perf_events" || len(manifest.Parameters) != 0 {
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
	reads, tasks, selected, summaries := 0, 0, 0, 0
	var fresh, cached bytes.Buffer
	result, err := e.Run(context.Background(), "linux.perf_events", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Verify() != nil {
			t.Fatal("invalid evidence seal")
		}
		switch row.Cells["RecordType"].String() {
		case "perf_event":
			selected++
		case "event_read":
			reads++
			verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
		case "task_observation":
			tasks++
		case "event_summary":
			summaries++
		default:
			t.Fatal(row)
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || selected != 0 || tasks != 316 || reads != 5928 || summaries != 1 {
		t.Fatal(result, err, tasks, reads, selected, summaries)
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
	again, err := e.Run(context.Background(), "linux.perf_events", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
	if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
		t.Fatal(again, err)
	}
}
