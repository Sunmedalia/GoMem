package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxPsCallStack(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_PSCALLSTACK_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional Debian corpus and pinned PID 1/2 callstack reference; not acceptance")
	}
	raw, err := os.ReadFile(prefix + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Baseline   struct{ Commit string }
		Plugin     string
		Parameters []string
		Image      string `json:"image_sha256"`
		Output     string `json:"output_sha256"`
	}
	if err = json.Unmarshal(raw, &m); err != nil || m.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || m.Plugin != "linux.pscallstack" {
		t.Fatal(m, err)
	}
	if len(m.Parameters) < 2 || m.Parameters[0] != "--pid" || (m.Parameters[1] != "1" && m.Parameters[1] != "2") {
		t.Fatal("unexpected reference parameters", m.Parameters)
	}
	params := map[string]string{"pid": m.Parameters[1]}
	switch {
	case len(m.Parameters) == 2:
	case len(m.Parameters) == 3 && m.Parameters[2] == "--unresolved":
		params["unresolved"] = "true"
	default:
		t.Fatal("unexpected reference parameters", m.Parameters)
	}
	raw, err = os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != m.Output {
		t.Fatal("reference digest")
	}
	var want []callStackRow
	if err = json.Unmarshal(raw, &want); err != nil || len(want) == 0 {
		t.Fatal(err, len(want))
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != m.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	got := []callStackRow(nil)
	reads, taskSummaries, summaries := 0, 0, 0
	var fresh, cached bytes.Buffer
	result, err := e.Run(context.Background(), "linux.pscallstack", params, engine.RunOptions{Emit: func(row evidence.Row) error {
		if er := row.Verify(); er != nil {
			t.Fatal(er)
		}
		switch row.Cells["RecordType"].String() {
		case "stack_entry":
			got = append(got, callStackSelected(row))
		case "stack_read":
			reads += verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
		case "stack_summary":
			summaries++
		case "task_stack_summary":
			taskSummaries++
		default:
			t.Fatal("unexpected diagnostic", row)
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, want) || reads == 0 || taskSummaries != 1 || summaries != 1 {
		t.Fatal(result, err, len(got), len(want), reads, taskSummaries, summaries)
	}
	for offset := 0; offset < int(result.Task.Rows); {
		rows, er := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
		if er != nil || len(rows) == 0 {
			t.Fatal(er)
		}
		for _, row := range rows {
			if er := row.Verify(); er != nil {
				t.Fatal(er)
			}
		}
		offset += len(rows)
	}
	next, err := e.Run(context.Background(), "linux.pscallstack", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
	if err != nil || !next.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
		t.Fatal(next, err)
	}
	t.Logf("%d eight-field entries, %d independent captures, sealed SQLite and byte-identical cache", len(got), reads)
}
