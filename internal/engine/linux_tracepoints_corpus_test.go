package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// An empty-probe control validates acquisition, not real positive probe detection.
func TestOfficialLinuxTracepointsEmptyControlEvidenceAndCache(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_TRACEPOINTS_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional corpus and pinned tracepoints reference; skipped test is not acceptance")
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
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.tracing.tracepoints" || len(manifest.Parameters) != 0 {
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
	result, err := e.Run(context.Background(), "linux.check_tracepoints", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Verify() != nil {
			t.Fatal("invalid evidence seal")
		}
		switch row.Cells["RecordType"].String() {
		case "tracepoint_probe":
			selected++
		case "tracepoint_read":
			reads++
			verifyTracepointCorpusCapture(t, e, row.Cells["FieldEvidence"])
		case "tracepoint_observation":
			tasks++
		case "tracepoints_summary":
			summaries++
		default:
			// Shared module-source evidence is retained alongside tracepoints.
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || selected != 0 || tasks != 202 || reads != 5128 || summaries != 1 {
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
	again, err := e.Run(context.Background(), "linux.check_tracepoints", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
	if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
		t.Fatal(again, err)
	}
}

// Verify successful captures and expected scanner read holes independently.
func verifyTracepointCorpusCapture(t *testing.T, e *engine.Engine, value evidence.Value) {
	t.Helper()
	raw, err := json.Marshal(value.Data)
	if err != nil {
		t.Fatal(err)
	}
	var proof map[string]evidence.Value
	if err = json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	at, err := proof["Address"].Uint()
	if err != nil {
		t.Fatal(err)
	}
	want, err := proof["RequestedBytes"].Uint()
	if err != nil || want > 16<<20 {
		t.Fatal(want, err)
	}
	captured, err := proof["CapturedBytes"].Uint()
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Raw struct {
			Data []byte `json:"value"`
		}
	}
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, int(want))
	n, cause := e.Env.Kernel.ReadAt(context.Background(), actual, at)
	if cause == nil && n != len(actual) {
		cause = io.ErrUnexpectedEOF
	}
	if uint64(n) != captured || !bytes.Equal(actual[:n], wire.Raw.Data) || proof["ReadComplete"].Data != (cause == nil) {
		t.Fatal("capture differs", proof, n, cause)
	}
	if cause != nil && proof["Error"].Error != cause.Error() {
		t.Fatal("read failure differs", proof, cause)
	}
}
