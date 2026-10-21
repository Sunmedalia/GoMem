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

func TestOfficialLinuxKmsgDifferentialEvidenceAndCache(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_KMSG_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional corpus and pinned kmsg reference; skipped test is not acceptance")
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
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.kmsg" || len(manifest.Parameters) != 0 {
		t.Fatal(err, manifest)
	}
	raw, err = os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != manifest.Output {
		t.Fatal("reference digest")
	}
	var want []kmsgOracleRow
	if err = json.Unmarshal(raw, &want); err != nil || len(want) != 1445 {
		t.Fatal(err, len(want))
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	got := []kmsgOracleRow{}
	reads, summaries := 0, 0
	var fresh, cached bytes.Buffer
	result, err := e.Run(context.Background(), "linux.kmsg", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Verify() != nil {
			t.Fatal("invalid evidence seal")
		}
		switch row.Cells["RecordType"].String() {
		case "log":
			got = append(got, kmsgRow(row))
		case "ring_read":
			reads++
			verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
		case "ring_summary":
			summaries++
		default:
			t.Fatal(row)
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, want) || reads != 4 || summaries != 1 {
		t.Fatal(result, err, len(got), len(want), reads, summaries, "equal", reflect.DeepEqual(got, want))
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
	again, err := e.Run(context.Background(), "linux.kmsg", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
	if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
		t.Fatal(again, err)
	}
}
