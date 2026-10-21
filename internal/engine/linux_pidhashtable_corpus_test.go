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
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxPIDHashDifferentialEvidenceAndCache(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_PIDHASH_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires corpus and pinned PID reference prefix; skipped test is not acceptance")
	}
	for _, decorate := range []bool{false, true} {
		t.Run(strconv.FormatBool(decorate), func(t *testing.T) {
			referencePrefix := prefix
			if decorate {
				referencePrefix = os.Getenv("GOMEM_PIDHASH_DECORATED_REFERENCE")
				if referencePrefix == "" {
					t.Fatal("decorated reference required")
				}
			}
			raw, err := os.ReadFile(referencePrefix + ".manifest.json")
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
			if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.pidhashtable" {
				t.Fatal(manifest, err)
			}
			expectedParams := []string{}
			if decorate {
				expectedParams = []string{"--decorate-comm"}
			}
			if !reflect.DeepEqual(manifest.Parameters, expectedParams) {
				t.Fatal(manifest.Parameters)
			}
			raw, err = os.ReadFile(referencePrefix + ".json")
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(raw)
			if hex.EncodeToString(hash[:]) != manifest.Output {
				t.Fatal("reference hash mismatch")
			}
			var want []pidOracleRow
			if err = json.Unmarshal(raw, &want); err != nil || len(want) != 316 {
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
			var fresh, cached bytes.Buffer
			got := []pidOracleRow{}
			reads, rejected, summaries := 0, 0, 0
			params := map[string]string{"decorate-comm": strconv.FormatBool(decorate)}
			result, err := e.Run(context.Background(), "linux.pidhashtable", params, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Verify() != nil {
					t.Fatal("invalid row seal")
				}
				switch row.Cells["RecordType"].String() {
				case "task":
					r := pidRow(row)
					r.Offset &= 0x0000ffffffffffff
					got = append(got, r)
				case "index_read":
					reads++
					verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
				case "task_candidate":
					rejected++
				case "index_summary":
					summaries++
				default:
					t.Fatal(row)
				}
				return json.NewEncoder(&fresh).Encode(row)
			}})
			expectedReads := 6492
			if decorate {
				expectedReads += 316
			} // one flags read per accepted task
			if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, want) || reads != expectedReads || rejected != 6 || summaries != 1 {
				t.Fatal(err, result, "rows", len(got), len(want), "captures", reads, rejected, summaries, "equal", reflect.DeepEqual(got, want))
			}
			// Page through every persisted row, including the entire acquisition trace.
			for offset := 0; offset < int(result.Task.Rows); {
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if err != nil || len(rows) == 0 {
					t.Fatal(err, offset)
				}
				for _, row := range rows {
					if row.Verify() != nil {
						t.Fatal("stored seal mismatch")
					}
				}
				offset += len(rows)
			}
			again, err := e.Run(context.Background(), "linux.pidhashtable", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
			if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
				t.Fatal(again, err)
			}
		})
	}
}
