package engine_test

import (
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

// Exact entity equality does not turn partial acquisition into a completed task.
func TestOfficialLinuxKallsymsSourcesPartialControl(t *testing.T) {
	dir, prefix := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_KALLSYMS_REFERENCE")
	if dir == "" || prefix == "" {
		t.Skip("requires optional corpus and pinned full kallsyms reference; not acceptance")
	}
	raw, err := os.ReadFile(prefix + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline   struct{ Commit string }
		Plugin     string
		Parameters []string
		Image      string `json:"image_sha256"`
		Output     string `json:"output_sha256"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.kallsyms" || len(manifest.Parameters) != 0 {
		t.Fatal(manifest, err)
	}
	raw, err = os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != manifest.Output {
		t.Fatal("reference digest")
	}
	var reference []struct {
		Addr                              uint64
		Type                              *string
		Size                              *uint64
		Exported                          *bool
		SubSystem, ModuleName, SymbolName string
		Description                       *string
	}
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 34472 {
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
	selected, reads, partial, sources, affected := 0, 0, 0, 0, 0
	result, err := e.Run(context.Background(), "linux.kallsyms", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Verify() != nil {
			t.Fatal("invalid seal")
		}
		switch row.Cells["RecordType"].String() {
		case "symbol":
			if selected >= len(reference) {
				t.Fatal("extra symbol")
			}
			r := reference[selected]
			want := kallsymsRow{Name: r.SymbolName, Type: r.Type, Address: r.Addr, Size: r.Size, Exported: r.Exported, Module: r.ModuleName, Subsystem: r.SubSystem, Description: r.Description}
			if got := kallsymsSelected(row); !reflect.DeepEqual(got, want) {
				t.Fatalf("index %d got %+v want %+v", selected, got, want)
			}
			if row.Cells["Error"].Reason == "symbol_name_acquisition_incomplete" {
				affected++
				if row.Cells["Error"].Error == "" {
					t.Fatal(row)
				}
			}
			selected++
		case "symbol_read":
			reads++
			verifyTracepointCorpusCapture(t, e, row.Cells["FieldEvidence"])
			raw, err := json.Marshal(row.Cells["FieldEvidence"].Data)
			if err != nil {
				t.Fatal(err)
			}
			var proof map[string]evidence.Value
			if err = json.Unmarshal(raw, &proof); err != nil {
				t.Fatal(err)
			}
			if proof["ReadComplete"].Data == false {
				partial++
			}
		case "symbol_source":
			sources++
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || result.Reused || selected != 34472 || partial != 65 || reads < 50000 || sources < 4 || affected == 0 {
		t.Fatal(result, err, selected, reads, partial, sources, affected)
	}
	stored := 0
	for offset := 0; offset < int(result.Task.Rows); {
		rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
		if err != nil || len(rows) == 0 {
			t.Fatal(offset, err)
		}
		for _, row := range rows {
			if row.Verify() != nil {
				t.Fatal("stored seal")
			}
			stored++
		}
		offset += len(rows)
	}
	if stored != int(result.Task.Rows) {
		t.Fatal(stored, result.Task.Rows)
	}
	t.Logf("%d symbols match all eight columns; %d reads (%d partial), %d affected entities and %d sealed rows; task remains failed", selected, reads, partial, affected, stored)
}
