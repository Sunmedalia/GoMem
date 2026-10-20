package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsHiveScan(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 big-pool hive offsets; not full capability acceptance")
	}
	reference := loadHiveScanReference(t, filepath.Join(dir, "reference-windows-hivescan.json"))
	if len(reference) != 24 {
		t.Fatal(len(reference))
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.hivescan", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, len(rows), err)
	}
	const mask = uint64(0x0000ffffffffffff)
	got := map[uint64]int{}
	var summary evidence.Row
	var summaries int
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "summary":
			summaries++
			summary = row
		case "hive":
			offset, err := row.Cells["Offset"].Uint()
			signature, sigErr := row.Cells["Signature"].Uint()
			if err != nil || sigErr != nil || signature != 0xBEE0BEE0 || row.Cells["Tag"].String() != "CM10" {
				t.Fatal(row.Cells, err, sigErr)
			}
			got[offset&mask]++
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
	}
	want := map[uint64]int{}
	for _, ref := range reference {
		want[ref&mask]++
	}
	if summaries != 1 || len(got) != 24 || len(want) != 24 {
		t.Fatal(summaries, len(got), len(want))
	}
	for key, n := range want {
		if got[key] != n {
			t.Fatalf("offset %#x native %d reference %d", key, got[key], n)
		}
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["entries"] != "32768" || coverage["hits"] != "24" || coverage["read_failures"] != "0" || summary.Cells["Error"].Reason != "not_applicable" {
		t.Fatal(summary.Cells)
	}
	t.Logf("hives 24 table-entries 32768 build %s", rows[0].Provenance.EngineBuild)
}

func loadHiveScanReference(t *testing.T, path string) []uint64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Offset uint64 `json:"Offset"`
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	out := make([]uint64, len(rows))
	for i, row := range rows {
		out[i] = row.Offset
	}
	return out
}
