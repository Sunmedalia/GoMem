package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsHashdump(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 SAM hashes; not full capability acceptance")
	}
	reference := loadHashdumpReference(t, filepath.Join(dir, "reference-windows-hashdump.json"))
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.hashdump", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	var hashes int
	var diagnostic string
	var build string
	for _, row := range rows {
		build = row.Provenance.EngineBuild
		switch row.Cells["RecordType"].String() {
		case "hash":
			hashes++
		case "diagnostic":
			diagnostic = row.Cells["Error"].String()
		default:
			t.Fatal("unexpected record", row.Cells["RecordType"])
		}
	}
	if len(reference) == 0 {
		if err == nil || result.Task.State != "failed" || hashes != 0 || !strings.Contains(diagnostic, "JD") {
			t.Fatalf("state %s hashes %d err %v diagnostic %s", result.Task.State, hashes, err, diagnostic)
		}
		t.Logf("reference rows 0; JD class cell unreadable; build %s", build)
		return
	}
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, err)
	}
	if hashes != len(reference) {
		t.Fatalf("hashes %d reference %d", hashes, len(reference))
	}
	got := map[string]int{}
	for _, row := range rows {
		if row.Cells["RecordType"].String() != "hash" {
			continue
		}
		got[hashIdentity(row)]++
	}
	want := map[string]int{}
	for _, ref := range reference {
		want[ref.identity()]++
	}
	if len(got) != len(want) {
		t.Fatalf("identities native %d reference %d", len(got), len(want))
	}
	for key, n := range want {
		if got[key] != n {
			t.Fatalf("mismatch %s native %d reference %d", key, got[key], n)
		}
	}
	t.Logf("rows %d build %s", hashes, build)
}

type hashRef struct {
	User   *string `json:"User"`
	RID    uint64  `json:"rid"`
	LMHash string  `json:"lmhash"`
	NTHash string  `json:"nthash"`
}

func (r hashRef) identity() string {
	name := "<missing>"
	if r.User != nil {
		name = *r.User
	}
	return strings.Join([]string{name, formatDec(r.RID), r.LMHash, r.NTHash}, "\x00")
}

func hashIdentity(row evidence.Row) string {
	name := "<missing>"
	if row.Cells["User"].Kind == "string" {
		name = row.Cells["User"].String()
	}
	rid, err := row.Cells["rid"].Uint()
	if err != nil {
		return "bad-rid"
	}
	return strings.Join([]string{name, formatDec(rid), row.Cells["lmhash"].String(), row.Cells["nthash"].String()}, "\x00")
}

func formatDec(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func loadHashdumpReference(t *testing.T, path string) []hashRef {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []hashRef
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}
