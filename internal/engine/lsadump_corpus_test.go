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

func TestOfficialWindowsLsadump(t *testing.T) {
	testOfficialCredentialDump(t, "windows.lsadump", "reference-windows-lsadump.json", "secret", "Key", "Secret")
}

func TestOfficialWindowsCachedump(t *testing.T) {
	testOfficialCredentialDump(t, "windows.cachedump", "reference-windows-cachedump.json", "credential", "Username", "Hash")
}

func testOfficialCredentialDump(t *testing.T, pluginName, referenceName, recordType, left, right string) {
	t.Helper()
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 LSA corpus; not full capability acceptance")
	}
	reference := loadObjectRows(t, filepath.Join(dir, referenceName))
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, pluginName, nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if verifyErr := row.Verify(); verifyErr != nil {
			return verifyErr
		}
		rows = append(rows, row)
		return nil
	}})
	var entities int
	var diagnostic string
	var build string
	for _, row := range rows {
		build = row.Provenance.EngineBuild
		switch row.Cells["RecordType"].String() {
		case recordType:
			entities++
		case "diagnostic":
			diagnostic = row.Cells["Error"].String()
		default:
			t.Fatal(pluginName, "unexpected record", row.Cells["RecordType"])
		}
	}
	if len(reference) == 0 {
		if err == nil || result.Task.State != "failed" || entities != 0 || !strings.Contains(diagnostic, "JD") {
			t.Fatalf("%s state %s entities %d err %v diagnostic %s", pluginName, result.Task.State, entities, err, diagnostic)
		}
		t.Logf("%s reference rows 0; JD class cell unreadable; build %s", pluginName, build)
		return
	}
	if err != nil || result.Task.State != "completed" {
		t.Fatal(pluginName, result.Task.State, err)
	}
	if entities != len(reference) {
		t.Fatalf("%s entities %d reference %d", pluginName, entities, len(reference))
	}
	got := map[string]int{}
	for _, row := range rows {
		if row.Cells["RecordType"].String() != recordType {
			continue
		}
		got[row.Cells[left].String()+"\x00"+row.Cells[right].String()]++
	}
	want := map[string]int{}
	for _, ref := range reference {
		want[jsonString(ref[left])+"\x00"+jsonString(ref[right])]++
	}
	if len(got) != len(want) {
		t.Fatalf("%s identities native %d reference %d", pluginName, len(got), len(want))
	}
	for key, n := range want {
		if got[key] != n {
			t.Fatalf("%s mismatch %q native %d reference %d", pluginName, key, got[key], n)
		}
	}
	t.Logf("%s rows %d build %s", pluginName, entities, build)
}

func loadObjectRows(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func jsonString(v any) string {
	if v == nil {
		return "<missing>"
	}
	switch typed := v.(type) {
	case string:
		return typed
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return "<invalid>"
		}
		return string(raw)
	}
}
