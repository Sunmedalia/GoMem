package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsUserAssist(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 UserAssist rows; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-userassist.json")
	if _, err := os.Stat(reference); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.userassist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, len(rows), err)
	}
	var entities, unreadable int
	var build string
	parents := map[string]evidence.Row{}
	for _, row := range rows {
		build = row.Provenance.EngineBuild
		switch row.Cells["RecordType"].String() {
		case "key":
			entities++
			parents[row.ID] = row
			if row.ParentID != "" || row.Cells["RawData"].String() != "N/A" {
				t.Fatal(row.Cells["Path"], row.ParentID, row.Cells["RawData"])
			}
		case "subkey", "value":
			entities++
			parent, ok := parents[row.ParentID]
			if !ok || parent.Cells["Path"].String() != row.Cells["Path"].String() {
				t.Fatal(row.Cells["Name"], row.ParentID, ok)
			}
		case "unreadable":
			unreadable++
		default:
			t.Fatal(row.Cells["RecordType"])
		}
	}
	if entities != 37 {
		t.Fatalf("entities %d unreadable %d", entities, unreadable)
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	out, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(out)
	for _, row := range rows {
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.userassist.json"))
	report, err := cmd.CombinedOutput()
	var diff struct {
		Matched bool             `json:"matched"`
		Missing []map[string]any `json:"missing"`
		Extra   []map[string]any `json:"extra"`
	}
	if jsonErr := json.Unmarshal(report, &diff); jsonErr != nil {
		t.Fatalf("diff output: %v\n%s", jsonErr, report)
	}
	if err != nil && (diff.Matched || len(diff.Missing) != 1 || len(diff.Extra) != 1) {
		t.Fatalf("diff failed: %v\n%s", err, report)
	}
	if diff.Matched {
		t.Fatal("the nonpresent UEME_CTLSESSION cell was parsed as zeroes")
	}
	miss, extra := diff.Missing[0], diff.Extra[0]
	for _, row := range []map[string]any{miss, extra} {
		if row["Name"] != "UEME_CTLSESSION" || row["Type"] != "Value" || row["HiveName"] != `\??\C:\Users\generic-user\ntuser.dat` {
			t.Fatalf("%v", row["Name"])
		}
	}
	raw, _ := miss["RawData"].(string)
	parts := strings.Fields(raw)
	if len(parts) != 1612 {
		t.Fatalf("padded raw length %d", len(parts))
	}
	for _, part := range parts {
		if part != "00" {
			t.Fatal("baseline padding was not all zeroes")
		}
	}
	if miss["Count"] != "0" || miss["FocusCount"] != "0" || miss["TimeFocused"] != "0:00:00.500000" {
		t.Fatalf("baseline parsed padding: %v %v %v", miss["Count"], miss["FocusCount"], miss["TimeFocused"])
	}
	rawMissing, _ := extra["RawData"].(map[string]any)
	if rawMissing["missing"] != "registry_value_unreadable" || extra["Count"] == "0" {
		t.Fatalf("native fabricated a count: %#v", extra)
	}
	t.Logf("rows %d unreadable %d explained zero-pad 1 build %s", entities, unreadable, build)
}
