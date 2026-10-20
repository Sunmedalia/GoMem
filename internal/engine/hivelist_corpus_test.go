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

func TestOfficialWindowsRegistryHives(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 registry hives; not full capability acceptance")
	}
	var reference []struct {
		Offset uint64 `json:"Offset"`
		Name   string `json:"FileFullPath"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-windows-hivelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 24 {
		t.Fatal(len(reference), err)
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
		t.Fatal("image drift", e.Hash)
	}
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.hivelist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" || len(rows) != 25 {
		t.Fatal(result, len(rows), err)
	}
	const mask = uint64(0x0000ffffffffffff)
	sources := map[string]int{}
	for i, row := range rows[:24] {
		cells := row.Cells
		if cells["RecordType"].String() != "hive" || cells["FileOutput"].String() != "disabled" || cells["Error"].Reason != "not_applicable" {
			t.Fatal(i, cells)
		}
		signature, err := cells["Signature"].Uint()
		offset, err2 := cells["Offset"].Uint()
		if err != nil || err2 != nil || signature != 0xBEE0BEE0 || offset&^mask == 0 || offset&mask != reference[i].Offset&mask {
			t.Fatal(i, signature, offset, reference[i].Offset, err, err2)
		}
		full, user, root := cells["FileFullPath"], cells["FileUserName"], cells["HiveRootPath"]
		if full.Kind != "string" || user.Kind != "string" || root.Kind != "string" {
			t.Fatal(i, full, user, root)
		}
		selected, source := full.String(), "FileFullPath"
		if selected == "" {
			selected, source = user.String(), "FileUserName"
		}
		if full.String() == "" && user.String() == "" {
			selected, source = root.String(), "HiveRootPath"
		}
		if full.String() == "" && user.String() == "" && root.String() == "" {
			selected, source = "", "none"
		}
		if cells["Name"].String() != selected || cells["Name"].String() != reference[i].Name || cells["NameSource"].String() != source {
			t.Fatal(i, cells["Name"], source, reference[i].Name)
		}
		sources[source]++
	}
	if sources["FileFullPath"] != 0 || sources["FileUserName"] != 21 || sources["HiveRootPath"] != 2 || sources["none"] != 1 {
		t.Fatal(sources)
	}
	summary := rows[24].Cells
	coverage, ok := summary["Coverage"].Data.(map[string]any)
	if !ok || summary["RecordType"].String() != "summary" || summary["Error"].Reason != "not_applicable" || coverage["hives"] != "24" || coverage["diagnostics"] != "0" {
		t.Fatal(summary)
	}
	var filtered []evidence.Row
	filteredResult, err := e.Run(ctx, "windows.hivelist", map[string]string{"filter": "sam"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		filtered = append(filtered, row)
		return nil
	}})
	if err != nil || filteredResult.Task.State != "completed" || len(filtered) != 2 || !strings.Contains(strings.ToLower(filtered[0].Cells["Name"].String()), "sam") || filtered[1].Cells["RecordType"].String() != "summary" {
		t.Fatal(filteredResult, len(filtered), err)
	}
}
