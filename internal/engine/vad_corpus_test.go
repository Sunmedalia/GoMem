package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsModernVADs(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional official corpus: set GOMEM_CORPUS_DIR; not full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
		t.Fatal("official image drift", e.Hash)
	}
	f, err := os.Open(filepath.Join(dir, "reference-windows-vadinfo.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	var reference []map[string]any
	err = decoder.Decode(&reference)
	f.Close()
	if err != nil || len(reference) != 19999 {
		t.Fatal("reference corpus drift", len(reference), err)
	}
	byObject := map[string]map[string]any{}
	for _, row := range reference {
		key := row["PID"].(json.Number).String() + "/" + row["Offset"].(json.Number).String()
		if byObject[key] != nil {
			t.Fatal("duplicate reference VAD", key)
		}
		byObject[key] = row
	}
	pathReadErrors := 0
	result, err := e.Run(ctx, "windows.vadinfo", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		a, err := row.Cells["Offset"].Uint()
		if err != nil {
			return err
		}
		key := row.Cells["PID"].String() + "/" + strconv.FormatUint(a, 10)
		ref := byObject[key]
		if ref == nil {
			return fmt.Errorf("unexpected/duplicate VAD %s", key)
		}
		delete(byObject, key)
		for native, reference := range map[string]string{"Start": "Start VPN", "End": "End VPN", "CommitCharge": "CommitCharge", "PrivateMemory": "PrivateMemory", "Parent": "Parent"} {
			actual, err := row.Cells[native].Uint()
			if err != nil {
				return err
			}
			want, err := strconv.ParseUint(ref[reference].(json.Number).String(), 10, 64)
			if err != nil || actual != want {
				return fmt.Errorf("VAD %s %s differs", key, native)
			}
		}
		for _, field := range []string{"Process", "Tag", "Protection"} {
			if row.Cells[field].Kind != "string" || row.Cells[field].String() != ref[field] {
				return fmt.Errorf("VAD %s %s differs", key, field)
			}
		}
		path := row.Cells["Path"]
		if ref["File"] == nil {
			if path.Kind != "missing" {
				return fmt.Errorf("VAD %s unexpected file path", key)
			}
			if path.Error != "" {
				if path.Reason != "unreadable_or_unavailable" {
					return fmt.Errorf("VAD %s unexplained path failure", key)
				}
				pathReadErrors++
			} else if path.Reason != "not_file_backed" {
				return fmt.Errorf("VAD %s unexplained missing path", key)
			}
		} else if path.Kind != "string" || path.String() != ref["File"] {
			return fmt.Errorf("VAD %s file path differs", key)
		}
		return nil
	}})
	if err != nil || result.Task.Rows != 19999 || len(byObject) != 0 || pathReadErrors != 39 {
		t.Fatal(result, len(byObject), pathReadErrors, err)
	}
}
