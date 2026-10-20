package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsDLLsAndExplicitDiagnostics(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected DLL corpus; not full acceptance")
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
	f, err := os.Open(filepath.Join(dir, "reference-windows-dlllist.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	var reference []map[string]any
	err = decoder.Decode(&reference)
	f.Close()
	if err != nil || len(reference) != 5742 {
		t.Fatal("reference drift", len(reference), err)
	}
	key := func(pid, base, size string) string { return pid + "/" + base + "/" + size }
	// Native then WoW64 loader order is shared with the pinned reference.
	// Keep duplicate core keys: two module bases occur in both PEB lists.
	groups := map[string][]map[string]any{}
	for _, r := range reference {
		k := key(r["PID"].(json.Number).String(), r["Base"].(json.Number).String(), r["Size"].(json.Number).String())
		groups[k] = append(groups[k], r)
	}
	modules, diagnostics, wow, nativeCounts, nativeTimes, readNames, readPaths, independentPaths := 0, 0, 0, 0, 0, 0, 0, 0
	result, err := e.Run(ctx, "windows.dlllist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		c := row.Cells
		if c["RecordType"].String() == "diagnostic" {
			diagnostics++
			if c["Error"].Error == "" {
				return fmt.Errorf("diagnostic lacks source error")
			}
			return nil
		}
		modules++
		base, err := c["Base"].Uint()
		if err != nil {
			return err
		}
		size, err := c["Size"].Uint()
		if err != nil {
			return err
		}
		k := key(c["PID"].String(), strconv.FormatUint(base, 10), strconv.FormatUint(size, 10))
		group := groups[k]
		if len(group) == 0 {
			return fmt.Errorf("unexpected/duplicate DLL %s", k)
		}
		ref := group[0]
		groups[k] = group[1:]
		if c["Process"].String() != ref["Process"] {
			return fmt.Errorf("DLL process name differs")
		}
		for _, field := range []string{"Name", "Path"} {
			cell := c[field]
			if cell.Kind == "missing" {
				if cell.Error == "" || ref[field] != nil {
					return fmt.Errorf("unexplained unreadable DLL %s", field)
				}
			} else if cell.String() != ref[field] {
				if field != "Path" || ref[field] != nil || c["Name"].Kind != "missing" {
					return fmt.Errorf("DLL %s differs", field)
				}
				independentPaths++
			} else if field == "Name" {
				readNames++
			} else {
				readPaths++
			}
		}
		if c["Architecture"].String() == "wow64-x86" {
			wow++
			if c["LoadTime"].Reason != "unsupported_loader_field" || c["LoadCount"].Reason != "unsupported_loader_field" {
				return fmt.Errorf("unverified WoW64 loader fields interpreted")
			}
		} else {
			n, err := c["LoadCount"].Int()
			if err != nil {
				return err
			}
			want, err := strconv.ParseInt(ref["LoadCount"].(json.Number).String(), 10, 64)
			if err != nil || n != want {
				return fmt.Errorf("native load count differs")
			}
			nativeCounts++
			if c["LoadTime"].Kind == "missing" {
				if c["LoadTime"].Error == "" || ref["LoadTime"] != nil {
					return fmt.Errorf("unexplained missing load time")
				}
			} else {
				actual, err := time.Parse(time.RFC3339Nano, c["LoadTime"].String())
				if err != nil {
					return err
				}
				expected, err := time.Parse(time.RFC3339Nano, ref["LoadTime"].(string))
				if err != nil || !actual.Truncate(time.Second).Equal(expected) {
					return fmt.Errorf("native load time differs")
				}
				nativeTimes++
			}
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || modules != 5742 || diagnostics != 19 || result.Task.Rows != 5761 || wow != 217 || nativeCounts != 5525 || nativeTimes != 5524 || readNames != 5414 || readPaths != 5410 || independentPaths != 21 {
		t.Fatal(result, modules, diagnostics, wow, nativeCounts, nativeTimes, readNames, readPaths, independentPaths, err)
	}
	for k, group := range groups {
		if len(group) != 0 {
			t.Fatal("missing reference module", k)
		}
	}
}
