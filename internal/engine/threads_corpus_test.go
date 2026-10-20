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

// This checks the explicit eight-field profile and separately accounts for the
// baseline's signed ExitTime union values. It never treats an unreadable path
// as equivalent to a reference null, or declares complete plugin acceptance.
func TestOfficialWindowsThreads(t *testing.T) {
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
	if e.Config.DTB != "0x6d4000" || e.WindowsDiscovery == nil || e.WindowsDiscovery.InitialDTB != "0x112c98000" {
		t.Fatal("unexpected System root proof", e.Config, e.WindowsDiscovery)
	}
	data, err := os.ReadFile(filepath.Join(dir, "reference-windows-threads.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reference []map[string]any
	// Addresses in this particular baseline output have been masked to 48 bits,
	// hence JSON float64 is exact. Native results retain all address bits.
	if err = json.Unmarshal(data, &reference); err != nil {
		t.Fatal(err)
	}
	if len(reference) != 1752 {
		t.Fatal("reference corpus drift", len(reference))
	}
	byOffset := map[uint64]map[string]any{}
	for _, row := range reference {
		a := uint64(row["Offset"].(float64))
		if byOffset[a] != nil {
			t.Fatal("duplicate reference thread object")
		}
		byOffset[a] = row
	}
	validExits, invalidExits := 0, 0
	result, err := e.Run(ctx, "windows.threads", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		a, _ := row.Cells["Offset"].Uint()
		a &= 0xffffffffffff
		ref := byOffset[a]
		if ref == nil {
			return fmt.Errorf("unexpected/duplicate thread %#x", a)
		}
		delete(byOffset, a)
		for _, field := range []string{"PID", "TID", "StartAddress", "Win32StartAddress"} {
			n, err := row.Cells[field].Uint()
			if err != nil {
				return err
			}
			if field == "StartAddress" || field == "Win32StartAddress" {
				n &= 0xffffffffffff
			}
			if n != uint64(ref[field].(float64)) {
				return fmt.Errorf("thread %#x %s differs", a, field)
			}
		}
		for _, field := range []string{"StartPath", "Win32StartPath"} {
			cell := row.Cells[field]
			if cell.Kind == "missing" {
				allowed := map[string]bool{"not_set": true, "not_file_backed": true, "not_mapped_in_vad": true, "system_thread_mapping_not_applicable": true}
				if !allowed[cell.Reason] || cell.Error != "" || ref[field] != nil {
					return fmt.Errorf("thread %#x path state differs: %s", a, field)
				}
			} else if cell.String() != ref[field] {
				return fmt.Errorf("thread %#x path differs: %s", a, field)
			}
		}
		compareTime := func(field string) error {
			cell := row.Cells[field]
			if cell.Kind == "missing" && cell.Reason == "not_set" && cell.Error == "" && ref[field] == nil {
				return nil
			}
			stamp, err := time.Parse(time.RFC3339Nano, cell.String())
			if err != nil {
				return err
			}
			want, err := time.Parse(time.RFC3339Nano, ref[field].(string))
			if err != nil || !stamp.Truncate(time.Second).Equal(want) {
				return fmt.Errorf("thread %#x time differs: %s", a, field)
			}
			return nil
		}
		if err := compareTime("CreateTime"); err != nil {
			return err
		}
		if row.Cells["ExitTime"].Reason == "invalid_filetime" {
			raw, err := row.Cells["ExitTimeRaw"].Uint()
			if err != nil || raw < 1<<63 {
				return fmt.Errorf("invalid exit without preserved unsigned bits: %s", strconv.FormatUint(raw, 16))
			}
			stamp, err := time.Parse(time.RFC3339Nano, ref["ExitTime"].(string))
			// Python's baseline uses floor division on a signed QuadPart.
			signed := int64(raw)
			seconds := signed / 10000000
			if signed%10000000 < 0 {
				seconds--
			}
			if err != nil || stamp.Year() != 1600 || !time.Unix(seconds-11644473600, 0).Equal(stamp) {
				return fmt.Errorf("unexplained ExitTime difference")
			}
			invalidExits++
		} else {
			if err := compareTime("ExitTime"); err != nil {
				return err
			}
			validExits++
		}
		return nil
	}})
	if err != nil || result.Task.Rows != 1752 || len(byOffset) != 0 || validExits != 91 || invalidExits != 1661 {
		t.Fatal(result, len(byOffset), validExits, invalidExits, err)
	}
}
