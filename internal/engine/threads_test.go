package engine_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsThreadsIdentityPathsFiltersAndLimits(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	processIDs := map[string]string{}
	if _, err = e.Run(context.Background(), "windows.pslist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["Created"].Kind != "string" {
			t.Fatal("LARGE_INTEGER process creation time lost", row.Cells["Created"])
		}
		processIDs[row.Cells["PID"].String()] = row.Cells["Identity"].String()
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "windows.threads", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
	if err != nil || result.Task.Rows != 3 {
		t.Fatal(result, err)
	}
	for _, row := range rows {
		if err = row.Verify(); err != nil {
			t.Fatal(err)
		}
		pid := row.Cells["PID"].String()
		if row.Cells["ProcessIdentity"].String() != processIDs[pid] || row.Cells["OwnerPIDMatches"].String() != "true" {
			t.Fatal("process identity link mismatch", row)
		}
		if !strings.Contains(row.Cells["CreateTime"].String(), ".1234567Z") {
			t.Fatal("FILETIME precision lost", row.Cells["CreateTime"])
		}
		if row.Cells["CreateTimeRaw"].Kind != "uint64" || row.Cells["ExitTime"].Reason != "not_set" {
			t.Fatal(row)
		}
		if pid == "104" && row.Cells["StartPath"].String() != `\Device\HarddiskVolume1\worker.exe` {
			t.Fatal("VAD-backed start path missing", row.Cells["StartPath"])
		}
		if pid == "4" && row.Cells["StartPath"].Reason != "system_thread_mapping_not_applicable" {
			t.Fatal(row.Cells["StartPath"])
		}
	}
	for _, tc := range []struct {
		pids    string
		threads int64
	}{{"104", 1}, {"4, 104", 3}, {"999", 0}} {
		result, err := e.Run(context.Background(), "windows.threads", map[string]string{"pid": tc.pids}, engine.RunOptions{})
		if err != nil || result.Task.Rows != tc.threads {
			t.Fatal(tc, result, err)
		}
	}
	result, err = e.Run(context.Background(), "windows.threads", map[string]string{"max-threads": "2"}, engine.RunOptions{})
	if err == nil || result.Task.State != "failed" || result.Task.Rows != 2 {
		t.Fatal("bounded traversal must retain partial evidence", result, err)
	}
	for _, parameters := range []map[string]string{{"pid": "4,"}, {"pid": "-1"}, {"max-threads": "0"}} {
		if _, err = e.Run(context.Background(), "windows.threads", parameters, engine.RunOptions{}); err == nil {
			t.Fatal("invalid thread parameters accepted", parameters)
		}
	}
}

func TestIndexedWindowsSymbolsEnableResidentTransitionPaths(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the identity large page with 4KiB mappings. The file/control-area
	// page remains resident behind a Windows transition PTE with PFN metadata.
	binary.LittleEndian.PutUint64(data[0x3000:], 0x1a003)
	for n := uint64(0); n < 32; n++ {
		value := n*4096 | 3
		if n == 0x17 {
			value = n*4096 | 0x880 | 1<<45
		}
		binary.LittleEndian.PutUint64(data[0x1a000+n*8:], value)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	index, err := symbols.BuildIndex(context.Background(), []string{f.Symbols})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "index.json")
	saveIndex(t, index, path)
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, DTB: f.DTB, KernelBase: f.KernelBase, SymbolIndex: path, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	result, err := e.Run(context.Background(), "windows.threads", map[string]string{"pid": "104"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["StartPath"].String() != `\Device\HarddiskVolume1\worker.exe` {
			t.Fatal("indexed Windows identity left a generic translator", row.Cells["StartPath"])
		}
		return nil
	}})
	if err != nil || result.Task.Rows != 1 {
		t.Fatal(result, err)
	}
}

func TestThreadFailuresAreVisibleAndDoNotInventPaths(t *testing.T) {
	for _, scenario := range []string{"thread-cycle", "owner-mismatch", "vad-cycle", "vad-parent", "file-unreadable"} {
		t.Run(scenario, func(t *testing.T) {
			f, err := testfixture.Write(t.TempDir(), "windows")
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "thread-cycle":
				binary.LittleEndian.PutUint64(data[0x12000:], 0x12000)
			case "owner-mismatch":
				binary.LittleEndian.PutUint64(data[0x14010:], 108)
			case "vad-cycle":
				binary.LittleEndian.PutUint64(data[0x15008:], 0x15000)
			case "vad-parent":
				binary.LittleEndian.PutUint64(data[0x16010:], 0)
			case "file-unreadable":
				binary.LittleEndian.PutUint64(data[0x17208:], 0x300000)
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "windows.threads", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			if scenario == "thread-cycle" {
				if err == nil || result.Task.State != "failed" || result.Task.Rows != 1 {
					t.Fatal(result, err)
				}
				return
			}
			if err != nil || len(rows) != 3 {
				t.Fatal(result, err)
			}
			path := rows[2].Cells["StartPath"]
			if path.Kind != "missing" {
				t.Fatal("failed metadata became a clean filename", path)
			}
			if scenario == "owner-mismatch" {
				if path.Reason != "owner_pid_mismatch" || rows[2].Cells["OwnerPIDMatches"].String() != "false" {
					t.Fatal(rows[2])
				}
			} else if path.Error == "" {
				t.Fatal("raw VAD/file error disappeared", path)
			}
		})
	}
}
