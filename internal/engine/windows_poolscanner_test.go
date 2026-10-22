package engine_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsPoolScannerSealedStorageCacheAndFailedRetry(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/windows-poolscanner-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Width, Size int
			ISF         json.RawMessage
			Writes      []struct {
				Offset int
				Data   string
			}
			Rows [][]json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 36 {
		t.Fatal("fixture drift")
	}
	for index, c := range fixture.Cases {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			data := make([]byte, 0x12000)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset+len(b) > len(data) {
					t.Fatal("invalid fixture")
				}
				copy(data[w.Offset:], b)
			}
			// Add a separately validated PE/PDB identity without changing the
			// oracle's pool allocations. The oracle type table contains zeros;
			// its relocated location at 0x11000 retains those original values.
			arch := "x64"
			if c.Width == 4 {
				arch = "x86"
			}
			var identity windowsRegexCase
			for _, candidate := range windowsRegexCases(t) {
				if candidate.Arch == arch && candidate.Name == "literal" {
					identity = candidate
					break
				}
			}
			for _, w := range identity.Writes {
				if w.Offset < 0x10000 || w.Offset >= 0x12000 {
					continue
				}
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset+len(b) > 0x12000 {
					t.Fatal("invalid PE fixture")
				}
				copy(data[w.Offset:], b)
			}
			var table, source map[string]json.RawMessage
			if err := json.Unmarshal(c.ISF, &table); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(identity.ISF, &source); err != nil {
				t.Fatal(err)
			}
			table["metadata"] = source["metadata"]
			isf, err := json.Marshal(table)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
			if err := os.WriteFile(image, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(symbol, isf, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, OS: "windows", Arch: arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var wire bytes.Buffer
			objects := 0
			result, err := e.Run(context.Background(), "windows.poolscanner", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "pool_object" {
					objects++
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			if err != nil || result.Reused || objects != len(c.Rows) {
				t.Fatal("initial task", err, result.Reused, objects)
			}
			var stored bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if err := row.Verify(); err != nil {
						t.Fatal(err)
					}
					if err := json.NewEncoder(&stored).Encode(row); err != nil {
						t.Fatal(err)
					}
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("stored evidence differs")
			}
			var replay bytes.Buffer
			cached, err := e.Run(context.Background(), "windows.poolscanner", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
			if err != nil || !cached.Reused || !bytes.Equal(wire.Bytes(), replay.Bytes()) {
				t.Fatal("cache replay differs", err, cached.Reused)
			}
			for retry := 0; retry < 2; retry++ {
				failed, err := e.Run(context.Background(), "windows.poolscanner", map[string]string{"max-reads": "1"}, engine.RunOptions{})
				if err == nil || failed.Reused {
					t.Fatal("failed task cached as success", err, failed.Reused)
				}
			}
		})
	}
}
