package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type windowsRegexCase struct {
	Name, Arch, Pattern string
	Size                int
	ISF                 json.RawMessage
	Writes              []struct {
		Offset int
		Data   string
	}
	Rows  [][]json.RawMessage
	Error *string
	PID   []uint64
}

func windowsRegexCases(t testing.TB) []windowsRegexCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []windowsRegexCase
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 57 {
		t.Fatal("fixture drift")
	}
	return fixture.Cases
}

func windowsRegexEngine(t *testing.T, c windowsRegexCase) (*engine.Engine, []byte) {
	t.Helper()
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset+len(raw) > len(data) {
			t.Fatal("invalid fixture")
		}
		copy(data[w.Offset:], raw)
	}
	dir := t.TempDir()
	image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symbol, c.ISF, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, OS: "windows", Arch: c.Arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, data
}

func TestWindowsVADRegexActualGeneratorAndSealedCache(t *testing.T) {
	for _, c := range windowsRegexCases(t) {
		t.Run(c.Arch+"/"+c.Name, func(t *testing.T) {
			e, data := windowsRegexEngine(t, c)
			var all, matches []evidence.Row
			var wire bytes.Buffer
			params := map[string]string{"pattern": c.Pattern, "maxsize": "4"}
			if len(c.PID) > 0 {
				params["pid"] = fmt.Sprint(c.PID[0])
			}
			result, err := e.Run(context.Background(), "windows.vadregexscan", params, engine.RunOptions{Emit: func(row evidence.Row) error {
				all = append(all, row)
				if row.Cells["RecordType"].String() == "regex_match" {
					matches = append(matches, row)
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			damaged := c.Error != nil || c.Name == "missing-page" || c.Name == "padded-context"
			if (err != nil) != damaged || len(matches) != len(c.Rows) {
				t.Fatal("completeness or match count", result.Task.State, err, len(matches), len(c.Rows))
			}
			for i, want := range c.Rows {
				var pid, offset uint64
				var name, text, encoded string
				for n, dst := range []any{&pid, &name, &offset, &text, &encoded} {
					if err := json.Unmarshal(want[n], dst); err != nil {
						t.Fatal(err)
					}
				}
				row := matches[i]
				p, _ := row.Cells["PID"].Uint()
				at, _ := row.Cells["Offset"].Uint()
				if p != pid || at != offset || row.Cells["Process"].String() != name || row.Cells["Text"].String() != text || hex.EncodeToString(stringsEvidenceBytes(t, row.Cells["Hex"])) != encoded {
					t.Fatalf("row %d differs: got %v want %s", i, row.Cells, want)
				}
			}
			verifyRegexRows(t, e, data, all)
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
					json.NewEncoder(&stored).Encode(row)
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("sealed storage changed rows")
			}
			var replay bytes.Buffer
			cached, cause := e.Run(context.Background(), "windows.vadregexscan", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
			if !damaged && (cause != nil || !cached.Reused || !bytes.Equal(wire.Bytes(), replay.Bytes())) {
				t.Fatal("cache replay differs", cause, cached.Reused)
			}
			if damaged && cached.Reused {
				t.Fatal("failed task reused")
			}
		})
	}
}

func TestWindowsVADRegexFailuresNeverBecomeCachedSuccess(t *testing.T) {
	for _, mode := range []string{"cycle", "overlap", "root-zero", "region-bound", "table-bound", "read-bound", "chunk-bound", "proof-bound", "cancel", "emitter"} {
		t.Run(mode, func(t *testing.T) {
			var c windowsRegexCase
			for _, candidate := range windowsRegexCases(t) {
				if candidate.Arch == "x64" && candidate.Name == "adjacent-vads" {
					c = candidate
					break
				}
			}
			mutate := func(at int, value uint64, width int) {
				b := make([]byte, 8)
				binary.LittleEndian.PutUint64(b, value)
				c.Writes = append(c.Writes, struct {
					Offset int
					Data   string
				}{at, hex.EncodeToString(b[:width])})
			}
			switch mode {
			case "cycle":
				mutate(0x1008, 0x1000, 8)
			case "overlap":
				mutate(0x1118, 0x102, 4)
			case "root-zero":
				mutate(0x450, 0, 8)
			}
			e, _ := windowsRegexEngine(t, c)
			params := map[string]string{"pattern": "XYZMATCH"}
			switch mode {
			case "region-bound":
				params["max-regions"] = "1"
			case "table-bound":
				params["max-map-tables"] = "1"
			case "read-bound":
				params["max-read-bytes"] = "1"
			case "chunk-bound":
				params["max-chunks"] = "1"
			case "proof-bound":
				params["max-proof-pages"] = "1"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("output stopped")
			calls := 0
			result, err := e.Run(ctx, "windows.vadregexscan", params, engine.RunOptions{Emit: func(evidence.Row) error {
				calls++
				if mode == "cancel" {
					cancel()
				}
				if mode == "emitter" {
					return sentinel
				}
				return nil
			}})
			if err == nil || result.Task.State == "completed" {
				t.Fatal("failure hidden", result.Task.State, err)
			}
			if mode == "cancel" && (!errors.Is(err, context.Canceled) || calls != 1) {
				t.Fatal("continued after cancellation", calls, err)
			}
			if mode == "emitter" && (!errors.Is(err, sentinel) || calls != 1) {
				t.Fatal("continued after output failure", calls, err)
			}
			replay, cause := e.Run(context.Background(), "windows.vadregexscan", params, engine.RunOptions{})
			if replay.Reused {
				t.Fatal("failed task reused", replay, cause)
			}
		})
	}
}
