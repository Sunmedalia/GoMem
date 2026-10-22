package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsConsolesSealedTreesAndFreshRetry(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/windows-consoles-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Scenario string
 Rows []json.RawMessage
			Layout   string
			Build    uint64
			Revision uint64
			ISF      json.RawMessage
			Size     int
			Writes   []struct {
				Offset int
				Data   string
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var auxiliary struct{ Catalog map[string]string }
	raw, err = os.ReadFile("../../pkg/winconsole/testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &auxiliary); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		if c.Scenario != "normal" && c.Scenario != "command-hole" {
			continue
		}
		t.Run(fmt.Sprintf("%d-%d/%s", c.Build, c.Revision, c.Scenario), func(t *testing.T) {
			dir := t.TempDir()
			image, symbol, cache := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json"), filepath.Join(dir, "symbols")
			data := make([]byte, c.Size)
			for _, w := range c.Writes {
				raw, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset > len(data) || len(raw) > len(data)-w.Offset {
					t.Fatal("invalid original write")
				}
				copy(data[w.Offset:], raw)
			}
			name := c.Layout
			schema := []byte(auxiliary.Catalog[name])
			if len(schema) == 0 {
				t.Fatal("unknown original layout", name)
			}
			hash := sha256.Sum256(schema)
			if err = os.MkdirAll(filepath.Join(cache, "console-symbols"), 0700); err != nil {
				t.Fatal(err)
			}
			for path, data := range map[string][]byte{image: data, symbol: c.ISF, filepath.Join(cache, "console-symbols", fmt.Sprintf("%s-%x.json", name, hash)): schema} {
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, SymbolCache: cache, OS: "windows", Arch: "x64", DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var wire bytes.Buffer
			seen := map[string]bool{}
			properties := 0
			params := map[string]string{"no-registry": "true"}
			result, runErr := e.Run(context.Background(), "windows.consoles", params, engine.RunOptions{Emit: func(row evidence.Row) error {
				if err := row.Verify(); err != nil {
					t.Fatal(err)
				}
				if row.ParentID != "" && !seen[row.ParentID] {
					t.Fatal("unresolved history parent")
				}
				seen[row.ID] = true
				if row.Cells["RecordType"].String() == "console_property" {
					properties++
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			var layout struct { Types map[string]struct { Fields map[string]struct { Type struct { Kind string } } } `json:"user_types"` }
            if err=json.Unmarshal(schema,&layout);err!=nil{t.Fatal(err)}
            failed := c.Scenario == "command-hole" || layout.Types["_EXE_ALIAS_LIST"].Fields["ExeName"].Type.Kind == "pointer"
			if (runErr != nil) != failed || result.Reused {
				t.Fatal(runErr, result.Reused)
			}
			if properties != len(c.Rows) {
				t.Fatal("property count", properties)
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
					json.NewEncoder(&stored).Encode(row)
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(stored.Bytes(), wire.Bytes()) {
				t.Fatal("stored tree differs from wire")
			}
			again, err := e.Run(context.Background(), "windows.consoles", params, engine.RunOptions{})
			// External layout dependency revalidation is not yet in cache keys: all
			// runs stay fresh, including successful runs, and failures never replay.
			if again.Reused || again.Task.ID == result.Task.ID || (err != nil) != failed {
				t.Fatal("unsafe task reuse", again.Reused, err)
			}
		})
	}
}
