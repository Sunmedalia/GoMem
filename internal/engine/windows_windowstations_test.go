package engine_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowStationsSealedStorageFreshSymbolsAndFailedRetry(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/windows-windowstations-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Scenario   string
			ISF        json.RawMessage
			Size       int
			KernelBase uint64 `json:"kernel_base"`
			KernelDTB  uint64 `json:"kernel_dtb"`
			Holes      [][2]uint64
			Rows       [][]json.RawMessage
			Writes     []struct {
				Offset int
				Data   string
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 16 {
		t.Fatal("GUI pipeline fixture drift")
	}
	var identity windowsRegexCase
	for _, c := range windowsRegexCases(t) {
		if c.Arch == "x64" && c.Name == "literal" {
			identity = c
			break
		}
	}
	for _, c := range fixture.Cases {
		if len(c.Holes) > 0 {
			continue
		}
		t.Run(c.Scenario, func(t *testing.T) {
			data := make([]byte, c.Size)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset > len(data)-len(b) {
					t.Fatal("invalid GUI fixture", err)
				}
				copy(data[w.Offset:], b)
			}
			for _, w := range identity.Writes {
				if w.Offset < 0x10000 || w.Offset >= 0x12000 {
					continue
				}
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset > len(data)-len(b) {
					t.Fatal("invalid PE fixture", err)
				}
				copy(data[w.Offset:], b)
			}
			var table, source map[string]json.RawMessage
			if err = json.Unmarshal(c.ISF, &table); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(identity.ISF, &source); err != nil {
				t.Fatal(err)
			}
			var meta, original map[string]json.RawMessage
			_ = json.Unmarshal(source["metadata"], &meta)
			_ = json.Unmarshal(table["metadata"], &original)
			var windows, identityWindows map[string]json.RawMessage
			_ = json.Unmarshal(original["windows"], &windows)
			_ = json.Unmarshal(meta["windows"], &identityWindows)
			for key, value := range windows {
				identityWindows[key] = value
			}
			meta["windows"], _ = json.Marshal(identityWindows)
			table["metadata"], _ = json.Marshal(meta)
			isf, err := json.Marshal(table)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
			if err = os.WriteFile(image, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(symbol, isf, 0600); err != nil {
				t.Fatal(err)
			}
			cache := filepath.Join(dir, "symbols")
			catalogPath := seedWindowStationsEngineCatalog(t, cache)
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, OS: "windows", Arch: "x64", DTB: "0x1000", KernelBase: c.KernelBase, CaseDir: filepath.Join(dir, "case"), SymbolCache: cache, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var wire bytes.Buffer
			got := [][]any{}
			result, cause := e.Run(context.Background(), "windows.windowstations", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "windowstation" {
					at, _ := row.Cells["Offset"].Uint()
					sid, _ := row.Cells["SessionId"].Uint()
					got = append(got, []any{at, row.Cells["Name"].String(), sid})
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			failure := c.Scenario == "null-next" || c.Scenario == "bad-session-cr3"
			if (cause != nil) != failure || result.Reused {
				t.Fatal("GUI task state", cause, result.Reused)
			}
			want := [][]any{}
			for _, r := range c.Rows {
				var at, sid uint64
				var name string
				_ = json.Unmarshal(r[0], &at)
				_ = json.Unmarshal(r[1], &name)
				_ = json.Unmarshal(r[2], &sid)
				want = append(want, []any{at, name, sid})
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("GUI engine entity difference", got, want, cause)
			}
			var stored bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if err = row.Verify(); err != nil {
						t.Fatal(err)
					}
					if err = json.NewEncoder(&stored).Encode(row); err != nil {
						t.Fatal(err)
					}
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("GUI sealed evidence differs from stream")
			}
			second, cause := e.Run(context.Background(), "windows.windowstations", nil, engine.RunOptions{})
			if (cause != nil) != failure || second.Reused || second.Task.ID == result.Task.ID {
				t.Fatal("runtime GUI symbols reused without revalidation", cause, second.Reused)
			}
			for retry := 0; retry < 2; retry++ {
				failed, cause := e.Run(context.Background(), "windows.windowstations", map[string]string{"max-reads": "1"}, engine.RunOptions{})
				if cause == nil || failed.Reused {
					t.Fatal("failed GUI task reused as success", cause, failed.Reused)
				}
			}
			if err = os.WriteFile(catalogPath, []byte("corrupt GUI cache"), 0600); err != nil {
				t.Fatal(err)
			}
			rejected, cause := e.Run(context.Background(), "windows.windowstations", nil, engine.RunOptions{})
			if cause == nil || rejected.Reused {
				t.Fatal("stale task hid corrupt GUI layout", cause, rejected.Reused)
			}
		})
	}
}
func seedWindowStationsEngineCatalog(t testing.TB, cache string) string {
	t.Helper()
	raw, err := os.ReadFile("../../pkg/wingui/testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Catalog map[string]struct {
			SHA256 string
			Source string `json:"source_gzip_base64"`
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	name := "gui-win10-19041-x64"
	c := f.Catalog[name]
	encoded, err := base64.StdEncoding.DecodeString(c.Source)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(z, (4<<20)+1))
	_ = z.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != c.SHA256 {
		t.Fatal("GUI catalog digest mismatch")
	}
	path := filepath.Join(cache, "gui", name+"-"+c.SHA256+".json")
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
