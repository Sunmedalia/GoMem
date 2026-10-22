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
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type callbackGeneratorCase struct {
	Arch, Scenario string
	Vista, Legacy  bool
	Width, Size    int
	ISF            json.RawMessage
	Writes         []struct {
		Offset int
		Data   string
	}
	Rows  [][]json.RawMessage
	Error *struct{ Type, Message string }
}

func callbackGeneratorExpected(t testing.TB, rows [][]json.RawMessage) map[string]int {
	t.Helper()
	result := map[string]int{}
	for _, row := range rows {
		if len(row) != 5 {
			t.Fatal("invalid original callback row")
		}
		values := make([]evidence.Value, 5)
		for i, raw := range row {
			if i == 1 {
				var at uint64
				if err := json.Unmarshal(raw, &at); err != nil {
					t.Fatal(err)
				}
				values[i] = evidence.Address(at)
				continue
			}
			var text string
			if json.Unmarshal(raw, &text) == nil {
				values[i] = evidence.Text(text)
				continue
			}
			var missing struct{ Missing string }
			if err := json.Unmarshal(raw, &missing); err != nil {
				t.Fatal(err)
			}
			reason, ok := map[string]string{"NotApplicableValue": "not_applicable", "NotAvailableValue": "not_available", "UnreadableValue": "unreadable", "UnparsableValue": "unparsable"}[missing.Missing]
			if !ok {
				t.Fatal("unknown absent class")
			}
			values[i] = evidence.Missing(reason, nil)
		}
		raw, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		result[string(raw)]++
	}
	return result
}
func TestWindowsCallbacksCompleteGeneratorStorageCacheAndRetry(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for complete callback generator case storage")
	}
	raw, err := os.ReadFile("../plugins/testdata/windows-callbacks-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []callbackGeneratorCase
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 144 {
		t.Fatal("callback generator fixture drift")
	}
	identities := map[string]windowsRegexCase{}
	for _, c := range windowsRegexCases(t) {
		if c.Name == "literal" {
			identities[c.Arch] = c
		}
	}
	for index, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%d/%s/vista%t/legacy%t/%s", index, c.Arch, c.Vista, c.Legacy, c.Scenario), func(t *testing.T) {
			data := make([]byte, c.Size)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset+len(b) > len(data) {
					t.Fatal("invalid original bytes")
				}
				copy(data[w.Offset:], b)
			}
			identity, ok := identities[c.Arch]
			if !ok {
				t.Fatal("missing separate PE identity")
			}
			// These PE bytes occupy neither callback indexes nor pool allocations.
			// Keep notification arrays through 0x115ff intact on x64 Vista controls.
			for _, w := range identity.Writes {
				if w.Offset >= 0x10000 && w.Offset < 0x12000 && (w.Offset < 0x11000 || w.Offset >= 0x11600) {
					b, err := hex.DecodeString(w.Data)
					if err != nil || w.Offset+len(b) > 0x12000 {
						t.Fatal("invalid PE bytes")
					}
					copy(data[w.Offset:], b)
				}
			}
			var table, source, meta, other, windows, pdb map[string]json.RawMessage
			for _, item := range []struct {
				raw []byte
				dst any
			}{{c.ISF, &table}, {identity.ISF, &source}} {
				if err := json.Unmarshal(item.raw, item.dst); err != nil {
					t.Fatal(err)
				}
			}
			json.Unmarshal(table["metadata"], &meta)
			json.Unmarshal(source["metadata"], &other)
			json.Unmarshal(meta["windows"], &windows)
			json.Unmarshal(other["windows"], &pdb)
			windows["pdb"] = pdb["pdb"]
			meta["windows"], _ = json.Marshal(windows)
			table["metadata"], _ = json.Marshal(meta)
			isf, err := json.Marshal(table)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
			cache := filepath.Join(dir, "symbols")
			if err := os.MkdirAll(filepath.Join(cache, "callback-symbols"), 0700); err != nil {
				t.Fatal(err)
			}
			name := "callbacks-x86"
			if c.Width == 8 {
				name = "callbacks-x64"
			}
			schema, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(schema)
			for path, b := range map[string][]byte{image: data, symbol: isf, filepath.Join(cache, "callback-symbols", fmt.Sprintf("%s-%x.json", name, sum)): schema} {
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, SymbolCache: cache, OS: "windows", Arch: c.Arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var wire bytes.Buffer
			actual := map[string]int{}
			detailErrors := 0
			result, runErr := e.Run(context.Background(), "windows.callbacks", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "callback" {
					selected := make([]evidence.Value, 0, 5)
					for _, key := range []string{"Type", "Callback", "Module", "Symbol", "Detail"} {
						v := row.Cells[key]
						if key == "Detail" && v.Error != "" {
							detailErrors++
						}
						v.Error = ""
						selected = append(selected, v)
					}
					raw, err := json.Marshal(selected)
					if err != nil {
						return err
					}
					actual[string(raw)]++
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			failed := c.Scenario == "bad-driver" || c.Scenario == "no-name-info" && c.Vista
			if (runErr != nil) != failed || result.Reused {
				t.Fatal("callback task completeness", runErr, result.Reused)
			}
			expected := callbackGeneratorExpected(t, c.Rows)
			if c.Error != nil {
				if c.Error.Type != "ValueError" || c.Scenario != "no-name-info" || !c.Vista {
					t.Fatal("unreviewed original exception", c.Error)
				}
				// Explicit deviation: the original aborts before its first PnP row;
				// native retains three readable callbacks with unavailable name details.
				values := []evidence.Value{evidence.Text("EventCategoryDeviceInterfaceChange"), evidence.Address(0x8800), evidence.Missing("not_available", nil), evidence.Missing("not_available", nil), evidence.Missing("unreadable", nil)}
				raw, _ := json.Marshal(values)
				expected[string(raw)] += 3
				if detailErrors != 3 {
					t.Fatal("lost PnP errors")
				}
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("engine callback projection differs", actual, expected)
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
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("sealed callback storage differs")
			}
			var replay bytes.Buffer
			again, replayErr := e.Run(context.Background(), "windows.callbacks", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
			if failed {
				if replayErr == nil || again.Reused || again.Task.ID == result.Task.ID {
					t.Fatal("failed callback task reused", replayErr)
				}
			} else if replayErr != nil || !again.Reused || again.Task.ID != result.Task.ID || !bytes.Equal(wire.Bytes(), replay.Bytes()) {
				t.Fatal("callback cache replay differs", replayErr, again.Reused)
			}
		})
	}
}
