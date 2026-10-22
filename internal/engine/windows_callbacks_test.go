package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
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

// These are composed native pipeline controls, not complete original-generator
// differentials. Index bytes are from the actual original method controls.
func TestWindowsCallbacksPagedStorageCacheAndFailedRetry(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for pinned callback layouts")
	}
	var indexes struct {
		Cases []struct {
			Width         int
			Vista, Legacy bool
			Scenario      string
			Kernel        json.RawMessage `json:"kernel_isf"`
			Results       []struct{ Rows [][]json.RawMessage }
			Writes        []struct {
				Offset int
				Data   string
			}
		}
	}
	var pools struct {
		Cases []struct {
			Width int
			Vista bool
			ISF   json.RawMessage
		}
	}
	for path, dst := range map[string]any{"../../pkg/wincallbacks/testdata/index-oracle.json": &indexes, "../plugins/testdata/windows-poolscanner-oracle.json": &pools} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"x86", "pae", "x64"} {
		t.Run(arch, func(t *testing.T) {
			width := 4
			if arch == "x64" {
				width = 8
			}
			data := make([]byte, 0x40000)
			var table map[string]json.RawMessage
			var expected [][]json.RawMessage
			for _, c := range indexes.Cases {
				if c.Width == width && !c.Vista && !c.Legacy && c.Scenario == "normal" {
					if err := json.Unmarshal(c.Kernel, &table); err != nil {
						t.Fatal(err)
					}
					for _, r := range c.Results {
						expected = append(expected, r.Rows...)
					}
					for _, w := range c.Writes {
						b, err := hex.DecodeString(w.Data)
						if err != nil || w.Offset < 0 || w.Offset+len(b) > len(data) {
							t.Fatal("invalid index bytes")
						}
						copy(data[w.Offset:], b)
					}
					break
				}
			}
			if table == nil {
				t.Fatal("missing index fixture")
			}
			var types map[string]json.RawMessage
			json.Unmarshal(table["user_types"], &types)
			for _, c := range pools.Cases {
				if c.Width == width && !c.Vista {
					var p map[string]json.RawMessage
					json.Unmarshal(c.ISF, &p)
					var other map[string]json.RawMessage
					json.Unmarshal(p["user_types"], &other)
					for k, v := range other {
						if _, ok := types[k]; !ok {
							types[k] = v
						}
					}
					var bases, otherBases map[string]json.RawMessage
					json.Unmarshal(table["base_types"], &bases)
					json.Unmarshal(p["base_types"], &otherBases)
					for k, v := range otherBases {
						if _, ok := bases[k]; !ok {
							bases[k] = v
						}
					}
					table["base_types"], _ = json.Marshal(bases)
					break
				}
			}
			types["_KLDR_DATA_TABLE_ENTRY"] = json.RawMessage(fmt.Sprintf(`{"kind":"struct","size":%d,"fields":{"InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}}`, 2*width))
			table["user_types"], _ = json.Marshal(types)
			var syms map[string]any
			json.Unmarshal(table["symbols"], &syms)
			syms["PsLoadedModuleList"] = map[string]any{"address": 0x1d000}
			syms["ObTypeIndexTable"] = map[string]any{"address": 0x1e000}
			table["symbols"], _ = json.Marshal(syms)
			put := func(at int, v uint64) {
				if width == 4 {
					binary.LittleEndian.PutUint32(data[at:], uint32(v))
				} else {
					binary.LittleEndian.PutUint64(data[at:], v)
				}
			}
			put(0x2d000, 0x2d000)
			put(0x2d000+width, 0x2d000)
			// Genuine hardware page tables; large pages avoid any dependency on an
			// injected translator or a copied fixture's process/VAD structures.
			switch arch {
			case "x86":
				binary.LittleEndian.PutUint32(data[0x8000:], 0x83)
			case "pae":
				binary.LittleEndian.PutUint64(data[0x8000:], 0x9003)
				binary.LittleEndian.PutUint64(data[0x9000:], 0x83)
			case "x64":
				binary.LittleEndian.PutUint64(data[0x8000:], 0x9003)
				binary.LittleEndian.PutUint64(data[0x9000:], 0xa003)
				binary.LittleEndian.PutUint64(data[0xa000:], 0x83)
			}
			identityFound := false
			for _, c := range windowsRegexCases(t) {
				if c.Arch == arch && c.Name == "literal" {
					for _, w := range c.Writes {
						if w.Offset >= 0x10000 && w.Offset < 0x12000 && (w.Offset < 0x11000 || w.Offset >= 0x11600) {
							b, err := hex.DecodeString(w.Data)
							if err != nil || w.Offset+len(b) > 0x12000 {
								t.Fatal("invalid identity bytes")
							}
							copy(data[w.Offset:], b)
						}
					}
					var source, meta, other, windows, pdb map[string]json.RawMessage
					json.Unmarshal(c.ISF, &source)
					json.Unmarshal(table["metadata"], &meta)
					json.Unmarshal(source["metadata"], &other)
					json.Unmarshal(meta["windows"], &windows)
					json.Unmarshal(other["windows"], &pdb)
					windows["pdb"] = pdb["pdb"]
					meta["windows"], _ = json.Marshal(windows)
					table["metadata"], _ = json.Marshal(meta)
					identityFound = true
					break
				}
			}
			if !identityFound {
				t.Fatal("missing PE identity")
			}
			// One real nonexecutive allocation, source header followed by original
			// callback structure. Empty module list intentionally yields no attribution.
			allocation := 0x30000
			header := 2 * width
			data[allocation+2], data[allocation+3] = 4, 2
			copy(data[allocation+4:], "IoFs")
			name := "callbacks-x86"
			if width == 8 {
				name = "callbacks-x64"
			}
			schema, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var cb struct {
				Types map[string]struct {
					Fields map[string]struct{ Offset int }
				} `json:"user_types"`
			}
			if err := json.Unmarshal(schema, &cb); err != nil {
				t.Fatal(err)
			}
			put(allocation+header+cb.Types["_NOTIFICATION_PACKET"].Fields["NotificationRoutine"].Offset, 0x28800)
			isf, err := json.Marshal(table)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			image, symbol := filepath.Join(dir, "memory.raw"), filepath.Join(dir, "kernel.json")
			cache := filepath.Join(dir, "symbols")
			os.MkdirAll(filepath.Join(cache, "callback-symbols"), 0700)
			sum := sha256.Sum256(schema)
			for path, raw := range map[string][]byte{image: data, symbol: isf, filepath.Join(cache, "callback-symbols", fmt.Sprintf("%s-%x.json", name, sum)): schema} {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: symbol, SymbolCache: cache, OS: "windows", Arch: arch, DTB: "0x8000", KernelBase: 0x10000, CaseDir: filepath.Join(dir, "case"), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var wire bytes.Buffer
			callbacks := 0
			result, err := e.Run(context.Background(), "windows.callbacks", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "callback" {
					if callbacks < len(expected) {
						want := expected[callbacks]
						var typ string
						var address uint64
						json.Unmarshal(want[0], &typ)
						json.Unmarshal(want[1], &address)
						got, decodeErr := row.Cells["Callback"].Uint()
						if decodeErr != nil || row.Cells["Type"].String() != typ || got != address {
							t.Fatal("original index projection differs", row.Cells, want)
						}
						if string(want[2]) == "null" {
							if row.Cells["Detail"].Reason != "not_applicable" {
								t.Fatal("lost absent detail")
							}
						} else {
							var detail string
							json.Unmarshal(want[2], &detail)
							if row.Cells["Detail"].String() != detail {
								t.Fatal("original index detail differs")
							}
						}
					} else if row.Cells["Route"].String() != "pool" || row.Cells["Type"].String() != "IoRegisterFsRegistrationChange" || row.Cells["Callback"].String() != evidence.Address(0x28800).String() {
						t.Fatal("callback pool projection differs", row.Cells)
					}
					if row.Cells["Module"].Reason != "not_available" || row.Cells["Symbol"].Reason != "not_available" {
						t.Fatal("invented module attribution")
					}
					callbacks++
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			if err != nil || result.Reused || callbacks != len(expected)+1 {
				t.Fatal("native callback pipeline", callbacks, result.Reused, err)
			}
			var stored bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rows {
					if err := r.Verify(); err != nil {
						t.Fatal(err)
					}
					json.NewEncoder(&stored).Encode(r)
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("sealed callback storage differs")
			}
			var replay bytes.Buffer
			cached, err := e.Run(context.Background(), "windows.callbacks", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
			if err != nil || !cached.Reused || !bytes.Equal(wire.Bytes(), replay.Bytes()) {
				t.Fatal("callback replay differs", err, cached.Reused)
			}
			last := ""
			for i := 0; i < 2; i++ {
				failed, err := e.Run(context.Background(), "windows.callbacks", map[string]string{"max-reads": "1"}, engine.RunOptions{})
				if err == nil || failed.Reused || failed.Task.ID == last {
					t.Fatal("failed callback task reused", err)
				}
				last = failed.Task.ID
			}
			for _, name := range []string{"max-read-bytes", "max-rows", "max-nodes"} {
				failed, err := e.Run(context.Background(), "windows.callbacks", map[string]string{name: "1"}, engine.RunOptions{})
				if err == nil || failed.Reused {
					t.Fatal("callback budget not enforced", name, err)
				}
			}
			stop := errors.New("callback output stopped")
			emitted := 0
			_, err = e.Run(context.Background(), "windows.callbacks", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { emitted++; return stop }})
			if !errors.Is(err, stop) || emitted != 1 {
				t.Fatal("output error not terminal", emitted, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			_, err = e.Run(ctx, "windows.callbacks", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { cancel(); return nil }})
			cancel()
			if !errors.Is(err, context.Canceled) {
				t.Fatal("lost callback cancellation", err)
			}
		})
	}
}
