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
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
)

func debugRegisterOracleCases(t *testing.T) []suspendedOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-debugregisters-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []suspendedOracleCase
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 66 {
		t.Fatal("fixture drift")
	}
	return fixture.Cases
}
func TestDebugRegistersActualPinnedGenerator(t *testing.T) {
	columns := []string{"Process", "PID", "TID", "State", "Dr7", "Dr0", "Range0", "Symbol0", "Dr1", "Range1", "Symbol1", "Dr2", "Range2", "Symbol2", "Dr3", "Range3", "Symbol3"}
	cases := debugRegisterOracleCases(t)
	for _, c := range append([]suspendedOracleCase(nil), cases...) {
		if c.Width == 4 {
			c.NativeArch = "pae"
			c.Name += "-pae"
			cases = append(cases, c)
		}
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d/%s", c.Width*8, c.Name), func(t *testing.T) {
			e, data := suspendedOracleEngine(t, c)
			ctx := context.Background()
			var found []evidence.Row
			captures := 0
			var encoded bytes.Buffer
			result, err := e.Run(ctx, "windows.debugregisters", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "memory_read" {
					captures++
					at, err := row.Cells["Offset"].Uint()
					if err != nil {
						t.Fatal(err)
					}
					requested, err := row.Cells["Requested"].Uint()
					if err != nil {
						t.Fatal(err)
					}
					raw, ok := row.Cells["Raw"].Data.([]byte)
					if !ok || at+requested > uint64(len(data)) || !bytes.Equal(raw, data[at:at+requested]) {
						t.Fatal("fixture raw capture", at, requested)
					}
					actual, err := memory.Read(ctx, e.Env.Kernel, at, int(requested))
					if err != nil || !bytes.Equal(actual, raw) {
						t.Fatal("independent paged reread", err)
					}
				}
				if row.Cells["RecordType"].String() == "thread" {
					found = append(found, row)
				}
				return json.NewEncoder(&encoded).Encode(row)
			}})
			if strings.HasPrefix(c.Name, "rsds-no-mz") {
				if err == nil || !strings.Contains(err.Error(), "invalid DOS signature") || result.Task.State != "failed" {
					t.Fatal(result, err)
				}
			} else if err != nil {
				t.Fatal(result, err)
			}
			if len(found) != len(c.Expected) || captures == 0 {
				t.Fatal(len(found), len(c.Expected), captures)
			}
			for i, want := range c.Expected {
				for j, col := range columns {
					got := found[i].Cells[col]
					if string(want[j]) == "null" {
						if got.Kind != "missing" {
							t.Fatal(col, got)
						}
						continue
					}
					if got.Kind == "address" || got.Kind == "uint64" {
						var n uint64
						if err = json.Unmarshal(want[j], &n); err != nil {
							t.Fatal(err)
						}
						v, err := got.Uint()
						if err != nil || v != n {
							t.Fatal(col, got, n, err)
						}
					} else {
						var s string
						if err = json.Unmarshal(want[j], &s); err != nil || got.String() != s {
							t.Fatal(col, got, s, err)
						}
					}
				}
			}
			// Runtime PDB dependencies are not yet revalidated for cache replay.
			again, err := e.Run(ctx, "windows.debugregisters", nil, engine.RunOptions{})
			if (err != nil && !strings.HasPrefix(c.Name, "rsds-no-mz")) || again.Reused || again.Task.ID == result.Task.ID {
				t.Fatal("dynamic symbols incorrectly reused", again, err)
			}
			var sealed bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					old := row.ID
					row.Seal()
					if row.ID != old {
						t.Fatal("seal drift")
					}
					if err = json.NewEncoder(&sealed).Encode(row); err != nil {
						t.Fatal(err)
					}
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(encoded.Bytes(), sealed.Bytes()) {
				t.Fatal("persisted evidence changed")
			}
		})
	}
}

func TestDebugRegistersFaultsBoundsAndCancellation(t *testing.T) {
	all := debugRegisterOracleCases(t)
	base := all[len(all)/2]
	for _, mode := range []string{"thread-cycle", "thread-limit", "vad-cycle", "region-limit", "owner-hole", "register-hole", "budget", "symbol-limit", "provider-error", "offline-fallback", "emit-error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c := base
			c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], c.Writes[:0]...)
			put := func(at int, n uint64) {
				raw := make([]byte, 8)
				binary.LittleEndian.PutUint64(raw, n)
				c.Writes = append(c.Writes, struct {
					Offset int
					Data   string
				}{at, hex.EncodeToString(raw)})
			}
			parameters := map[string]string{}
			switch mode {
			case "thread-cycle":
				put(0x600, 0x600)
			case "thread-limit":
				put(0x600, 0x700)
				put(0x448, 0x700)
				put(0x700, 0x440)
				put(0x708, 0x600)
				parameters["max-threads"] = "1"
			case "vad-cycle":
				put(0x1008, 0x1000)
			case "region-limit":
				put(0x1008, 0x1200)
				put(0x1210, 0x1000)
				c.Writes = append(c.Writes, struct {
					Offset int
					Data   string
				}{0x1200 - 12, hex.EncodeToString([]byte("Vadl"))})
				put(0x1218, 0x11000000110)
				put(0x1228, 0x2000)
				parameters["max-regions"] = "1"
			case "budget":
				parameters["max-read-bytes"] = "1"
			case "symbol-limit":
				var table map[string]any
				if err := json.Unmarshal(c.PDB, &table); err != nil {
					t.Fatal(err)
				}
				table["symbols"].(map[string]any)["second"] = map[string]any{"address": 0x1300}
				c.PDB, _ = json.Marshal(table)
				parameters["max-symbols"] = "1"
			}
			e, _ := suspendedOracleEngine(t, c)
			sentinel := errors.New("injected acquisition/output failure")
			calls := 0
			switch mode {
			case "owner-hole":
				e.Env.Kernel = suspendedHoleLayer{e.Env.Kernel, 0x648, &calls}
			case "register-hole":
				e.Env.Kernel = suspendedHoleLayer{e.Env.Kernel, 0x7020, &calls}
			case "provider-error":
				e.Env.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) { return pesymbols.PDB{}, sentinel }
			case "offline-fallback":
				e.Env.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) {
					return pesymbols.PDB{}, pesymbols.ErrUnavailable
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var rows []evidence.Row
			result, err := e.Run(ctx, "windows.debugregisters", parameters, engine.RunOptions{Emit: func(row evidence.Row) error {
				rows = append(rows, row)
				if mode == "emit-error" {
					return sentinel
				}
				if mode == "cancel" {
					cancel()
				}
				return nil
			}})
			if mode == "offline-fallback" {
				if err != nil {
					t.Fatal(result, err)
				}
				matched := false
				for _, r := range rows {
					if r.Cells["RecordType"].String() == "thread" {
						matched = r.Cells["Symbol0"].String() == "Alpha"
					}
				}
				if !matched {
					t.Fatal("expected exact export fallback")
				}
				return
			}
			if err == nil || result.Task.State != "failed" && result.Task.State != "canceled" {
				t.Fatal(mode, result, err)
			}
			if mode == "provider-error" && !errors.Is(err, sentinel) {
				t.Fatal("lost acquisition error", err)
			}
			if mode == "emit-error" && (!errors.Is(err, sentinel) || len(rows) != 1) {
				t.Fatal("output failure did not stop", err, len(rows))
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			again, err := e.Run(context.Background(), "windows.debugregisters", parameters, engine.RunOptions{})
			if again.Reused || again.Task.ID == result.Task.ID {
				t.Fatal("failed analysis replayed", again, err)
			}
		})
	}
}

func TestDebugRegistersContinuesAfterUnreadableThread(t *testing.T) {
	c := debugRegisterOracleCases(t)[33]
	put := func(at int, n uint64) {
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, n)
		c.Writes = append(c.Writes, struct {
			Offset int
			Data   string
		}{at, hex.EncodeToString(raw)})
	}
	// A second independent thread survives the first saved-register read failure.
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		raw, _ := hex.DecodeString(w.Data)
		copy(data[w.Offset:], raw)
	}
	c.Writes = append(c.Writes, struct {
		Offset int
		Data   string
	}{0x700, hex.EncodeToString(data[0x600:0x660])})
	put(0x600, 0x700)
	put(0x448, 0x700)
	put(0x700, 0x440)
	put(0x708, 0x600)
	put(0x718, 12)
	put(0x750, 0x7100)
	put(0x7100, 0x101200)
	put(0x7120, 1)
	e, _ := suspendedOracleEngine(t, c)
	e.Env.Kernel = suspendedHoleLayer{MemoryLayer: e.Env.Kernel, at: 0x7020}
	reported := 0
	result, err := e.Run(context.Background(), "windows.debugregisters", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "thread" {
			reported++
			tid, _ := row.Cells["TID"].Uint()
			if tid != 12 {
				t.Fatal("unreadable thread reported", tid)
			}
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || reported != 1 {
		t.Fatal(result, err, reported)
	}
}
