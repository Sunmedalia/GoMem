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
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func etwOracleCases(t *testing.T) []suspendedOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-etwpatch-oracle.json")
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
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 56 {
		t.Fatal("fixture drift")
	}
	return fixture.Cases
}
func TestETWPatchActualPinnedGenerator(t *testing.T) {
	columns := []string{"PID", "Process", "DLL", "Function", "Offset", "Opcode"}
	cases := etwOracleCases(t)
	for _, c := range append([]suspendedOracleCase(nil), cases...) {
		if c.Width == 4 {
			c.NativeArch = "pae"
			c.Name += "-pae"
			cases = append(cases, c)
		}
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d/%s", c.Width*8, c.Name), func(t *testing.T) {
			e, data := etwOracleEngine(t, c)
			layers, roots := etwOracleLayers(t, e)
			parameters := map[string]string{}
			if strings.HasPrefix(c.Name, "pid-match") {
				parameters["pid"] = "104"
			}
			if strings.HasPrefix(c.Name, "pid-mismatch") || strings.HasPrefix(c.Name, "second-filtered") {
				parameters["pid"] = "108"
			}
			ctx := context.Background()
			var found []evidence.Row
			captures := 0
			var encoded bytes.Buffer
			result, err := e.Run(ctx, "windows.etwpatch", parameters, engine.RunOptions{Emit: func(row evidence.Row) error {
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
					if !ok || at+requested > uint64(len(data)) {
						t.Fatal("fixture raw capture", at, requested)
					}
					layer := layers[row.Provenance.Layer]
					if layer == nil {
						t.Fatal("unknown captured layer", row.Provenance.Layer)
					}
					physical := at
					if roots[row.Provenance.Layer] == 0xb000 && at >= 0x101000 && at+requested <= 0x102000 {
						physical = at - 0x101000 + 0x1e0000
					}
					if !bytes.Equal(raw, data[physical:physical+requested]) {
						t.Fatal("original physical bytes differ", row.Provenance.Layer, at, physical)
					}
					actual, err := memory.Read(ctx, layer, at, int(requested))
					if err != nil || !bytes.Equal(actual, raw) {
						t.Fatal("independent paged reread", err)
					}
				}
				if row.Cells["RecordType"].String() == "finding" {
					found = append(found, row)
				}
				return json.NewEncoder(&encoded).Encode(row)
			}})
			if err != nil {
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
			again, err := e.Run(ctx, "windows.etwpatch", parameters, engine.RunOptions{})
			if err != nil || again.Reused || again.Task.ID == result.Task.ID {
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

func etwOracleEngine(t *testing.T, c suspendedOracleCase) (*engine.Engine, []byte) {
	t.Helper()
	if c.NativeArch == "pae" && strings.HasPrefix(c.Name, "second-") {
		put := func(at int, n uint64) {
			raw := binary.LittleEndian.AppendUint64(nil, n)
			c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], struct {
				Offset int
				Data   string
			}{at, hex.EncodeToString(raw)})
		}
		put(0xb000, 0xc003)
		put(0xc000, 0xe003)
		for i := range 512 {
			put(0xe000+i*8, uint64(i<<12)|3)
		}
		put(0xe000+0x101*8, 0x1e0003)
	}
	return suspendedOracleEngine(t, c)
}
func etwOracleLayers(t *testing.T, e *engine.Engine) (map[string]memory.MemoryLayer, map[string]uint64) {
	t.Helper()
	layers := map[string]memory.MemoryLayer{e.Env.Kernel.Name(): e.Env.Kernel}
	roots := map[string]uint64{}
	ps, err := e.Registry.Get("windows.pslist")
	if err != nil {
		t.Fatal(err)
	}
	params, err := plugin.Parameters(ps.Spec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = ps.Run(context.Background(), e.Env, params, func(row evidence.Row) error {
		root, err := row.Cells["DTB"].Uint()
		if err != nil {
			return err
		}
		translator, err := memory.NewTranslatorForOS(e.Env.Physical, root, e.Env.Architecture, e.Env.OS, 128)
		if err != nil {
			return err
		}
		id := "process:" + row.Cells["Identity"].String()
		layers[id] = &memory.Virtual{Physical: e.Env.Physical, Translator: translator, ID: id}
		roots[id] = root
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return layers, roots
}

type etwOpcodeFault struct {
	memory.MemoryLayer
	mode  string
	calls *int
}

func (l etwOpcodeFault) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	*l.calls++
	if len(p) == 1 && at == 0x101200 {
		switch l.mode {
		case "opcode-hole":
			return 0, memory.ErrUnmapped
		case "opcode-short":
			return 0, nil
		case "opcode-invalid-count":
			return 2, nil
		}
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func TestETWPatchBoundsFaultsAndCancellation(t *testing.T) {
	all := etwOracleCases(t)
	find := func(name string) suspendedOracleCase {
		for _, c := range all {
			if c.Width == 8 && c.Name == name {
				return c
			}
		}
		t.Fatal(name)
		return suspendedOracleCase{}
	}
	for _, mode := range []string{"process-cycle", "node-limit", "vad-cycle", "region-limit", "module-limit", "byte-limit", "symbol-limit", "probe-limit", "name-hole", "root-hole", "opcode-hole", "opcode-short", "opcode-invalid-count", "provider-error", "offline-fallback", "emit-error", "emit-opcode-error", "emit-finding-error", "cancel", "cancel-opcode"} {
		t.Run(mode, func(t *testing.T) {
			c := find("normal")
			switch mode {
			case "node-limit":
				c = find("second-clean")
			case "region-limit", "module-limit":
				c = find("both-modules")
			case "provider-error", "offline-fallback":
				c = find("export-only")
			}
			put := func(at int, n uint64) {
				raw := binary.LittleEndian.AppendUint64(nil, n)
				c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], struct {
					Offset int
					Data   string
				}{at, hex.EncodeToString(raw)})
			}
			p := map[string]string{}
			switch mode {
			case "process-cycle":
				put(0x400, 0x400)
			case "node-limit":
				p["max-nodes"] = "1"
			case "vad-cycle":
				put(0x1008, 0x1000)
			case "region-limit":
				p["max-regions"] = "1"
			case "module-limit":
				p["max-modules"] = "1"
			case "byte-limit":
				p["max-read-bytes"] = "1"
			case "symbol-limit":
				p["max-symbols"] = "1"
			case "probe-limit":
				p["max-probes"] = "1"
			}
			e, _ := etwOracleEngine(t, c)
			calls, callsAtStop := 0, -1
			e.Env.Physical = etwOpcodeFault{e.Env.Physical, mode, &calls}
			if mode == "name-hole" {
				e.Env.Kernel = suspendedHoleLayer{MemoryLayer: e.Env.Kernel, at: 0x5000}
			}
			if mode == "root-hole" {
				e.Env.Kernel = suspendedHoleLayer{MemoryLayer: e.Env.Kernel, at: 0x450}
			}
			sentinel := errors.New("ETW injected acquisition/output failure")
			if mode == "provider-error" {
				e.Env.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) { return pesymbols.PDB{}, sentinel }
			}
			if mode == "offline-fallback" {
				e.Env.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) {
					return pesymbols.PDB{}, pesymbols.ErrUnavailable
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			findings, rows := 0, 0
			result, err := e.Run(ctx, "windows.etwpatch", p, engine.RunOptions{Emit: func(row evidence.Row) error {
				rows++
				kind := row.Cells["RecordType"].String()
				if kind == "finding" {
					findings++
				}
				scope := ""
				if d, ok := row.Cells["Resolution"].Data.(map[string]any); ok {
					scope, _ = d["method"].(string)
				}
				stop := mode == "emit-error" || mode == "emit-opcode-error" && scope == "opcode" || mode == "emit-finding-error" && kind == "finding"
				canceled := mode == "cancel" || mode == "cancel-opcode" && scope == "opcode"
				if stop || canceled {
					callsAtStop = calls
					if canceled {
						cancel()
						return nil
					}
					return sentinel
				}
				return nil
			}})
			if mode == "offline-fallback" {
				if err != nil || findings != 1 {
					t.Fatal("exact export fallback", result, err, findings)
				}
				return
			}
			if err == nil || result.Task.State != "failed" && result.Task.State != "canceled" {
				t.Fatal(mode, result, err)
			}
			if mode == "provider-error" && (!errors.Is(err, sentinel) || findings != 1) {
				t.Fatal("provider cause/useful match lost", err, findings)
			}
			if strings.HasPrefix(mode, "opcode-") && findings != 6 {
				t.Fatal("unreadable opcode hid other functions", findings, err)
			}
			if strings.HasPrefix(mode, "emit-") && !errors.Is(err, sentinel) {
				t.Fatal("lost output failure", err)
			}
			if strings.HasPrefix(mode, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation", err)
			}
			if callsAtStop >= 0 && callsAtStop != calls {
				t.Fatal("acquisition continued after output/cancel", callsAtStop, calls)
			}
			if mode == "emit-error" && rows != 1 {
				t.Fatal("extra output", rows)
			}
			again, err := e.Run(context.Background(), "windows.etwpatch", p, engine.RunOptions{})
			if again.Reused || again.Task.ID == result.Task.ID {
				t.Fatal("failed result replayed", again, err)
			}
		})
	}
}
