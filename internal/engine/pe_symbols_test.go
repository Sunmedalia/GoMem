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

type peSymbolOracleQuery struct {
	Fixture     int
	Source      string
	NativeError string `json:"native_error"`
	Query       struct {
		Module    string
		Symbols   []string
		Addresses []string
	}
	Expected [][]json.RawMessage
}

func TestPESymbolsFailuresCancellationAndFreshTasks(t *testing.T) {
	fixtures, _ := peSymbolOracle(t)
	var base suspendedOracleCase
	for _, c := range fixtures {
		if c.Width == 8 && c.Name == "normal" {
			base = c
		}
	}
	for _, mode := range []string{"node-limit", "region-limit", "module-limit", "byte-limit", "symbol-limit", "session-hole", "name-hole", "scan-hole", "module-cycle", "provider-error", "offline-fallback", "cancel", "emit-error", "no-query", "fresh", "file-hole"} {
		t.Run(mode, func(t *testing.T) {
			c := base
			if mode == "node-limit" || mode == "region-limit" || mode == "module-limit" || mode == "file-hole" {
				// Link the existing second process into the active list; both
				// processes own one VAD, so a bound of one must be exceeded.
				for at, value := range map[int]uint64{0x18088: 0x500, 0x400: 0x500, 0x500: 0x18080, 0x508: 0x400} {
					raw := binary.LittleEndian.AppendUint64(nil, value)
					c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], struct {
						Offset int
						Data   string
					}{at, hex.EncodeToString(raw)})
				}
			}
			p := map[string]string{"source": "processes", "module": "fixture.dll", "symbols": `["Alpha"]`}
			switch mode {
			case "node-limit":
				p["max-nodes"] = "1"
			case "region-limit":
				p["max-regions"] = "1"
			case "module-limit":
				p["max-modules"] = "1"
			case "byte-limit":
				p["max-read-bytes"] = "1"
			case "symbol-limit":
				p["max-symbols"] = "1"
				var table map[string]any
				if err := json.Unmarshal(c.PDB, &table); err != nil {
					t.Fatal(err)
				}
				table["symbols"].(map[string]any)["Second"] = map[string]any{"address": 0x1300}
				c.PDB, _ = json.Marshal(table)
			case "module-cycle":
				p["source"] = "kernel"
				raw := binary.LittleEndian.AppendUint64(nil, 0x1a000)
				c.Writes = append(c.Writes[:len(c.Writes):len(c.Writes)], struct {
					Offset int
					Data   string
				}{0x1a000, hex.EncodeToString(raw)})
			case "session-hole", "name-hole":
				p["source"] = "kernel"
			case "no-query":
				p["symbols"] = "[]"
			}
			if mode == "file-hole" {
				// First process has a bad filename; second keeps the original
				// readable mapping and must still provide the export symbol.
				data := make([]byte, c.Size)
				for _, w := range c.Writes {
					raw, _ := hex.DecodeString(w.Data)
					copy(data[w.Offset:], raw)
				}
				copy(data[0x10f4:0x1130], data[0xff4:0x1030])
				binary.LittleEndian.PutUint64(data[0x430:], 0x1100)
				binary.LittleEndian.PutUint64(data[0x1128:], 0x2100)
				binary.LittleEndian.PutUint64(data[0x2100:], 0x3100)
				binary.LittleEndian.PutUint64(data[0x3100:], 0x4103)
				copy(data[0x4100:0x4110], data[0x4000:0x4010])
				binary.LittleEndian.PutUint64(data[0x4108:], 0x5100)
				copy(data[0x5100:0x5180], data[0x5000:0x5080])
				for _, at := range []int{0x430, 0x10f4, 0x2100, 0x3100, 0x4100, 0x5100} {
					c.Writes = append(c.Writes, struct {
						Offset int
						Data   string
					}{at, hex.EncodeToString(data[at : at+128])})
				}
			}
			e, _ := suspendedOracleEngine(t, c)
			calls := 0
			sentinel := errors.New("PE-symbol output or provider stopped")
			switch mode {
			case "session-hole":
				e.Env.Kernel = suspendedHoleLayer{e.Env.Kernel, 0x458, &calls}
			case "name-hole":
				e.Env.Kernel = suspendedHoleLayer{e.Env.Kernel, 0x1a020, &calls}
			case "file-hole":
				e.Env.Kernel = suspendedHoleLayer{e.Env.Kernel, 0x5100, &calls}
			case "scan-hole":
				e.Env.Physical = suspendedHoleLayer{e.Env.Physical, 0x101000, &calls}
			case "provider-error":
				e.Env.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) { return pesymbols.PDB{}, sentinel }
			case "offline-fallback":
				e.Env.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) {
					return pesymbols.PDB{}, pesymbols.ErrUnavailable
				}
			case "cancel", "emit-error", "no-query":
				e.Env.Kernel = suspendedHoleLayer{e.Env.Kernel, ^uint64(0), &calls}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var rows []evidence.Row
			callsAtEmit := -1
			result, err := e.Run(ctx, "windows.pe_symbols", p, engine.RunOptions{Emit: func(row evidence.Row) error {
				rows = append(rows, row)
				if callsAtEmit < 0 {
					callsAtEmit = calls
				}
				if mode == "emit-error" {
					return sentinel
				}
				if mode == "cancel" {
					cancel()
				}
				return nil
			}})
			if mode == "offline-fallback" || mode == "fresh" || mode == "no-query" {
				if err != nil {
					t.Fatal(result, err)
				}
				if mode == "no-query" && (calls != callsAtEmit || len(rows) != 1) {
					t.Fatal("no-query performed reads", calls, len(rows))
				}
				if mode == "fresh" {
					again, err := e.Run(ctx, "windows.pe_symbols", p, engine.RunOptions{})
					if err != nil || again.Reused || again.Task.ID == result.Task.ID {
						t.Fatal("stale dynamic-symbol task replayed", again, err)
					}
				}
				return
			}
			if err == nil {
				t.Fatal("failure reported success", mode, result)
			}
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) || calls != callsAtEmit {
					t.Fatal(err, calls)
				}
				return
			}
			if mode == "emit-error" {
				if !errors.Is(err, sentinel) || calls != callsAtEmit {
					t.Fatal(err, calls)
				}
				return
			}
			if len(rows) == 0 || rows[len(rows)-1].Cells["RecordType"].String() != "summary" {
				t.Fatal("failed acquisition lost summary")
			}
			if mode == "provider-error" || mode == "file-hole" {
				found := false
				for _, row := range rows {
					if row.Cells["RecordType"].String() == "symbol" && row.Cells["Symbol"].String() == "Alpha" {
						found = true
					}
				}
				if !found || (mode == "provider-error" && !errors.Is(err, sentinel)) {
					t.Fatal("genuine provider error or fallback result lost", err, found)
				}
			}
		})
	}
}

func peSymbolOracle(t *testing.T) ([]suspendedOracleCase, []peSymbolOracleQuery) {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-pe-symbols-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit   string
		Fixtures []suspendedOracleCase
		Cases    []peSymbolOracleQuery
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Fixtures) != 36 || len(fixture.Cases) != 240 {
		t.Fatal("PE-symbol oracle drift")
	}
	return fixture.Fixtures, fixture.Cases
}
func peSymbolParameters(q peSymbolOracleQuery) map[string]string {
	names, _ := json.Marshal(q.Query.Symbols)
	addresses, _ := json.Marshal(q.Query.Addresses)
	return map[string]string{"source": q.Source, "module": q.Query.Module, "symbols": string(names), "addresses": string(addresses)}
}
func TestPESymbolsActualPinnedCommand(t *testing.T) {
	fixtures, queries := peSymbolOracle(t)
	ctx := context.Background()
	native := 0
	for id, c := range fixtures {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s", arch, c.Name), func(t *testing.T) {
				c.NativeArch = arch
				e, data := suspendedOracleEngine(t, c)
				for qid, q := range queries {
					if q.Fixture != id {
						continue
					}
					native++
					t.Run(fmt.Sprintf("%d-%s", qid, q.Source), func(t *testing.T) {
						var found []evidence.Row
						var emitted bytes.Buffer
						var summary evidence.Row
						result, err := e.Run(ctx, "windows.pe_symbols", peSymbolParameters(q), engine.RunOptions{Emit: func(row evidence.Row) error {
							switch row.Cells["RecordType"].String() {
							case "symbol":
								found = append(found, row)
							case "summary":
								summary = row
							case "memory_read":
								at, cause := row.Cells["Offset"].Uint()
								if cause != nil {
									t.Fatal(cause)
								}
								n, cause := row.Cells["Requested"].Uint()
								if cause != nil {
									t.Fatal(cause)
								}
								raw, ok := row.Cells["Raw"].Data.([]byte)
								if !ok || at > uint64(len(data)) || n > uint64(len(data))-at || !bytes.Equal(raw, data[at:at+n]) {
									t.Fatal("raw byte provenance", at, n)
								}
								actual, cause := memory.Read(ctx, e.Env.Kernel, at, int(n))
								if cause != nil || !bytes.Equal(raw, actual) {
									t.Fatal("independent paging reread", cause)
								}
							}
							return json.NewEncoder(&emitted).Encode(row)
						}})
						if q.NativeError != "" {
							if err == nil || !strings.Contains(err.Error(), q.NativeError) {
								t.Fatal("missing native corruption diagnostic", err)
							}
						} else if err != nil {
							t.Fatal(result, err)
						}
						if len(found) != len(q.Expected) {
							t.Fatal("entity count", len(found), len(q.Expected))
						}
						if summary.Cells["RecordType"].String() != "summary" {
							t.Fatal("missing summary")
						}
						for i, want := range q.Expected {
							for j, col := range []string{"Module", "Symbol", "Address"} {
								if col == "Address" {
									var n uint64
									if err := json.Unmarshal(want[j], &n); err != nil {
										t.Fatal(err)
									}
									got, err := found[i].Cells[col].Uint()
									if err != nil || got != n {
										t.Fatal(col, got, n, err)
									}
								} else {
									var text string
									if err := json.Unmarshal(want[j], &text); err != nil || found[i].Cells[col].String() != text {
										t.Fatal(col, found[i].Cells[col], text, err)
									}
								}
							}
						}
						var stored bytes.Buffer
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
								if err := json.NewEncoder(&stored).Encode(row); err != nil {
									t.Fatal(err)
								}
							}
							if len(rows) < 1000 {
								break
							}
						}
						if !bytes.Equal(emitted.Bytes(), stored.Bytes()) {
							t.Fatal("sealed JSONL changed")
						}
					})
				}
			})
		}
	}
	if native != 360 {
		t.Fatal("paging-query coverage", native)
	}
}
