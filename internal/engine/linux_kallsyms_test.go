package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type kallsymsRow struct {
	Name              string
	Type              *string
	Address           uint64
	Size              *uint64
	Exported          *bool
	Module, Subsystem string
	Description       *string
}
type kallsymsCase struct {
	Width                 int
	Layout, BPF, Scenario string
	ISF                   json.RawMessage
	Writes                [][]json.RawMessage
	Expected              []kallsymsRow
	ReferenceError        *string `json:"reference_error"`
}

func loadKallsymsOracle(t testing.TB) []kallsymsCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-kallsyms-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []kallsymsCase
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 120 {
		t.Fatal(err, len(v.Cases))
	}
	return v.Cases
}
func kallsymsEngine(t *testing.T, c kallsymsCase, arch string) *engine.Engine {
	t.Helper()
	// Every zero byte is significant: clear the region previously used by the
	// underlying paging fixture before installing sparse oracle writes.
	at, _ := json.Marshal(0x16000)
	zero, _ := json.Marshal(strings.Repeat("00", 0xa000))
	writes := append([][]json.RawMessage{{at, zero}}, c.Writes...)
	return ftraceOracleEngine(t, ftraceOracleCase{Width: c.Width, ISF: c.ISF, Writes: writes}, arch)
}
func kallsymsSelected(row evidence.Row) kallsymsRow {
	text := func(key string) *string {
		if row.Cells[key].Kind == "missing" {
			return nil
		}
		s := row.Cells[key].String()
		return &s
	}
	r := kallsymsRow{Name: row.Cells["SymbolName"].String(), Type: text("Type"), Module: row.Cells["ModuleName"].String(), Subsystem: row.Cells["SubSystem"].String(), Description: text("Description")}
	r.Address, _ = row.Cells["Addr"].Uint()
	if row.Cells["Size"].Kind != "missing" {
		v, _ := row.Cells["Size"].Uint()
		r.Size = &v
	}
	if row.Cells["Exported"].Kind != "missing" {
		v := row.Cells["Exported"].Data == true
		r.Exported = &v
	}
	return r
}
func TestLinuxKallsymsAllSourcesPagingEvidenceAndCache(t *testing.T) {
	cases := loadKallsymsOracle(t)
	for _, c := range cases {
		expected := c.Expected
		if c.ReferenceError != nil {
			if *c.ReferenceError != "pointer_to_string takes a Pointer" || c.Scenario != "prel32-exports" {
				t.Fatal(c.ReferenceError)
			}
			// The fixed PREL32 export-name helper raises TypeError. Native PREL32
			// is checked against identical absolute export data, not claimed parity.
			for _, control := range cases {
				if control.Width == c.Width && control.Layout == c.Layout && control.BPF == c.BPF && control.Scenario == "normal" {
					expected = control.Expected
					break
				}
			}
		}
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s/%s", arch, c.Layout, c.BPF, c.Scenario), func(t *testing.T) {
				e := kallsymsEngine(t, c, arch)
				got := []kallsymsRow{}
				reads, sources, summaries := 0, 0, 0
				var fresh, cached bytes.Buffer
				held := []evidence.Row{}
				result, err := e.Run(context.Background(), "linux.kallsyms", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Verify() != nil {
						t.Fatal("seal")
					}
					held = append(held, row)
					switch row.Cells["RecordType"].String() {
					case "symbol":
						got = append(got, kallsymsSelected(row))
					case "symbol_read":
						reads++
						verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
					case "symbol_source":
						sources++
						if row.Cells["Error"].Error != "" {
							t.Fatal(row)
						}
					case "symbols_summary":
						summaries++
					default:
						t.Fatal(row)
					}
					return json.NewEncoder(&fresh).Encode(row)
				}})
				if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, expected) || reads == 0 || sources != 4 || summaries != 1 {
					g, _ := json.Marshal(got)
					w, _ := json.Marshal(expected)
					t.Fatalf("state=%s error=%v reads=%d sources=%d summaries=%d\ngot %s\nwant %s", result.Task.State, err, reads, sources, summaries, g, w)
				}
				for _, row := range held {
					if row.Verify() != nil {
						t.Fatal("mutated output")
					}
				}
				for offset := 0; offset < int(result.Task.Rows); {
					rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
					if err != nil || len(rows) == 0 {
						t.Fatal(offset, err)
					}
					for _, row := range rows {
						if row.Verify() != nil {
							t.Fatal("stored seal")
						}
					}
					offset += len(rows)
				}
				again, err := e.Run(context.Background(), "linux.kallsyms", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal(again, err)
				}
			})
		}
	}
}

func TestLinuxKallsymsFailuresAreExplicitAndNotCached(t *testing.T) {
	var c kallsymsCase
	for _, candidate := range loadKallsymsOracle(t) {
		if candidate.Width == 8 && candidate.Layout == "typetab" && candidate.BPF == "legacy" && candidate.Scenario == "normal" {
			c = candidate
			break
		}
	}
	for _, fault := range []string{"module-cycle", "ftrace-cycle", "bpf-cycle", "string-hole", "export-hole", "symbol-table-hole", "core-count-bound", "core-name-hole", "node-bound", "symbol-bound", "byte-bound"} {
		t.Run(fault, func(t *testing.T) {
			mutated := c
			params := map[string]string{}
			at, value := uint64(0), uint64(0)
			switch fault {
			case "module-cycle":
				at, value = 0x18000, 0x18000
			case "ftrace-cycle":
				at, value = 0x19d00, 0x19d00
			case "bpf-cycle":
				at, value = 0x1a200, 0x1a200
			case "string-hole":
				at, value = 0x18208, 0x300000
			case "export-hole":
				at, value = 0x18088, 0x300000
			case "symbol-table-hole":
				at, value = 0x18200, 0x300000
			case "core-name-hole":
				var isf map[string]json.RawMessage
				if err := json.Unmarshal(c.ISF, &isf); err != nil {
					t.Fatal(err)
				}
				var syms map[string]json.RawMessage
				if err := json.Unmarshal(isf["symbols"], &syms); err != nil {
					t.Fatal(err)
				}
				syms["kallsyms_names"] = json.RawMessage(`{"address":3145728}`)
				isf["symbols"], _ = json.Marshal(syms)
				mutated.ISF, _ = json.Marshal(isf)
			case "core-count-bound":
				at, value = 0x16000, 10000001
			case "node-bound":
				params["max-nodes"] = "1"
			case "symbol-bound":
				params["max-symbols"] = "4"
			case "byte-bound":
				params["max-bytes"] = "16"
			}
			if at != 0 {
				p := pidOracleWrite(pidOracleCase{Width: 8, Writes: c.Writes}, at, value)
				mutated.Writes = p.Writes
			}
			e := kallsymsEngine(t, mutated, "x64")
			first := ""
			for attempt := 0; attempt < 2; attempt++ {
				result, err := e.Run(context.Background(), "linux.kallsyms", params, engine.RunOptions{})
				if err == nil || result.Task.State != "failed" || result.Reused || result.Task.ID == first {
					t.Fatal(fault, result, err)
				}
				first = result.Task.ID
			}
		})
	}
}
