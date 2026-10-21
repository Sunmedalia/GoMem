package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type ftraceOracleRow struct {
	Ops, Address             uint64
	Callback, Hooked, Module *string
	ModuleAddress            *uint64 `json:"module_address"`
	Flags                    string
}
type ftraceOracleCase struct {
	Width            int
	Layout, Scenario string
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Expected         []ftraceOracleRow
}

func loadFtraceOracle(t testing.TB) []ftraceOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-ftrace-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []ftraceOracleCase
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 48 {
		t.Fatal(err, len(v.Cases))
	}
	return v.Cases
}
func ftraceOracleEngine(t *testing.T, c ftraceOracleCase, arch string, fullModules ...bool) *engine.Engine {
	t.Helper()
	scenario := arch
	if arch == "x64" {
		scenario = "control"
	}
	f := kthreadFixture(t, scenario, "worker-private")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range fragment.Bases {
		table.Bases[k] = v
	}
	for k, v := range fragment.Types {
		table.Types[k] = v
	}
	for k, v := range fragment.Symbols {
		table.Symbols[k] = v
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	clear(data[0x16f00:0x18000])
	// Kernel-only parser oracles have an explicit kernel range. Run real but
	// empty module gatherers here; the separate module-owner pipeline below
	// exercises positive Lsmod/SysFs/Scanner ranges and ELF resolution.
	if len(fullModules) == 0 || !fullModules[0] {
		put := func(at, value uint64) {
			if c.Width == 4 {
				binary.LittleEndian.PutUint32(data[at:], uint32(value))
			} else {
				binary.LittleEndian.PutUint64(data[at:], value)
			}
		}
		put(0x1d000, 0x1d000)
		put(0x1d000+uint64(c.Width), 0x1d000)
		put(0xe000, 0xe000)
		put(0xe000+uint64(c.Width), 0xe000)
		binary.LittleEndian.PutUint64(data[0x1d108:], 0xc000)
		binary.LittleEndian.PutUint64(data[0x1d110:], 0xc000)
	}

	for _, w := range c.Writes {
		var at int
		var s string
		if err = json.Unmarshal(w[0], &at); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(w[1], &s); err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], b)
	}
	raw, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return openModx(t, f, scenario)
}
func ftraceSelected(row evidence.Row) ftraceOracleRow {
	text := func(k string) *string {
		if row.Cells[k].Kind == "missing" {
			return nil
		}
		s := row.Cells[k].String()
		return &s
	}
	r := ftraceOracleRow{Callback: text("Callback"), Hooked: text("Hooked symbols"), Module: text("Module"), Flags: row.Cells["Flags"].String()}
	r.Ops, _ = row.Cells["ftrace_ops address"].Uint()
	r.Address, _ = row.Cells["Callback address"].Uint()
	if row.Cells["Module address"].Kind != "missing" {
		v, _ := row.Cells["Module address"].Uint()
		r.ModuleAddress = &v
	}
	return r
}
func TestLinuxFtracePinnedObjectsPagingEvidenceAndCache(t *testing.T) {
	for _, c := range loadFtraceOracle(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, c.Scenario), func(t *testing.T) {
				e := ftraceOracleEngine(t, c, arch)
				for _, show := range []bool{false, true} {
					got := []ftraceOracleRow{}
					reads := 0
					summary := 0
					var fresh, cached bytes.Buffer
					held := []evidence.Row{}
					params := map[string]string{"show-ftrace-flags": fmt.Sprint(show)}
					result, err := e.Run(context.Background(), "linux.check_ftrace", params, engine.RunOptions{Emit: func(row evidence.Row) error {
						if row.Verify() != nil {
							t.Fatal("seal")
						}
						held = append(held, row)
						switch row.Cells["RecordType"].String() {
						case "ftrace_hook":
							r := ftraceSelected(row)
							if !show {
								r.Flags = ""
								if _, ok := row.Cells["Flags"]; ok {
									t.Fatal("unexpected optional flag column")
								}
							}
							got = append(got, r)
						case "ftrace_read":
							reads++
							verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
						case "ftrace_summary":
							summary++
						}
						return json.NewEncoder(&fresh).Encode(row)
					}})
					want := make([]ftraceOracleRow, len(c.Expected))
					copy(want, c.Expected)
					if !show {
						for i := range want {
							want[i].Flags = ""
						}
					}
					if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, want) || reads == 0 || summary != 1 {
						t.Fatalf("state=%s err=%v reads=%d summary=%d\ngot=%+v\nwant=%+v", result.Task.State, err, reads, summary, got, want)
					}
					for _, row := range held {
						if row.Verify() != nil {
							t.Fatal("emitted row mutated")
						}
					}
					for offset := 0; offset < int(result.Task.Rows); {
						rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
						if err != nil || len(rows) == 0 {
							t.Fatal(err, offset)
						}
						for _, row := range rows {
							if row.Verify() != nil {
								t.Fatal("stored seal")
							}
						}
						offset += len(rows)
					}
					again, err := e.Run(context.Background(), "linux.check_ftrace", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
					if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
						t.Fatal(again, err)
					}
				}
			})
		}
	}
}

func ftraceWrite(c ftraceOracleCase, at, value uint64) ftraceOracleCase {
	p := pidOracleWrite(pidOracleCase{Width: c.Width, Writes: c.Writes}, at, value)
	c.Writes = p.Writes
	return c
}
func TestLinuxFtraceReadFailuresBoundsAndFreshRetry(t *testing.T) {
	for _, c := range loadFtraceOracle(t) {
		if c.Scenario != "normal" {
			continue
		}
		arch := "x64"
		if c.Width == 4 {
			arch = "x86"
		}
		for _, fault := range []string{"ops-cycle", "entry-cycle", "ops-hole", "entry-hole", "hash-hole", "next-hole", "null-end", "entry-bound", "ops-bound", "byte-budget"} {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, fault), func(t *testing.T) {
				mutated := c
				params := map[string]string{}
				switch fault {
				case "ops-cycle":
					mutated = ftraceWrite(c, 0x17108, 0x17000)
				case "entry-cycle":
					mutated = ftraceWrite(c, 0x17a40, 0x17a00)
				case "ops-hole":
					mutated = ftraceWrite(c, 0x16f00, 0x300000)
				case "entry-hole":
					mutated = ftraceWrite(c, 0x17800, 0x300000)
				case "hash-hole":
					at := uint64(0x17018)
					if c.Layout == "pointer" {
						at = 0x17400
					}
					mutated = ftraceWrite(c, at, 0x300000)
				case "next-hole":
					mutated = ftraceWrite(c, 0x17008, 0x300000)
				case "null-end":
					mutated = ftraceWrite(c, 0x17108, 0)
				case "entry-bound":
					params["max-entries"] = "1"
				case "ops-bound":
					params["max-nodes"] = "1"
				case "byte-budget":
					params["max-bytes"] = "16"
				}
				e := ftraceOracleEngine(t, mutated, arch)
				first := ""
				for attempt := 0; attempt < 2; attempt++ {
					result, err := e.Run(context.Background(), "linux.check_ftrace", params, engine.RunOptions{Emit: func(row evidence.Row) error {
						if row.Verify() != nil {
							t.Fatal("seal")
						}
						return nil
					}})
					if err == nil || result.Task.State != "failed" || result.Reused || result.Task.ID == first {
						t.Fatal(fault, result, err)
					}
					first = result.Task.ID
				}
			})
		}
	}
}
func TestLinuxFtraceSelectedModuleOwnership(t *testing.T) {
	for _, c := range loadFtraceOracle(t) {
		if c.Scenario != "normal" || c.Layout != "legacy" {
			continue
		}
		arch := "x64"
		if c.Width == 4 {
			arch = "x86"
		}
		t.Run(arch, func(t *testing.T) {
			c = ftraceWrite(c, 0x17000, 0x10100)
			e := ftraceOracleEngine(t, c, arch, true)
			selected := 0
			result, err := e.Run(context.Background(), "linux.check_ftrace", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "ftrace_hook" {
					at, _ := row.Cells["ftrace_ops address"].Uint()
					if at == 0x17000 {
						selected++
						if row.Cells["Module"].String() != "active" || row.Cells["Callback"].String() != "module_entry" {
							t.Fatal(row)
						}
					}
				}
				return nil
			}})
			if err != nil || result.Task.State != "completed" || selected != 2 {
				t.Fatal(result, err, selected)
			}
		})
	}
}
