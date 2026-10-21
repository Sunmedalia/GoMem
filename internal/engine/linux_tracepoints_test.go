package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

type tracepointOracleRow struct {
	Name                string
	Tracepoint, Address uint64
	Probe, Module       *string
	ModuleAddress       *uint64 `json:"module_address"`
	Priority            *int64
	RawPriority         *int64 `json:"raw_priority"`
}
type tracepointOracleCase struct {
	Width            int
	Layout, Scenario string
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Expected         []tracepointOracleRow
}

func loadTracepointsOracle(t testing.TB) []tracepointOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-tracepoints-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []tracepointOracleCase
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 60 {
		t.Fatal(err, len(v.Cases))
	}
	return v.Cases
}
func tracepointsEngine(t *testing.T, c tracepointOracleCase, arch string, fullModules ...bool) *engine.Engine {
	return ftraceOracleEngine(t, ftraceOracleCase{Width: c.Width, ISF: c.ISF, Writes: c.Writes}, arch, fullModules...)
}
func tracepointSelected(row evidence.Row) tracepointOracleRow {
	text := func(k string) *string {
		if row.Cells[k].Kind == "missing" {
			return nil
		}
		s := row.Cells[k].String()
		return &s
	}
	signed := func(k string) *int64 {
		if row.Cells[k].Kind == "missing" {
			return nil
		}
		v, err := row.Cells[k].Int()
		if err != nil {
			panic(err)
		}
		return &v
	}
	r := tracepointOracleRow{Name: row.Cells["tracepoint"].String(), Probe: text("Probe"), Module: text("Module"), Priority: signed("Probe priority"), RawPriority: signed("RawPriority")}
	r.Tracepoint, _ = row.Cells["tracepoint address"].Uint()
	r.Address, _ = row.Cells["Probe address"].Uint()
	if row.Cells["Module address"].Kind != "missing" {
		v, _ := row.Cells["Module address"].Uint()
		r.ModuleAddress = &v
	}
	return r
}
func TestLinuxTracepointsPinnedObjectsPagingEvidenceAndCache(t *testing.T) {
	for _, c := range loadTracepointsOracle(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, c.Scenario), func(t *testing.T) {
				e := tracepointsEngine(t, c, arch)
				got := []tracepointOracleRow{}
				reads, summaries := 0, 0
				held := []evidence.Row{}
				var fresh, cached bytes.Buffer
				result, err := e.Run(context.Background(), "linux.check_tracepoints", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Verify() != nil {
						t.Fatal("seal")
					}
					held = append(held, row)
					switch row.Cells["RecordType"].String() {
					case "tracepoint_probe":
						got = append(got, tracepointSelected(row))
						if row.Cells["NameReadComplete"].Data != true {
							t.Fatal(row)
						}
					case "tracepoint_read":
						reads++
						verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
					case "tracepoints_summary":
						summaries++
					}
					return json.NewEncoder(&fresh).Encode(row)
				}})
				if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, c.Expected) || reads == 0 || summaries != 1 {
					g, _ := json.Marshal(got)
					w, _ := json.Marshal(c.Expected)
					t.Fatalf("state=%s err=%v reads=%d summaries=%d\ngot=%s\nwant=%s", result.Task.State, err, reads, summaries, g, w)
				}
				for _, row := range held {
					if row.Verify() != nil {
						t.Fatal("output mutated")
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
				again, err := e.Run(context.Background(), "linux.check_tracepoints", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal(again, err)
				}
			})
		}
	}
}

func tracepointWrite(c tracepointOracleCase, at, value uint64) tracepointOracleCase {
	p := pidOracleWrite(pidOracleCase{Width: c.Width, Writes: c.Writes}, at, value)
	c.Writes = p.Writes
	return c
}
func TestLinuxTracepointsFailuresAreExplicitAndNotCached(t *testing.T) {
	for _, c := range loadTracepointsOracle(t) {
		if c.Scenario != "normal" {
			continue
		}
		arch := "x64"
		if c.Width == 4 {
			arch = "x86"
		}
		for _, fault := range []string{"point-hole", "funcs-hole", "probe-hole", "name-hole", "probe-bound", "point-bound", "byte-budget", "relative-underflow"} {
			if fault == "relative-underflow" && c.Layout != "prel32" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, fault), func(t *testing.T) {
				mutated := c
				params := map[string]string{}
				switch fault {
				case "point-hole":
					value := uint64(0x300000)
					if c.Layout == "prel32" {
						value -= 0x16f00
					}
					mutated = tracepointWrite(c, 0x16f00, value)
				case "funcs-hole":
					mutated = tracepointWrite(c, 0x17010, 0x300000)
				case "probe-hole":
					mutated = tracepointWrite(c, 0x17200, 0x300000)
				case "name-hole":
					mutated = tracepointWrite(c, 0x17000, 0x300000)
				case "probe-bound":
					params["max-probes"] = "2"
				case "point-bound":
					params["max-tracepoints"] = "1"
				case "byte-budget":
					params["max-bytes"] = "16"
				case "relative-underflow":
					mutated = tracepointWrite(c, 0x16f00, 0xfff00000)
				}
				e := tracepointsEngine(t, mutated, arch)
				first := ""
				for attempt := 0; attempt < 2; attempt++ {
					result, err := e.Run(context.Background(), "linux.check_tracepoints", params, engine.RunOptions{Emit: func(row evidence.Row) error {
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
func TestLinuxTracepointsSelectedModuleObjectAddress(t *testing.T) {
	for _, c := range loadTracepointsOracle(t) {
		if c.Scenario != "normal" || c.Layout != "absolute" {
			continue
		}
		arch := "x64"
		if c.Width == 4 {
			arch = "x86"
		}
		t.Run(arch, func(t *testing.T) {
			c = tracepointWrite(c, 0x17200, 0x10100)
			e := tracepointsEngine(t, c, arch, true)
			selected := 0
			result, err := e.Run(context.Background(), "linux.check_tracepoints", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "tracepoint_probe" {
					fn, _ := row.Cells["Probe address"].Uint()
					if fn == 0x10100 {
						selected++
						address, _ := row.Cells["Module address"].Uint()
						if row.Cells["Module"].String() != "active" || row.Cells["Probe"].String() != "module_entry" || address != 0xc000 {
							t.Fatal(row)
						}
					}
				}
				return nil
			}})
			if err != nil || result.Task.State != "completed" || selected != 1 {
				t.Fatal(result, err, selected)
			}
		})
	}
}
