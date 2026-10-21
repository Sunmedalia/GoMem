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
	"reflect"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type pidOracleRow struct {
	Offset, PID, TID, PPID uint64
	Comm                   string
}
type pidOracleCase struct {
	Width            int
	Layout, Scenario string
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Plain, Decorated []pidOracleRow
}

func loadPIDOracle(t *testing.T) []pidOracleCase {
	t.Helper()
	b, err := os.ReadFile("testdata/linux-pidhashtable-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []pidOracleCase
	}
	if err = json.Unmarshal(b, &v); err != nil || v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 96 {
		t.Fatal(err, len(v.Cases))
	}
	return v.Cases
}
func pidRow(row evidence.Row) pidOracleRow {
	at, _ := row.Cells["OFFSET"].Uint()
	pid, _ := row.Cells["PID"].Uint()
	tid, _ := row.Cells["TID"].Uint()
	ppid, _ := row.Cells["PPID"].Uint()
	return pidOracleRow{at, pid, tid, ppid, row.Cells["COMM"].String()}
}
func TestLinuxPIDHashPinnedObjectsPagingEvidenceAndCache(t *testing.T) {
	for _, c := range loadPIDOracle(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, c.Scenario), func(t *testing.T) {
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: c.Writes}, arch, "")
				for _, decorate := range []bool{false, true} {
					params := map[string]string{"decorate-comm": strconv.FormatBool(decorate)}
					got := []pidOracleRow{}
					reads, summaries := 0, 0
					var fresh, cached bytes.Buffer
					res, err := e.Run(context.Background(), "linux.pidhashtable", params, engine.RunOptions{Emit: func(row evidence.Row) error {
						if err := row.Verify(); err != nil {
							t.Fatal(err)
						}
						switch row.Cells["RecordType"].String() {
						case "task":
							got = append(got, pidRow(row))
							if row.Cells["TaskIdentity"].String() == "" {
								t.Fatal(row)
							}
						case "index_read":
							reads++
							verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
						case "task_candidate":
						case "index_summary":
							summaries++
						default:
							t.Fatal(row)
						}
						return json.NewEncoder(&fresh).Encode(row)
					}})
					want := c.Plain
					if decorate {
						want = c.Decorated
					}
					if err != nil || res.Task.State != "completed" || !reflect.DeepEqual(got, want) || reads == 0 || summaries != 1 {
						t.Fatalf("%+v %v got=%+v want=%+v", res, err, got, want)
					}
					stored, err := e.Store.Query(context.Background(), evidence.Query{TaskID: res.Task.ID, Limit: 1000})
					if err != nil || len(stored) != int(res.Task.Rows) {
						t.Fatal(err, len(stored), res)
					}
					for _, row := range stored {
						if err := row.Verify(); err != nil {
							t.Fatal(err)
						}
					}
					again, err := e.Run(context.Background(), "linux.pidhashtable", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
					if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
						t.Fatal(again, err)
					}
				}
			})
		}
	}
}

// Mutations change bytes consumed through real paging, not object-reader mocks.
func pidOracleWrite(c pidOracleCase, at uint64, value uint64) pidOracleCase {
	raw := make([]byte, c.Width)
	if c.Width == 4 {
		binary.LittleEndian.PutUint32(raw, uint32(value))
	} else {
		binary.LittleEndian.PutUint64(raw, value)
	}
	a, _ := json.Marshal(at)
	b, _ := json.Marshal(hex.EncodeToString(raw))
	c.Writes = append(append([][]json.RawMessage(nil), c.Writes...), []json.RawMessage{a, b})
	return c
}
func TestLinuxPIDHashFailuresAreExplicitAndNotCached(t *testing.T) {
	for _, c := range loadPIDOracle(t) {
		if c.Scenario != "normal" || c.Layout != "legacy" && c.Layout != "xarray" {
			continue
		}
		arch := "x64"
		if c.Width == 4 {
			arch = "x86"
		}
		for _, fault := range []string{"task-hole", "parent-hole", "index-hole", "cycle"} {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, fault), func(t *testing.T) {
				mutated := c
				switch fault {
				case "task-hole":
					mutated = pidOracleWrite(c, 0x12000, 0x300020)
				case "parent-hole":
					mutated = pidOracleWrite(c, 0x14010, 0x300000)
				case "index-hole":
					at, value := uint64(0x11000), uint64(0x300030)
					if c.Layout == "xarray" {
						at, value = 0x10018, 0x300002
					}
					mutated = pidOracleWrite(c, at, value)
				case "cycle":
					at, value := uint64(0x12130), uint64(0x12130)
					if c.Layout == "xarray" {
						at, value = 0x11010, 0x11002
					}
					mutated = pidOracleWrite(c, at, value)
				}
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: mutated.Width, ISF: mutated.ISF, Writes: mutated.Writes}, arch, "")
				var previous string
				for attempt := 0; attempt < 2; attempt++ {
					tasks, summaries, errorsSeen := 0, 0, 0
					r, err := e.Run(context.Background(), "linux.pidhashtable", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
						if row.Verify() != nil {
							t.Fatal("unsealed evidence")
						}
						if row.Cells["Error"].Error != "" {
							errorsSeen++
						}
						if row.Cells["RecordType"].String() == "task" {
							tasks++
						}
						if row.Cells["RecordType"].String() == "index_summary" {
							summaries++
							if row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data != false {
								t.Fatal(row)
							}
						}
						return nil
					}})
					if err == nil || r.Task.State != "failed" || r.Reused || r.Task.ID == previous || summaries != 1 || errorsSeen == 0 {
						t.Fatal(r, err, summaries, errorsSeen)
					}
					if (fault == "task-hole" || fault == "parent-hole") && tasks != 2 {
						t.Fatal("unrelated tasks lost", tasks)
					}
					previous = r.Task.ID
				}
			})
		}
	}
}
func TestLinuxPIDHashCancellationOutputAndBounds(t *testing.T) {
	for _, c := range loadPIDOracle(t) {
		if c.Width != 8 || c.Scenario != "normal" || c.Layout != "legacy" && c.Layout != "xarray" {
			continue
		}
		t.Run(c.Layout, func(t *testing.T) {
			e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: c.Writes}, "x64", "")
			for _, p := range []map[string]string{{"max-nodes": "0"}, {"max-tasks": "1000001"}, {"max-nodes": "1"}, {"max-tasks": "1"}, {"max-buckets": "0"}, {"decorate-comm": "invalid"}} {
				r, err := e.Run(context.Background(), "linux.pidhashtable", p, engine.RunOptions{})
				if c.Layout == "xarray" && p["max-nodes"] == "1" {
					if err != nil || r.Task.State != "completed" {
						t.Fatal(r, err, p)
					}
					continue
				}
				if err == nil || r.Task.State == "completed" {
					t.Fatal(r, err, p)
				}
			}
			stop := errors.New("output stopped")
			calls := 0
			_, err := e.Run(context.Background(), "linux.pidhashtable", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; return stop }})
			if !errors.Is(err, stop) || calls != 1 {
				t.Fatal(err, calls)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls = 0
			_, err = e.Run(ctx, "linux.pidhashtable", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; cancel(); return nil }})
			if !errors.Is(err, context.Canceled) || calls != 1 {
				t.Fatal(err, calls)
			}
		})
	}
}

func TestLinuxPIDHashRejectsMalformedSymbols(t *testing.T) {
	for _, c := range loadPIDOracle(t) {
		if c.Width != 8 || c.Scenario != "normal" || c.Layout != "legacy" && c.Layout != "xarray" {
			continue
		}
		for _, fault := range []string{"missing-enum", "scalar-task-links", "scalar-pid-tasks", "missing-root"} {
			t.Run(c.Layout+"/"+fault, func(t *testing.T) {
				table, err := symbols.Parse(c.ISF)
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "missing-enum":
					delete(table.Enums, "pid_type")
				case "scalar-task-links":
					typ := table.Types["task_struct"]
					field := typ.Fields["pids"]
					field.Type = symbols.TypeRef{Kind: "base", Name: "u32"}
					typ.Fields["pids"] = field
					table.Types["task_struct"] = typ
				case "scalar-pid-tasks":
					typ := table.Types["pid"]
					field := typ.Fields["tasks"]
					field.Type = symbols.TypeRef{Kind: "base", Name: "u32"}
					typ.Fields["tasks"] = field
					table.Types["pid"] = typ
				case "missing-root":
					delete(table.Symbols, "init_pid_ns")
					delete(table.Symbols, "pid_hash")
				}
				raw, err := table.Encode()
				if err != nil {
					t.Fatal(err)
				}
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: raw, Writes: c.Writes}, "x64", "")
				r, err := e.Run(context.Background(), "linux.pidhashtable", nil, engine.RunOptions{})
				if err == nil || r.Task.State != "failed" {
					t.Fatal(r, err)
				}
			})
		}
	}
}
