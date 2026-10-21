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

type perfOracleRow struct {
	PID                uint64
	Process            string
	Event, Short, Full *string
	Address            *uint64
}
type perfOracleCase struct {
	Width            int
	Layout, Scenario string
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Expected         []perfOracleRow
	Incomplete       bool
}

func loadPerfOracle(t testing.TB) []perfOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-perf-events-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Commit string
		Cases  []perfOracleCase
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 44 {
		t.Fatal(err, len(oracle.Cases))
	}
	return oracle.Cases
}
func perfRow(row evidence.Row) perfOracleRow {
	text := func(name string) *string {
		v := row.Cells[name]
		if v.Kind == "missing" {
			return nil
		}
		s := v.String()
		return &s
	}
	pid, _ := row.Cells["PID"].Uint()
	r := perfOracleRow{PID: pid, Process: row.Cells["Process"].String(), Event: text("Event"), Short: text("Short Program Name"), Full: text("Full Name")}
	if row.Cells["Address"].Kind != "missing" {
		n, _ := row.Cells["Address"].Uint()
		r.Address = &n
	}
	return r
}
func TestLinuxPerfEventsPinnedObjectsPagingEvidenceAndCache(t *testing.T) {
	for _, c := range loadPerfOracle(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, c.Scenario), func(t *testing.T) {
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: c.Writes}, arch, "")
				got := []perfOracleRow{}
				reads, tasks, summaries := 0, 0, 0
				var fresh, cached bytes.Buffer
				result, err := e.Run(context.Background(), "linux.perf_events", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Verify() != nil {
						t.Fatal("unsealed evidence")
					}
					switch row.Cells["RecordType"].String() {
					case "perf_event":
						got = append(got, perfRow(row))
						if row.Cells["TaskIdentity"].String() == "" {
							t.Fatal(row)
						}
					case "event_observation":
						if row.Cells["Status"].String() != "null_program" {
							t.Fatal(row)
						}
					case "event_read":
						reads++
						verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
					case "task_observation":
						tasks++
					case "event_summary":
						summaries++
					default:
						t.Fatal(row)
					}
					return json.NewEncoder(&fresh).Encode(row)
				}})
				wantState := "completed"
				wantTasks := 3
				if c.Incomplete {
					wantState = "failed"
				}
				if c.Scenario == "invalid-leader-parent" {
					wantTasks = 2
				}
				if (err != nil) != c.Incomplete || result.Task.State != wantState || !reflect.DeepEqual(got, c.Expected) || reads == 0 || tasks != wantTasks || summaries != 1 {
					t.Fatalf("%+v %v tasks=%d\ngot=%+v\nwant=%+v", result, err, tasks, got, c.Expected)
				}
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 1000})
				if err != nil || len(rows) != int(result.Task.Rows) {
					t.Fatal(err, len(rows), result)
				}
				for _, row := range rows {
					if row.Verify() != nil {
						t.Fatal("stored seal")
					}
				}
				again, err := e.Run(context.Background(), "linux.perf_events", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if (err != nil) != c.Incomplete || again.Reused == c.Incomplete || !bytes.Equal(fresh.Bytes(), cached.Bytes()) || c.Incomplete && again.Task.ID == result.Task.ID {
					t.Fatal(again, err)
				}
			})
		}
	}
}
