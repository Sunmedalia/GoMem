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

type kmsgOracleRow struct {
	Facility, Level, Timestamp, Line string
	Caller                           *string
}
type kmsgOracleCase struct {
	Width            int
	Layout, Scenario string
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Expected         []kmsgOracleRow
}

func loadKmsgOracle(t testing.TB) []kmsgOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/linux-kmsg-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Commit string
		Cases  []kmsgOracleCase
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 64 {
		t.Fatal(err, len(oracle.Cases))
	}
	return oracle.Cases
}
func kmsgRow(row evidence.Row) kmsgOracleRow {
	r := kmsgOracleRow{Facility: row.Cells["facility"].String(), Level: row.Cells["level"].String(), Timestamp: row.Cells["timestamp"].String(), Line: row.Cells["line"].String()}
	if row.Cells["caller"].Kind != "missing" {
		s := row.Cells["caller"].String()
		r.Caller = &s
	}
	return r
}
func TestLinuxKmsgPinnedObjectsPagingEvidenceAndCache(t *testing.T) {
	for _, c := range loadKmsgOracle(t) {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s/%s", arch, c.Layout, c.Scenario), func(t *testing.T) {
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: c.Writes}, arch, "")
				got := []kmsgOracleRow{}
				reads, summaries := 0, 0
				var fresh, cached bytes.Buffer
				result, err := e.Run(context.Background(), "linux.kmsg", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Verify() != nil {
						t.Fatal("unsealed row")
					}
					switch row.Cells["RecordType"].String() {
					case "log":
						got = append(got, kmsgRow(row))
					case "ring_read":
						reads++
						verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
					case "descriptor":
					case "ring_summary":
						summaries++
					default:
						t.Fatal(row)
					}
					return json.NewEncoder(&fresh).Encode(row)
				}})
				if err != nil || result.Task.State != "completed" || !reflect.DeepEqual(got, c.Expected) || reads == 0 || summaries != 1 {
					t.Fatalf("%+v %v\ngot=%+v\nwant=%+v", result, err, got, c.Expected)
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
				again, err := e.Run(context.Background(), "linux.kmsg", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !again.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
					t.Fatal(again, err)
				}
			})
		}
	}
}

func TestLinuxKmsgFailedTasksRetainEvidenceAndRetry(t *testing.T) {
	for _, c := range loadKmsgOracle(t) {
		if c.Width != 8 || c.Scenario != "normal" {
			continue
		}
		t.Run(c.Layout, func(t *testing.T) {
			at, value := uint64(0x10000), uint64(0x300000)
			if c.Layout == "log" || c.Layout == "printk_log" {
				at, value = 0x11008, 0
			}
			mutation := pidOracleWrite(pidOracleCase{Width: c.Width, Writes: c.Writes}, at, value)
			e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: mutation.Writes}, "x64", "")
			var first, second bytes.Buffer
			var taskID string
			for i, b := range []*bytes.Buffer{&first, &second} {
				summaries := 0
				r, err := e.Run(context.Background(), "linux.kmsg", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Verify() != nil {
						t.Fatal("unsealed failure evidence")
					}
					if row.Cells["RecordType"].String() == "ring_summary" {
						summaries++
						if row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data != false {
							t.Fatal(row)
						}
					}
					return json.NewEncoder(b).Encode(row)
				}})
				if err == nil || r.Task.State != "failed" || r.Reused || summaries != 1 || i > 0 && r.Task.ID == taskID {
					t.Fatal(r, err, summaries)
				}
				taskID = r.Task.ID
			}
			if !bytes.Equal(first.Bytes(), second.Bytes()) {
				t.Fatal("retry evidence differs")
			}
		})
	}
}

func TestLinuxKmsgPinnedIDWrapAndEqualHeadTail(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-kmsg-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Controls []struct {
			kmsgOracleCase
			Failed bool
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Controls) != 4 {
		t.Fatal(err, len(oracle.Controls))
	}
	for _, c := range oracle.Controls {
		arches := []string{"x64"}
		if c.Width == 4 {
			arches = []string{"x86", "pae"}
		}
		for _, arch := range arches {
			t.Run(fmt.Sprintf("%s/%s", arch, c.Scenario), func(t *testing.T) {
				e := ebpfOracleEngine(t, ebpfOracleCase{Width: c.Width, ISF: c.ISF, Writes: c.Writes}, arch, "")
				got := []kmsgOracleRow{}
				params := map[string]string{"max-records": "8"}
				r, err := e.Run(context.Background(), "linux.kmsg", params, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "log" {
						got = append(got, kmsgRow(row))
					}
					if row.Cells["RecordType"].String() == "ring_read" {
						verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
					}
					return nil
				}})
				wantState := "completed"
				if c.Failed {
					wantState = "failed"
				}
				if (err != nil) != c.Failed || r.Task.State != wantState || !reflect.DeepEqual(got, c.Expected) {
					t.Fatal(r, err, "rows", len(got), len(c.Expected))
				}
				again, err := e.Run(context.Background(), "linux.kmsg", params, engine.RunOptions{})
				if (err != nil) != c.Failed || again.Reused == c.Failed || c.Failed && again.Task.ID == r.Task.ID {
					t.Fatal(again, err)
				}
			})
		}
	}
}
