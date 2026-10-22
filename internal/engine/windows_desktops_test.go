package engine_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestDesktopsSealedStorageFreshSymbolsAndFailedRetry(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/windows-desktops-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Scenario   string
			ISF        json.RawMessage
			Size       int
			KernelBase uint64 `json:"kernel_base"`
			Results    map[string]struct{ Rows [][]json.RawMessage }
			Writes     []struct {
				Offset int
				Data   string
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 16 {
		t.Fatal("desktop fixture drift")
	}
	for _, c := range fixture.Cases {
		for _, mode := range []string{"desktops", "deskscan"} {
			t.Run(mode+"/"+c.Scenario, func(t *testing.T) {
				data := make([]byte, c.Size)
				for _, w := range c.Writes {
					b, err := hex.DecodeString(w.Data)
					if err != nil || w.Offset < 0 || w.Offset > len(data)-len(b) {
						t.Fatal("bad desktop fixture", err)
					}
					copy(data[w.Offset:], b)
				}
				e, catalogPath := openGUIFixtureEngine(t, data, c.ISF, c.KernelBase)
				defer e.Close()
				var wire bytes.Buffer
				got := [][]any{}
				result, cause := e.Run(context.Background(), "windows."+mode, nil, engine.RunOptions{Emit: func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "desktop" {
						at, _ := row.Cells["Offset"].Uint()
						sid, _ := row.Cells["Session"].Uint()
						pid, _ := row.Cells["PID"].Uint()
						var name any
						if row.Cells["Desktop"].Kind != "missing" {
							name = row.Cells["Desktop"].String()
						}
						got = append(got, []any{at, row.Cells["WindowStation"].String(), sid, name, row.Cells["Process"].String(), pid})
					}
					return json.NewEncoder(&wire).Encode(row)
				}})
				failure := c.Scenario == "owner-unmapped" || c.Scenario == "thread-cycle" || c.Scenario == "thread-unmapped" || c.Scenario == "name-unmapped" || mode == "deskscan" && c.Scenario == "parent-unmapped"
				if (cause != nil) != failure || result.Reused {
					t.Fatal("desktop task status", cause, result.Reused)
				}
				want := [][]any{}
				for _, r := range c.Results[mode].Rows {
					var at, sid, pid uint64
					var station, process string
					var name any
					_ = json.Unmarshal(r[0], &at)
					_ = json.Unmarshal(r[1], &station)
					_ = json.Unmarshal(r[2], &sid)
					_ = json.Unmarshal(r[3], &name)
					_ = json.Unmarshal(r[4], &process)
					_ = json.Unmarshal(r[5], &pid)
					want = append(want, []any{at, station, sid, name, process, pid})
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatal("desktop engine original field difference", got, want)
				}
				var stored bytes.Buffer
				for offset := 0; ; offset += 1000 {
					rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range rows {
						if err = row.Verify(); err != nil {
							t.Fatal(err)
						}
						if err = json.NewEncoder(&stored).Encode(row); err != nil {
							t.Fatal(err)
						}
					}
					if len(rows) < 1000 {
						break
					}
				}
				if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
					t.Fatal("desktop sealed stream differs")
				}
				second, cause := e.Run(context.Background(), "windows."+mode, nil, engine.RunOptions{})
				if (cause != nil) != failure || second.Reused || second.Task.ID == result.Task.ID {
					t.Fatal("desktop fresh dependency validation bypassed", cause, second.Reused)
				}
				for retry := 0; retry < 2; retry++ {
					failed, cause := e.Run(context.Background(), "windows."+mode, map[string]string{"max-reads": "1"}, engine.RunOptions{})
					if cause == nil || failed.Reused {
						t.Fatal("failed desktop task reused", cause, failed.Reused)
					}
				}
				if err = os.WriteFile(catalogPath, []byte("bad layout"), 0600); err != nil {
					t.Fatal(err)
				}
				rejected, cause := e.Run(context.Background(), "windows."+mode, nil, engine.RunOptions{})
				if cause == nil || rejected.Reused {
					t.Fatal("desktop task reused over corrupt layout", cause, rejected.Reused)
				}
			})
		}
	}
}
