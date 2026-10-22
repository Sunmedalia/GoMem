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

func TestWindowListSealedStoreFreshSymbolsAndFailedRetry(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/windows-windowlist-oracle.json")
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
			Rows       [][]json.RawMessage
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
		t.Fatal("window list fixture drift")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Scenario, func(t *testing.T) {
			data := make([]byte, c.Size)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset > len(data)-len(b) {
					t.Fatal("invalid window image", err)
				}
				copy(data[w.Offset:], b)
			}
			e, catalogPath := openGUIFixtureEngine(t, data, c.ISF, c.KernelBase)
			defer e.Close()
			var wire bytes.Buffer
			got := [][]any{}
			result, cause := e.Run(context.Background(), "windows.windows", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "window" {
					fields := make([]any, 8)
					for i, key := range []string{"Offset", "Station", "Session", "Desktop", "Window", "Procedure", "Process", "PID"} {
						v := row.Cells[key]
						if v.Kind == "missing" {
							continue
						}
						if i == 0 || i == 2 || i == 5 || i == 7 {
							n, _ := v.Uint()
							fields[i] = n
						} else {
							fields[i] = v.String()
						}
					}
					got = append(got, fields)
				}
				return json.NewEncoder(&wire).Encode(row)
			}})
			if cause == nil || result.Reused || result.Task.State != "failed" {
				t.Fatal("partial window task state", cause, result)
			}
			want := [][]any{}
			for _, r := range c.Rows {
				fields := make([]any, 8)
				for i, v := range r {
					if string(v) == "null" {
						continue
					}
					if i == 0 || i == 2 || i == 5 || i == 7 {
						var n uint64
						if err := json.Unmarshal(v, &n); err != nil {
							t.Fatal(err)
						}
						fields[i] = n
					} else {
						var s string
						if err := json.Unmarshal(v, &s); err != nil {
							t.Fatal(err)
						}
						fields[i] = s
					}
				}
				want = append(want, fields)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("stored window entities differ", got, want)
			}
			var stored bytes.Buffer
			for offset := 0; ; offset += 1000 {
				rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if err := row.Verify(); err != nil {
						t.Fatal(err)
					}
					if err := json.NewEncoder(&stored).Encode(row); err != nil {
						t.Fatal(err)
					}
				}
				if len(rows) < 1000 {
					break
				}
			}
			if !bytes.Equal(wire.Bytes(), stored.Bytes()) {
				t.Fatal("window sealed stream differs from SQLite")
			}
			second, cause := e.Run(context.Background(), "windows.windows", nil, engine.RunOptions{})
			if cause == nil || second.Reused || second.Task.ID == result.Task.ID {
				t.Fatal("failed window result reused", cause, second.Reused)
			}
			for retry := 0; retry < 2; retry++ {
				failed, cause := e.Run(context.Background(), "windows.windows", map[string]string{"max-reads": "1"}, engine.RunOptions{})
				if cause == nil || failed.Reused {
					t.Fatal("failed window bound task reused", cause)
				}
			}
			if err := os.WriteFile(catalogPath, []byte("corrupt GUI layout"), 0600); err != nil {
				t.Fatal(err)
			}
			if rejected, cause := e.Run(context.Background(), "windows.windows", nil, engine.RunOptions{}); cause == nil || rejected.Reused {
				t.Fatal("corrupt runtime layout hidden by cache", cause)
			}
		})
	}
}
