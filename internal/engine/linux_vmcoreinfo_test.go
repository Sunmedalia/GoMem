package engine_test

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func vmcoreImage(t *testing.T, scenario string) string {
	t.Helper()
	data := make([]byte, (1<<20)+4096)
	note := func(at int, desc []byte) {
		binary.LittleEndian.PutUint32(data[at:], 11)
		binary.LittleEndian.PutUint32(data[at+4:], uint32(len(desc)))
		copy(data[at+12:], "VMCOREINFO\x00\x00")
		copy(data[at+24:], desc)
	}
	// The signature crosses a scanner chunk boundary, while the descriptor is separate.
	first := (1 << 20) - 16
	desc := []byte("OSRELEASE=old\r\nPAGESIZE=4096\nSYMBOL(test)=ffffffffffffffff\nNUMBER(huge)=340282366920938463463374607431768211456\nOSRELEASE=new\n")
	note(first, desc)
	note(128, []byte("OSRELEASE=other\nKERNELOFFSET=-0x10\n"))
	switch scenario {
	case "empty":
		clear(data)
	case "header":
		binary.LittleEndian.PutUint32(data[first:], 10)
	case "nonprintable":
		note(first, []byte("OSRELEASE=test\x00"))
	case "bad-number":
		note(first, []byte("OSRELEASE=test\nPAGESIZE=09\n"))
	case "bad-line":
		note(first, []byte("OSRELEASE=test\nBAD\n"))
	case "tag":
		note(first, []byte("OTHER=test\n"))
	case "huge":
		binary.LittleEndian.PutUint32(data[first+4:], 1048577)
	case "truncated":
		clear(data[first:])
		at := len(data) - 32
		note(at, []byte("OSRELEASE=test\nPAGESIZE=4096\n"))
		binary.LittleEndian.PutUint32(data[at+4:], 100)
	case "underflow":
		copy(data[:12], "VMCOREINFO\x00\x00")
	}
	path := filepath.Join(t.TempDir(), "notes.raw")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func openVMCore(t *testing.T, image string) *engine.Engine {
	t.Helper()
	e, err := engine.Open(context.Background(), engine.Config{Image: image, CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func TestVMCoreInfoStreamingStore(t *testing.T) {
	for _, scenario := range []string{"valid", "empty", "header", "nonprintable", "bad-number", "bad-line", "tag", "huge", "truncated", "underflow"} {
		t.Run(scenario, func(t *testing.T) {
			e := openVMCore(t, vmcoreImage(t, scenario))
			ctx := context.Background()
			var observed []evidence.Row
			result, err := e.Run(ctx, "linux.vmcoreinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error { observed = append(observed, r); return nil }})
			failed := scenario == "bad-number" || scenario == "bad-line" || scenario == "huge" || scenario == "truncated" || scenario == "underflow"
			if failed != (err != nil) {
				t.Fatal(scenario, result, err)
			}
			if failed && result.Task.State != "failed" {
				t.Fatal(result)
			}
			rows, queryErr := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if queryErr != nil || len(rows) != len(observed) {
				t.Fatal(queryErr, len(rows), len(observed))
			}
			entries := 0
			for _, r := range rows {
				if err := r.Verify(); err != nil {
					t.Fatal(err)
				}
				if r.Cells["RecordType"].String() != "entry" {
					continue
				}
				entries++
				if r.Cells["Key"].String() == "NUMBER(huge)" && r.Cells["TypedValue"].String() != "340282366920938463463374607431768211456" {
					t.Fatal(r)
				}
				if r.Cells["Key"].String() == "OSRELEASE" && r.Cells["Value"].String() == "old" {
					t.Fatal("duplicate did not use final value")
				}
			}
			want := 2
			if scenario == "valid" || scenario == "underflow" {
				want = 6
			}
			if scenario == "empty" {
				want = 0
			}
			if entries != want {
				t.Fatal(entries, want, err)
			}
			if !failed {
				again, err := e.Run(ctx, "linux.vmcoreinfo", nil, engine.RunOptions{})
				if err != nil || !again.Reused {
					t.Fatal(again, err)
				}
			}
		})
	}
}
func TestVMCoreInfoBoundsAndCancellation(t *testing.T) {
	for _, p := range []map[string]string{{"max-candidates": "1"}, {"max-rows": "1"}, {"max-descriptor": "1"}, {"max-descriptor": "16777217"}, {"max-candidates": "0"}, {"max-rows": "1000001"}} {
		e := openVMCore(t, vmcoreImage(t, "valid"))
		_, err := e.Run(context.Background(), "linux.vmcoreinfo", p, engine.RunOptions{})
		if err == nil {
			t.Fatal("ignored bound", p)
		}
	}
	for _, cancelled := range []bool{false, true} {
		e := openVMCore(t, vmcoreImage(t, "valid"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sentinel := errors.New("output stopped")
		count := 0
		result, err := e.Run(ctx, "linux.vmcoreinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
			count++
			if cancelled {
				cancel()
				return nil
			}
			return sentinel
		}})
		want := sentinel
		if cancelled {
			want = context.Canceled
		}
		if !errors.Is(err, want) || count != 1 {
			t.Fatal(result, err, count)
		}
		if cancelled {
			rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(rows) != 1 {
				t.Fatal(err, len(rows))
			}
		}
	}
}
