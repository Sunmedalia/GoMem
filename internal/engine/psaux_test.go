package engine_test

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func psauxFixture(t *testing.T, scenario string) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	switch scenario {
	case "no-mm":
		put(0xa038, 0)
	case "bad-mm-pointer":
		put(0xa038, 0x300000)
	case "bad-root":
		put(0xe000, 0)
	case "backwards":
		put(0xe038, 0x1bfff)
	case "empty":
		put(0xe038, 0x1c000)
	case "large":
		put(0xe038, 0x1c000+4097)
	case "partial":
		put(0xe030, 0x1fffe)
		put(0xe038, 0x20006)
		copy(data[0x1fffe:], "ab")
	case "independent-root":
		put(0xe000, 0x1d000)
		put(0x1d000, 0x1e003)
		put(0x1e000, 0x1f003)
		put(0x1f000, 0x83)
		put(0x1f008, 0x83)
		put(0xe030, 0x21c000)
		put(0xe038, 0x21c000+uint64(len("/sbin/init\x00--test\x00")))
	case "parent-tgid":
		binary.LittleEndian.PutUint32(data[0xa014:], 77)
	case "mixed-mm":
		put(0xa038, 0x300000)
	case "large-vector":
		data = append(data, make([]byte, 0x20000)...)
		clear(data[0x1c000 : 0x1c000+65537])
		put(0xe038, 0x1c000+65537)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func openPsaux(t *testing.T, f testfixture.Fixture) *engine.Engine {
	t.Helper()
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, OS: "linux", CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLinuxPsauxRawArgumentsIdentityAndIndependentPageTables(t *testing.T) {
	for _, scenario := range []string{"native", "independent-root", "parent-tgid", "no-mm"} {
		t.Run(scenario, func(t *testing.T) {
			e := openPsaux(t, psauxFixture(t, scenario))
			ctx := context.Background()
			identities := map[string]string{}
			if _, err := e.Run(ctx, "linux.pslist", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
				identities[r.Cells["PID"].String()] = r.Cells["Identity"].String()
				return nil
			}}); err != nil {
				t.Fatal(err)
			}
			var rows []evidence.Row
			r, err := e.Run(ctx, "linux.psaux", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			if err != nil || r.Task.Rows != 2 {
				t.Fatal(r, err)
			}
			for _, row := range rows {
				if row.Verify() != nil || row.Cells["ProcessIdentity"].String() != identities[row.Cells["PID"].String()] {
					t.Fatal(row)
				}
				if row.Cells["PID"].String() == "100" && scenario == "no-mm" {
					if row.Cells["ARGS"].String() != "[init]" || row.Cells["ArgsSource"].String() != "comm_without_mm" || row.Cells["ArgsRaw"].Reason != "no_user_mm" {
						t.Fatal(row)
					}
					continue
				}
				if row.Cells["ARGS"].String() != "/sbin/init --test" || string(row.Cells["ArgsRaw"].Data.([]byte)) != "/sbin/init\x00--test\x00" || row.Cells["ReadComplete"].Data != true || row.Provenance.Layer != "process:"+row.Cells["ProcessIdentity"].String() || row.Cells["ArgsSource"].String() != "user_argument_bytes" {
					t.Fatal(row)
				}
				if row.Cells["PID"].String() == "101" && scenario == "parent-tgid" && row.Cells["PPID"].String() != "77" {
					t.Fatal("getppid must use tgid", row)
				}
			}
			for _, tc := range []struct {
				pid string
				n   int64
			}{{"100", 1}, {"100,101", 2}, {"999", 0}} {
				r, err := e.Run(ctx, "linux.psaux", map[string]string{"pid": tc.pid}, engine.RunOptions{})
				if err != nil || r.Task.Rows != tc.n {
					t.Fatal(r, err)
				}
			}
		})
	}
}

func TestLinuxPsauxBoundsAndPartialReads(t *testing.T) {
	for _, tc := range []struct{ scenario, reason string }{{"bad-mm-pointer", "argument_range_unreadable"}, {"bad-root", "process_address_space_unavailable"}, {"backwards", "invalid_argument_range"}, {"empty", "empty_argument_range"}, {"large", "argument_size_limit"}, {"partial", "argument_buffer_unreadable"}} {
		t.Run(tc.scenario, func(t *testing.T) {
			e := openPsaux(t, psauxFixture(t, tc.scenario))
			var row evidence.Row
			r, err := e.Run(context.Background(), "linux.psaux", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
			if r.Task.Rows != 1 || (err == nil) != (tc.scenario == "empty") || row.Cells["ARGS"].Reason != tc.reason {
				t.Fatal(r, row, err)
			}
			if tc.scenario != "empty" && (r.Task.State != "failed" || row.Cells["ARGS"].Error == "") {
				t.Fatal(row)
			}
			if tc.scenario == "partial" && (row.Cells["CapturedBytes"].String() != "2" || string(row.Cells["ArgsRaw"].Data.([]byte)) != "ab" || row.Cells["ReadComplete"].Data != false || row.Cells["Length"].String() != "8") {
				t.Fatal("partial capture presented as full arguments", row)
			}
			if tc.scenario == "large" {
				r, err := e.Run(context.Background(), "linux.psaux", map[string]string{"pid": "100", "max-args": "4097"}, engine.RunOptions{})
				if err != nil || r.Task.Rows != 1 {
					t.Fatal("explicit larger bound did not allow capture", r, err)
				}
			}
		})
	}
	for _, value := range []string{"0", "16777217"} {
		e := openPsaux(t, psauxFixture(t, "native"))
		if _, err := e.Run(context.Background(), "linux.psaux", map[string]string{"max-args": value}, engine.RunOptions{}); err == nil {
			t.Fatal("invalid argument limit accepted")
		}
	}
}

func TestLinuxPsauxContinuesIndependentFailuresButStopsOnOutputAndCancel(t *testing.T) {
	e := openPsaux(t, psauxFixture(t, "mixed-mm"))
	var rows []evidence.Row
	r, err := e.Run(context.Background(), "linux.psaux", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
	if err == nil || r.Task.Rows != 2 || r.Task.State != "failed" || rows[0].Cells["ARGS"].Error == "" || rows[1].Cells["ARGS"].Kind != "string" {
		t.Fatal(r, rows, err)
	}
	for _, cancel := range []bool{false, true} {
		ctx, stop := context.WithCancel(context.Background())
		output := errors.New("output closed")
		r, err := e.Run(ctx, "linux.psaux", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error {
			if cancel {
				stop()
				return nil
			}
			return output
		}})
		stop()
		want := output
		if cancel {
			want = context.Canceled
		}
		if !errors.Is(err, want) || r.Task.Rows != 1 {
			t.Fatal(r, err)
		}
	}
	if r, err := e.Run(context.Background(), "linux.psaux", map[string]string{"max-nodes": "1"}, engine.RunOptions{}); err == nil || r.Task.Rows != 1 || !strings.Contains(err.Error(), "exceeded") {
		t.Fatal(r, err)
	}
}

func TestLinuxPsauxLargeVectorRetainsRawCaptureAndDisplay(t *testing.T) {
	e := openPsaux(t, psauxFixture(t, "large-vector"))
	var row evidence.Row
	r, err := e.Run(context.Background(), "linux.psaux", map[string]string{"pid": "100", "max-args": "65537"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
	if err == nil || r.Task.Rows != 1 || row.Cells["Arguments"].Reason != "argument_count_limit" || row.Cells["Arguments"].Error == "" || len(row.Cells["ArgsRaw"].Data.([]byte)) != 65537 || len(row.Cells["ARGS"].String()) != 65536 || row.Cells["ReadComplete"].Data != true {
		t.Fatal(r, err)
	}
}

func TestLinuxPsauxX86AndPAE(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		f := psauxFixture(t, "native")
		table, err := symbols.Load(f.Symbols)
		if err != nil {
			t.Fatal(err)
		}
		pointer := table.Bases["pointer"]
		pointer.Size = 4
		table.Bases["pointer"] = pointer
		list := table.Types["list_head"]
		prev := list.Fields["prev"]
		prev.Offset = 4
		list.Fields["prev"] = prev
		table.Types["list_head"] = list
		b, err := table.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(f.Symbols, b, 0600); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(f.Image)
		if err != nil {
			t.Fatal(err)
		}
		clear(data[0x1000:0x4000])
		if mode == "x86" {
			binary.LittleEndian.PutUint32(data[0x1000:], 0x83)
		} else {
			binary.LittleEndian.PutUint64(data[0x1000:], 0x2001)
			binary.LittleEndian.PutUint64(data[0x2000:], 0x83)
		}
		for _, item := range []struct{ address, next, prev uint32 }{{0x9000, 0xa000, 0xb000}, {0xa000, 0xb000, 0x9000}, {0xb000, 0x9000, 0xa000}} {
			binary.LittleEndian.PutUint32(data[item.address:], item.next)
			binary.LittleEndian.PutUint32(data[item.address+4:], item.prev)
		}
		if err = os.WriteFile(f.Image, data, 0600); err != nil {
			t.Fatal(err)
		}
		e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", Offline: true})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		r, err := e.Run(context.Background(), "linux.psaux", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
			if row.Cells["ARGS"].String() != "/sbin/init --test" {
				t.Fatal(row)
			}
			count++
			return nil
		}})
		e.Close()
		if err != nil || r.Task.Rows != 2 || count != 2 {
			t.Fatal(mode, r, err)
		}
	}
}
