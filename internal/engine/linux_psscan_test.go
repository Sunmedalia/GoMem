package engine_test

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxScanFixture(t *testing.T, scenario string) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	// A physically contiguous candidate that is independent of the active list.
	copy(data[0x1e003:0x1e093], data[0xa000:0xa090])
	binary.LittleEndian.PutUint32(data[0x1e013:], 222)
	binary.LittleEndian.PutUint32(data[0x1e017:], 222)
	copy(data[0x1e01b:0x1e02b], []byte("residual\x00"))
	put(0x1e02b, 0xa000)
	put(0x1e033, 3000000000)
	binary.LittleEndian.PutUint32(data[0x1e08b:], 32)
	switch scenario {
	case "bad-state":
		binary.LittleEndian.PutUint32(data[0x1e08b:], 7)
	case "bad-pid":
		binary.LittleEndian.PutUint32(data[0x1e013:], 65535)
	case "bad-parent":
		put(0x1e02b, 0x300000)
	case "no-symbols":
		delete(table.Symbols, "fair_sched_class")
	case "alias":
		table.Symbols["alias_sched_class"] = table.Symbols["fair_sched_class"]
	case "canonical":
		table.Symbols["fair_sched_class"] = symbols.Symbol{Address: 0xffff81008200}
		for _, a := range []uint64{0xa080, 0xb080, 0x1e083} {
			put(a, 0xffffffff81008200)
		}
	case "truncated":
		copy(data[len(data)-8:], data[0x1e083:0x1e08b])
	case "invalid-symbol":
		table.Symbols["fair_sched_class"] = symbols.Symbol{Address: 0xffff000000008200}
	}
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLinuxPhysicalTaskScanHeuristicsAndProvenance(t *testing.T) {
	for _, scenario := range []string{"normal", "bad-state", "bad-pid", "alias", "canonical"} {
		t.Run(scenario, func(t *testing.T) {
			f := linuxScanFixture(t, scenario)
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			r, err := e.Run(context.Background(), "linux.psscan", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			want := 4
			if scenario == "bad-state" || scenario == "bad-pid" {
				want = 3
			}
			if err != nil || r.Task.State != "completed" || len(rows) != want {
				t.Fatal(r, rows, err)
			}
			for _, row := range rows[:len(rows)-1] {
				if row.Cells["RecordType"].String() != "task" || row.Cells["OffsetSpace"].String() != "physical" || row.Cells["PhysicalOffset"].String() != row.Cells["Offset"].String() || row.Provenance.Layer != row.Cells["PhysicalLayer"].String() || row.Cells["TaskIdentity"].String() == "" {
					t.Fatal(row)
				}
			}
			last := rows[len(rows)-1]
			if last.Cells["RecordType"].String() != "scan_summary" || last.Cells["Scan"].Data.(map[string]any)["complete"] != true {
				t.Fatal(last)
			}
			if want == 4 {
				hidden := rows[2]
				if hidden.Cells["PID"].String() != "222" || hidden.Cells["PPID"].String() != "100" || hidden.Cells["ExitState"].String() != "EXIT_ZOMBIE" {
					t.Fatal(hidden)
				}
				if scenario == "alias" && len(hidden.Cells["SchedClassNames"].Data.([]string)) != 2 {
					t.Fatal(hidden)
				}
			}
			if scenario == "bad-pid" {
				result, err := e.Run(context.Background(), "linux.psscan", map[string]string{"max-pid": "65535"}, engine.RunOptions{})
				if err != nil || result.Task.Rows != 4 {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestLinuxTaskScanFailuresAndCancellation(t *testing.T) {
	for _, scenario := range []string{"bad-parent", "no-symbols", "invalid-symbol", "truncated", "max-candidates", "max-results"} {
		t.Run(scenario, func(t *testing.T) {
			f := linuxScanFixture(t, scenario)
			e := openLinuxELF(t, f, true)
			p := map[string]string{}
			if scenario == "max-candidates" || scenario == "max-results" {
				p[scenario] = "1"
			}
			var rows []evidence.Row
			r, err := e.Run(context.Background(), "linux.psscan", p, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			if err == nil || r.Task.State != "failed" {
				t.Fatal(r, err)
			}
			if scenario == "bad-parent" {
				if rows[2].Cells["PPID"].Kind != "missing" || rows[2].Cells["PPID"].Error == "" {
					t.Fatal(rows)
				}
			}
			if scenario == "truncated" {
				found := false
				for _, row := range rows {
					found = found || row.Cells["RecordType"].String() == "diagnostic"
				}
				if !found {
					t.Fatal(rows)
				}
			}
			if scenario == "max-results" || scenario == "max-candidates" {
				if rows[len(rows)-1].Cells["Scan"].Data.(map[string]any)["complete"] != false {
					t.Fatal(rows)
				}
			}
		})
	}
	e := openLinuxELF(t, linuxScanFixture(t, "normal"), true)
	for _, params := range []map[string]string{{"max-candidates": "0"}, {"max-results": "1000001"}, {"max-pid": "0"}, {"max-pid": "4294967296"}} {
		if _, err := e.Run(context.Background(), "linux.psscan", params, engine.RunOptions{}); err == nil {
			t.Fatal(params)
		}
	}
	sentinel := errors.New("output stop")
	r, err := e.Run(context.Background(), "linux.psscan", nil, engine.RunOptions{Emit: func(evidence.Row) error { return sentinel }})
	if !errors.Is(err, sentinel) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err = e.Run(ctx, "linux.psscan", nil, engine.RunOptions{Emit: func(evidence.Row) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
}

func TestLinuxTaskScan32BitX86AndPAE(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxScanFixture(t, "normal")
			table, err := symbols.Load(f.Symbols)
			if err != nil {
				t.Fatal(err)
			}
			ptr := table.Bases["pointer"]
			ptr.Size = 4
			table.Bases["pointer"] = ptr
			encoded, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
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
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			r, err := e.Run(context.Background(), "linux.psscan", nil, engine.RunOptions{})
			if err != nil || r.Task.Rows != 4 {
				t.Fatal(r, err)
			}
		})
	}
}
