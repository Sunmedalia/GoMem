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

func linuxTreeFixture(t *testing.T, scenario, arch string) testfixture.Fixture {
	t.Helper()
	f := linuxTasksFixture(t, "control")
	if scenario == "signal" {
		f = linuxTasksFixture(t, "signal")
	}
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	word := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(data[a:], v) }
	word(0xa010, 1)
	word(0xa014, 1)
	word(0xb010, 101)
	word(0xb014, 101)
	put(0xb028, 0xa000)
	for _, a := range []uint64{0x1d000, 0x1d200} {
		word(a+20, 1)
		put(a+40, 0xb000)
		put(a+88, 0xa000)
	}
	switch scenario {
	case "filter":
	case "duplicate":
		word(0xb010, 1)
		word(0xb014, 1)
		put(0xb028, 0x9000)
	case "orphan":
		put(0xa028, 0xb000)
		word(0xb014, 999)
		put(0xb028, 0x9000)
	case "bad-parent":
		put(0xb028, 0x300000)
	case "parent-field":
		typ := table.Types["task_struct"]
		f := typ.Fields["real_parent"]
		f.Offset = 0x300000
		typ.Fields["real_parent"] = f
		typ.Size = 0x300008
		table.Types["task_struct"] = typ
	case "cycle":
		put(0xa028, 0xb000)
		put(0xb028, 0xa000)
	case "smeared":
		word(0xa010, 100)
		word(0xa014, 100)
	case "kernel":
		word(0xb050, 0x200000)
	case "bad-comm":
		typ := table.Types["task_struct"]
		field := typ.Fields["comm"]
		field.Offset = 0x300000
		typ.Fields["comm"] = field
		typ.Size = 0x300010
		table.Types["task_struct"] = typ
		word(0xa050, 0x200000)
	case "name":
		copy(data[0xa018:], []byte{'x', 0xff, 'y', 0})
	case "bad-thread":
		put(0x1d260, 0x1d060)
	case "missing":
		delete(table.Types["task_struct"].Fields, "real_parent")
	}
	if arch == "x86" || arch == "pae" {
		ptr := table.Bases["pointer"]
		ptr.Size = 4
		table.Bases["pointer"] = ptr
		list := table.Types["list_head"]
		list.Size = 8
		prev := list.Fields["prev"]
		prev.Offset = 4
		list.Fields["prev"] = prev
		table.Types["list_head"] = list
		clear(data[0x1000:0x4000])
		if arch == "x86" {
			word(0x1000, 0x83)
		} else {
			put(0x1000, 0x2001)
			put(0x2000, 0x83)
		}
		for _, item := range []struct{ at, next, prev uint32 }{{0x9000, 0xa000, 0xb000}, {0xa000, 0xb000, 0x9000}, {0xb000, 0x9000, 0xa000}, {0xa060, 0x1d060, 0x1d260}, {0x1d060, 0x1d260, 0xa060}, {0x1d260, 0xa060, 0x1d060}, {0xb060, 0xb060, 0xb060}} {
			word(uint64(item.at), item.next)
			word(uint64(item.at+4), item.prev)
		}
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

func TestLinuxPsTreeReadersAndEvidence(t *testing.T) {
	for _, scenario := range []string{"control", "threads", "signal", "filter", "duplicate", "orphan", "bad-parent", "parent-field", "cycle", "smeared", "kernel", "name", "bad-comm", "bad-thread", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			e := openPsaux(t, linuxTreeFixture(t, scenario, "x64"))
			p := map[string]string{}
			if scenario == "threads" || scenario == "signal" || scenario == "bad-thread" {
				p["threads"] = "true"
			}
			if scenario == "kernel" || scenario == "threads" || scenario == "bad-comm" {
				p["decorate-comm"] = "true"
			}
			if scenario == "filter" {
				p["pid"] = "101"
			}
			var rows, processes, observations, selections []evidence.Row
			result, err := e.Run(context.Background(), "linux.pstree", p, engine.RunOptions{Emit: func(r evidence.Row) error {
				rows = append(rows, r)
				switch r.Cells["RecordType"].String() {
				case "process":
					processes = append(processes, r)
				case "observation":
					observations = append(observations, r)
				case "selection":
					selections = append(selections, r)
				}
				return nil
			}})
			bad := scenario == "bad-parent" || scenario == "parent-field" || scenario == "bad-thread" || scenario == "bad-comm" || scenario == "missing"
			if (err != nil) != bad {
				t.Fatal(result, err)
			}
			if scenario == "missing" {
				return
			}
			expected := 2
			switch scenario {
			case "threads", "signal", "bad-thread":
				expected = 4
			case "filter", "duplicate", "smeared", "bad-parent":
				expected = 1
			case "parent-field", "bad-comm":
				expected = 1
			case "cycle":
				expected = 0
			}
			if len(processes) != expected {
				t.Fatal(scenario, len(processes), expected, err)
			}
			if len(selections) != len(observations) {
				t.Fatal("selection records missing", rows)
			}
			switch scenario {
			case "control", "threads", "signal", "kernel", "name", "bad-comm", "bad-thread":
				if processes[0].Cells["TID"].String() != "1" || processes[0].ParentID != "" {
					t.Fatal(processes)
				}
				for _, r := range processes[1:] {
					if r.ParentID != processes[0].ID {
						t.Fatal("expected process/threads under init", r)
					}
				}
			}
			if scenario == "threads" {
				if processes[2].Cells["COMM"].String() != "{worker0}" || processes[3].Cells["COMM"].String() != "{worker1}" || processes[2].Cells["PPID"].String() != "101" || processes[2].Cells["HierarchyParentTID"].String() != "1" {
					t.Fatal(processes)
				}
			}
			if scenario == "duplicate" {
				if selections[0].Cells["HierarchyState"].String() != "replaced_duplicate_tid" || processes[0].Cells["COMM"].String() != "worker" || observations[0].Cells["TaskIdentity"].String() == observations[1].Cells["TaskIdentity"].String() {
					t.Fatal(rows)
				}
			}
			if scenario == "bad-comm" && (observations[0].Cells["COMM"].Kind != "missing" || processes[0].Cells["COMM"].Kind != "missing") {
				t.Fatal(rows)
			}
			if scenario == "kernel" && processes[1].Cells["COMM"].String() != "[worker]" {
				t.Fatal(processes)
			}
			if scenario == "name" && processes[0].Cells["COMM"].String() != "x" {
				t.Fatal(processes)
			}
			if scenario == "filter" && processes[0].Cells["Depth"].String() != "0" {
				t.Fatal(processes)
			}
			stored, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(stored) != len(rows) {
				t.Fatal(err, len(stored), len(rows))
			}
			for _, r := range stored {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			if !bad {
				again, err := e.Run(context.Background(), "linux.pstree", p, engine.RunOptions{})
				if err != nil || !again.Reused {
					t.Fatal(again, err)
				}
			}
		})
	}
}

func TestLinuxPsTreeBoundsCancellationAnd32Bit(t *testing.T) {
	for _, arch := range []string{"x86", "pae"} {
		t.Run(arch, func(t *testing.T) {
			f := linuxTreeFixture(t, "control", arch)
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var processes int
			r, err := e.Run(context.Background(), "linux.pstree", map[string]string{"threads": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error {
				if r.Cells["RecordType"].String() == "process" {
					processes++
				}
				return nil
			}})
			if err != nil || r.Task.State != "completed" || processes != 4 {
				t.Fatal(r, err, processes)
			}
		})
	}
	e := openPsaux(t, linuxTreeFixture(t, "control", "x64"))
	for _, p := range []map[string]string{{"max-nodes": "0"}, {"max-tasks": "0"}, {"max-work": "100000001"}, {"max-work": "0"}, {"max-work": "1"}, {"max-tasks": "1"}, {"threads": "wrong"}, {"pid": "-1"}} {
		if _, err := e.Run(context.Background(), "linux.pstree", p, engine.RunOptions{}); err == nil {
			t.Fatal(p)
		}
	}
	stop := errors.New("stop")
	if _, err := e.Run(context.Background(), "linux.pstree", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { return stop }}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var observed int
	result, err := e.Run(ctx, "linux.pstree", nil, engine.RunOptions{Fresh: true, Emit: func(r evidence.Row) error { observed++; cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || observed != 1 {
		t.Fatal(result, err, observed)
	}
	rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
	if err != nil || len(rows) != 1 || rows[0].Cells["RecordType"].String() != "observation" {
		t.Fatal(rows, err)
	}
}
