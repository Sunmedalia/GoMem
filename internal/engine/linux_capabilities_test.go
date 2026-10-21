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

func linuxCapabilityFixture(t *testing.T, scenario string) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
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
	word := symbols.TypeRef{Kind: "base", Name: "u32"}
	task := table.Types["task_struct"]
	task.Fields["real_cred"] = symbols.Field{Offset: 144, Type: symbols.TypeRef{Kind: "pointer"}}
	task.Size = 152
	table.Types["task_struct"] = task
	table.Types["kernel_cap_t"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"cap": {Type: symbols.TypeRef{Kind: "array", Count: 2, Subtype: &word}}}}
	cred := table.Types["cred"]
	cred.Size = 56
	for i, name := range []string{"cap_inheritable", "cap_permitted", "cap_effective", "cap_bset", "cap_ambient"} {
		cred.Fields[name] = symbols.Field{Offset: uint64(16 + i*8), Type: symbols.TypeRef{Kind: "struct", Name: "kernel_cap_t"}}
	}
	table.Types["cred"] = cred
	table.Symbols["cap_last_cap"] = symbols.Symbol{Address: 0x1d800, Type: &word}
	binary.LittleEndian.PutUint32(data[0x1d800:], 35)
	for i, address := range []uint64{0xa000, 0xb000} {
		credential := uint64(0x1d000 + i*0x100)
		put(address+144, credential)
		for j, value := range []uint64{0, ^uint64(0), 1<<12 | 1<<21, 1 << 40, 1 << 7} {
			put(credential+16+uint64(j*8), value)
		}
	}
	switch scenario {
	case "no-ambient":
		delete(cred.Fields, "cap_ambient")
	case "modern":
		cap := table.Types["kernel_cap_t"]
		delete(cap.Fields, "cap")
		cap.Fields["val"] = symbols.Field{Type: symbols.TypeRef{Kind: "base", Name: "u64"}}
		table.Types["kernel_cap_t"] = cap
		uid := cred.Fields["euid"]
		uid.Type = symbols.TypeRef{Kind: "struct", Name: "kuid_t"}
		cred.Fields["euid"] = uid
		table.Types["kuid_t"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"val": {Type: word}}}
	case "fallback":
		delete(table.Symbols, "cap_last_cap")
	case "future":
		binary.LittleEndian.PutUint32(data[0x1d800:], 45)
		put(0x1d020, 1<<45|1<<40)
	case "missing-member":
		delete(cred.Fields, "cap_effective")
	case "null-real-cred":
		put(0xa090, 0)
	case "bad-real-cred":
		put(0xa090, 0x300000)
	case "bad-cred":
		put(0xa048, 0x300000)
	case "bad-parent":
		put(0xa028, 0x300000)
	case "parent-tgid":
		binary.LittleEndian.PutUint32(data[0x9014:], 81)
	case "tid-not-tgid":
		binary.LittleEndian.PutUint32(data[0xa014:], 900)
	case "partial":
		put(0xa090, 0x1ffea)
		copy(data[0x1fffa:], []byte{1, 2, 3, 4, 5, 6})
	case "bad-last":
		table.Symbols["cap_last_cap"] = symbols.Symbol{Address: 0x300000, Type: &word}
	case "malformed-comm":
		copy(data[0xa018:], []byte{'a', 0xff, 'b', 0})
	case "x86", "pae":
		pointer := table.Bases["pointer"]
		pointer.Size = 4
		table.Bases["pointer"] = pointer
		list := table.Types["list_head"]
		prev := list.Fields["prev"]
		prev.Offset = 4
		list.Fields["prev"] = prev
		table.Types["list_head"] = list
		clear(data[0x1000:0x4000])
		if scenario == "x86" {
			binary.LittleEndian.PutUint32(data[0x1000:], 0x83)
		} else {
			put(0x1000, 0x2001)
			put(0x2000, 0x83)
		}
		for _, item := range []struct{ at, next, prev uint32 }{{0x9000, 0xa000, 0xb000}, {0xa000, 0xb000, 0x9000}, {0xb000, 0x9000, 0xa000}} {
			binary.LittleEndian.PutUint32(data[item.at:], item.next)
			binary.LittleEndian.PutUint32(data[item.at+4:], item.prev)
		}
	}
	table.Types["cred"] = cred
	raw, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLinuxCapabilityNativeReaders(t *testing.T) {
	for _, scenario := range []string{"control", "no-ambient", "modern", "fallback", "future", "missing-member", "null-real-cred", "bad-real-cred", "bad-cred", "bad-parent", "parent-tgid", "tid-not-tgid", "partial", "bad-last", "malformed-comm", "x86", "pae"} {
		t.Run(scenario, func(t *testing.T) {
			f := linuxCapabilityFixture(t, scenario)
			arch := "x64"
			if scenario == "x86" || scenario == "pae" {
				arch = scenario
			}
			ctx := context.Background()
			e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			result, err := e.Run(ctx, "linux.capabilities", map[string]string{"pids": "100"}, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			bad := scenario == "missing-member" || scenario == "null-real-cred" || scenario == "bad-real-cred" || scenario == "bad-cred" || scenario == "bad-parent" || scenario == "partial" || scenario == "bad-last"
			if bad != (err != nil) {
				t.Fatal(result, err)
			}
			if scenario == "bad-last" {
				if len(rows) != 0 {
					t.Fatal(rows)
				}
				return
			}
			if len(rows) != 2 {
				t.Fatal(len(rows), err)
			}
			c := rows[0].Cells
			if c["Tid"].String() != "100" || c["EUID"].String() != "0" && scenario != "bad-cred" {
				t.Fatal(c)
			}
			if !bad && scenario != "future" && (c["cap_inheritable"].String() != "" || c["cap_permitted"].String() != "all" || c["cap_effective"].String() != "net_admin, sys_admin") {
				t.Fatal(c)
			}
			if !bad && scenario != "fallback" && scenario != "future" && c["cap_bounding"].String() != "" {
				t.Fatal(c)
			}
			if scenario == "no-ambient" && (c["cap_ambient"].Kind != "missing" || c["cap_ambient"].Reason != "not_available" || c["cap_ambient"].Error != "") {
				t.Fatal(c)
			}
			if scenario == "parent-tgid" && c["PPid"].String() != "81" || scenario == "tid-not-tgid" && c["Pid"].String() != "900" || scenario == "malformed-comm" && c["Name"].String() != "a" {
				t.Fatal(c)
			}
			if scenario == "future" && (c["cap_effective"].String() != "checkpoint_restore" || c["CapLast"].String() != "45") {
				t.Fatal(c)
			}
			if scenario == "bad-cred" && (c["EUID"].Kind != "missing" || c["cap_effective"].Kind != "string") {
				t.Fatal("cred and real_cred confused", c)
			}
			if scenario == "bad-parent" && c["PPid"].String() != "0" {
				t.Fatal(c)
			}
			if bad && (c["Error"].Kind != "structure" || result.Task.State != "failed") {
				t.Fatal(c)
			}
			saved, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 10})
			if err != nil || len(saved) != 2 {
				t.Fatal(saved, err)
			}
			for _, row := range saved {
				if err = row.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			if !bad {
				again, err := e.Run(ctx, "linux.capabilities", map[string]string{"pids": "100"}, engine.RunOptions{})
				if err != nil || !again.Reused {
					t.Fatal(again, err)
				}
			}
		})
	}
}

func TestLinuxCapabilityFilteringAndStops(t *testing.T) {
	e := openPsaux(t, linuxCapabilityFixture(t, "control"))
	ctx := context.Background()
	for _, tc := range []struct {
		pids  string
		count int
	}{{"", 3}, {"100,101", 3}, {"101", 2}, {"900", 1}, {"100,100", 2}} {
		var rows []evidence.Row
		_, err := e.Run(ctx, "linux.capabilities", map[string]string{"pids": tc.pids}, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
		if err != nil || len(rows) != tc.count {
			t.Fatal(tc, len(rows), err)
		}
	}
	for _, params := range []map[string]string{{"pids": "bad"}, {"pids": "-1"}, {"pids": "1,"}, {"max-nodes": "0"}, {"max-nodes": "1"}} {
		if _, err := e.Run(ctx, "linux.capabilities", params, engine.RunOptions{}); err == nil {
			t.Fatal(params)
		}
	}
	stop := errors.New("output stopped")
	if _, err := e.Run(ctx, "linux.capabilities", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { return stop }}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.Run(ctx, "linux.capabilities", nil, engine.RunOptions{Fresh: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
