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

func linuxTasksFixture(t *testing.T, scenario string) testfixture.Fixture {
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
	ptr := symbols.TypeRef{Kind: "pointer"}
	ref := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	base := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: name} }
	field := func(offset uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: typ}
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	list := func(head uint64, nodes ...uint64) {
		put(head, head)
		put(head+8, head)
		if len(nodes) == 0 {
			return
		}
		put(head, nodes[0])
		put(head+8, nodes[len(nodes)-1])
		for i, a := range nodes {
			next, prev := head, head
			if i > 0 {
				prev = nodes[i-1]
			}
			if i+1 < len(nodes) {
				next = nodes[i+1]
			}
			put(a, next)
			put(a+8, prev)
		}
	}
	for i, a := range []uint64{0x1d000, 0x1d200} {
		copy(data[a:a+128], data[0xa000:0xa080])
		binary.LittleEndian.PutUint32(data[a+16:], uint32(200+i))
		binary.LittleEndian.PutUint32(data[a+20:], 100)
		clear(data[a+24 : a+40])
		copy(data[a+24:], []string{"worker0", "worker1"}[i])
		put(a+48, uint64(i+3)*1000000000)
		put(a+112, uint64(i+3)*1000000000+1234567)
	}
	list(0xa060, 0x1d060, 0x1d260)
	if scenario == "signal" {
		task := table.Types["task_struct"]
		task.Size = 144
		task.Fields["signal"] = field(128, ptr)
		task.Fields["thread_node"] = task.Fields["thread_group"]
		delete(task.Fields, "thread_group")
		table.Types["task_struct"] = task
		table.Types["signal_struct"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"thread_head": field(0, ref("list_head"))}}
		for _, a := range []uint64{0xa000, 0x1d000, 0x1d200} {
			put(a+128, 0x1e000)
		}
		put(0xb080, 0x1e100)
		list(0x1e000, 0xa060, 0x1d060, 0x1d260)
		list(0x1e100, 0xb060)
	}
	if scenario == "kuid" {
		table.Types["kuid_t"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"val": field(0, base("u32"))}}
		cred := table.Types["cred"]
		for name, value := range cred.Fields {
			value.Type = ref("kuid_t")
			cred.Fields[name] = value
		}
		table.Types["cred"] = cred
	}
	switch scenario {
	case "kernel":
		binary.LittleEndian.PutUint32(data[0xb050:], 0x00200000)
	case "null-cred":
		put(0xa048, 0)
	case "partial-cred":
		put(0xa048, 0x1fff8)
		binary.LittleEndian.PutUint32(data[0x1fff8:], 55)
		binary.LittleEndian.PutUint32(data[0x1fffc:], 66)
	case "null-clock":
		delete(table.Symbols, "wall_to_monotonic")
		delete(table.Symbols, "total_sleep_time")
	case "sleep-seconds":
		value := table.Symbols["total_sleep_time"]
		typ := base("u64")
		value.Type = &typ
		table.Symbols["total_sleep_time"] = value
		put(0x1b820, 2)
	case "timekeeper":
		table.Types["timekeeper"] = symbols.Type{Kind: "struct", Size: 48, Fields: map[string]symbols.Field{"wall_to_monotonic": field(0, ref("timespec")), "total_sleep_time": field(32, ref("timespec"))}}
		typ := ref("timekeeper")
		table.Symbols["timekeeper"] = symbols.Symbol{Address: 0x1b800, Type: &typ}
	case "tk_core", "tv64", "bad-clock":
		ktime := base("i64")
		if scenario == "tv64" {
			ktime = symbols.TypeRef{Kind: "union", Name: "ktime_t"}
			table.Types["ktime_t"] = symbols.Type{Kind: "union", Size: 8, Fields: map[string]symbols.Field{"tv64": field(0, base("i64"))}}
		}
		table.Types["timekeeper"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"offs_real": field(0, ktime), "offs_boot": field(8, ktime)}}
		table.Types["tk_core"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"timekeeper": field(0, ref("timekeeper"))}}
		typ := ref("tk_core")
		address := uint64(0x1b900)
		if scenario == "bad-clock" {
			address = 0x300000
		}
		table.Symbols["tk_core"] = symbols.Symbol{Address: address, Type: &typ}
		put(0x1b900, 1700000000123456789)
	case "start-boottime":
		task := table.Types["task_struct"]
		task.Fields["start_boottime"] = field(120, base("u64"))
		table.Types["task_struct"] = task
		put(0xa078, 3000000999)
	case "timespec-counter", "invalid-counter":
		task := table.Types["task_struct"]
		task.Fields["real_start_time"] = field(112, ref("timespec"))
		table.Types["task_struct"] = task
		put(0xa070, 1)
		put(0xa078, 2345678)
		if scenario == "invalid-counter" {
			put(0xa078, 1000000000)
		}
	case "negative-counter":
		task := table.Types["task_struct"]
		task.Fields["real_start_time"] = field(112, base("i64"))
		table.Types["task_struct"] = task
		put(0xa070, ^uint64(0))
	case "bad-tgid":
		binary.LittleEndian.PutUint32(data[0x1d014:], 101)
	case "bad-owner":
		put(0x1d058, 0xb000)
	case "cycle":
		put(0x1d260, 0x1d060)
	case "bad-flags":
		task := table.Types["task_struct"]
		delete(task.Fields, "flags")
		table.Types["task_struct"] = task
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

func TestLinuxTaskFieldsClockModelsAndCredentialLayouts(t *testing.T) {
	for _, scenario := range []string{"native", "kuid", "null-cred", "partial-cred", "null-clock", "sleep-seconds", "timekeeper", "tk_core", "tv64", "bad-clock", "start-boottime", "timespec-counter", "invalid-counter", "negative-counter"} {
		t.Run(scenario, func(t *testing.T) {
			e := openPsaux(t, linuxTasksFixture(t, scenario))
			var row evidence.Row
			r, err := e.Run(context.Background(), "linux.pslist", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
			if err != nil || r.Task.Rows != 1 || row.Verify() != nil {
				t.Fatal(r, err)
			}
			c := row.Cells
			if c["PID"].String() != "100" || c["TID"].String() != "100" || c["StartTimeNS"].String() != "1000000000" || c["TaskIdentity"].String() == c["Identity"].String() {
				t.Fatal(c)
			}
			if scenario == "null-cred" {
				if c["UID"].Reason != "credential_not_set" || c["UID"].Error != "" {
					t.Fatal(c)
				}
			} else if scenario == "partial-cred" {
				if c["UID"].String() != "55" || c["GID"].String() != "66" || c["EUID"].Error == "" {
					t.Fatal(c)
				}
			} else if c["UID"].String() != "1000" || c["GID"].String() != "100" || c["EUID"].String() != "0" || c["EGID"].String() != "0" {
				t.Fatal(c)
			}
			switch scenario {
			case "null-clock", "bad-clock":
				if c["Created"].Reason != "boot_clock_unavailable" || c["Created"].Error == "" {
					t.Fatal(c)
				}
			case "invalid-counter", "negative-counter":
				if c["CreationCounterNS"].Kind != "missing" || c["CreationCounterNS"].Error == "" || c["Created"].Kind != "missing" {
					t.Fatal(c)
				}
			case "start-boottime":
				if c["CreationCounterField"].String() != "start_boottime" || c["CreationCounterNS"].String() != "3000000999" || !strings.HasSuffix(c["Created"].String(), "23.000000999Z") {
					t.Fatal(c)
				}
			case "timespec-counter":
				if c["CreationCounterNS"].String() != "1002345678" {
					t.Fatal(c)
				}
			case "sleep-seconds":
				if c["BootTime"].String() != "2023-11-14T22:13:18.123456789Z" {
					t.Fatal(c)
				}
			default:
				if c["Created"].String() != "2023-11-14T22:13:21.001234567Z" || c["CreatedExact"].String() != "2023-11-14T22:13:21.124691356Z" || c["BootTime"].String() != "2023-11-14T22:13:20.123456789Z" {
					t.Fatal(c)
				}
			}
		})
	}
}

func TestLinuxThreadListsFiltersDecorationsAndIdentities(t *testing.T) {
	for _, scenario := range []string{"native", "signal", "kernel"} {
		t.Run(scenario, func(t *testing.T) {
			e := openPsaux(t, linuxTasksFixture(t, scenario))
			ctx := context.Background()
			var rows []evidence.Row
			r, err := e.Run(ctx, "linux.pslist", map[string]string{"threads": "true", "decorate-comm": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if err != nil || r.Task.Rows != 4 {
				t.Fatal(r, err)
			}
			leader := rows[0]
			seen := map[string]bool{}
			for _, row := range rows {
				c := row.Cells
				if row.Verify() != nil || seen[c["TaskIdentity"].String()] {
					t.Fatal(row)
				}
				seen[c["TaskIdentity"].String()] = true
				if c["RecordType"].String() == "thread" {
					if c["PID"].String() != "100" || c["Identity"].String() != leader.Cells["Identity"].String() || c["ProcessOffset"].String() != leader.Cells["Offset"].String() || !strings.HasPrefix(c["Name"].String(), "{worker") || c["IsUserThread"].Data != true {
						t.Fatal(row)
					}
				}
				if scenario == "kernel" && c["PID"].String() == "101" && (c["Name"].String() != "[worker]" || c["IsKernelThread"].Data != true) {
					t.Fatal(row)
				}
			}
			for _, tc := range []struct {
				pid string
				n   int64
			}{{"100", 3}, {"101", 1}, {"200", 0}, {"100,101", 4}} {
				r, err := e.Run(ctx, "linux.pslist", map[string]string{"threads": "true", "pid": tc.pid}, engine.RunOptions{})
				if err != nil || r.Task.Rows != tc.n {
					t.Fatal(tc, r, err)
				}
			}
		})
	}
}

func TestLinuxThreadFailuresRetainDiagnosticsAndContinueGroups(t *testing.T) {
	for _, scenario := range []string{"bad-tgid", "bad-owner", "cycle", "bad-flags"} {
		t.Run(scenario, func(t *testing.T) {
			e := openPsaux(t, linuxTasksFixture(t, scenario))
			var rows []evidence.Row
			r, err := e.Run(context.Background(), "linux.pslist", map[string]string{"threads": "true", "decorate-comm": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			if err == nil || r.Task.State != "failed" || rows[len(rows)-1].Cells["TID"].String() != "101" {
				t.Fatal(r, rows, err)
			}
			if scenario != "bad-flags" {
				diagnostics := 0
				for _, row := range rows {
					if row.Cells["RecordType"].String() == "diagnostic" {
						diagnostics++
						if row.Cells["Error"].Error == "" {
							t.Fatal(row)
						}
					}
				}
				if diagnostics != 1 {
					t.Fatal(rows)
				}
			}
		})
	}
	for _, limit := range []string{"0", "1000001"} {
		e := openPsaux(t, linuxTasksFixture(t, "native"))
		if _, err := e.Run(context.Background(), "linux.pslist", map[string]string{"max-tasks": limit}, engine.RunOptions{}); err == nil {
			t.Fatal("invalid total limit")
		}
	}
	e := openPsaux(t, linuxTasksFixture(t, "native"))
	if r, err := e.Run(context.Background(), "linux.pslist", map[string]string{"threads": "true", "max-tasks": "2"}, engine.RunOptions{}); err == nil || r.Task.State != "failed" {
		t.Fatal(r, err)
	}
	for _, cancel := range []bool{false, true} {
		ctx, stop := context.WithCancel(context.Background())
		output := errors.New("output closed")
		r, err := e.Run(ctx, "linux.pslist", map[string]string{"threads": "true"}, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error {
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
}
