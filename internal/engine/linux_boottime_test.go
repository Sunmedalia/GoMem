package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxBootFixture(t *testing.T, ids []*uint64, scenario string) testfixture.Fixture {
	t.Helper()
	f := linuxTasksFixture(t, "tk_core")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	ref := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: n} }
	ptr := symbols.TypeRef{Kind: "pointer"}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	task := table.Types["task_struct"]
	task.Size = 152
	task.Fields["nsproxy"] = symbols.Field{Offset: 144, Type: ptr}
	table.Types["task_struct"] = task
	table.Types["nsproxy"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"time_ns": {Type: ptr}}}
	table.Types["ns_common"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"inum": {Type: u32}}}
	table.Types["timens_offsets"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"boottime": {Type: ref("timespec")}}}
	ns := symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"ns": {Type: ref("ns_common")}, "offsets": {Offset: 8, Type: ref("timens_offsets")}}}
	table.Types["time_namespace"] = ns
	for i, a := range []uint64{0xa000, 0xb000} {
		proxy, namespace := uint64(0x1e000+i*0x100), uint64(0x1e400+i*0x100)
		put(a+144, proxy)
		if ids[i] == nil {
			put(proxy, 0)
			continue
		}
		put(proxy, namespace)
		binary.LittleEndian.PutUint32(data[namespace:], uint32(*ids[i]))
		put(namespace+8, uint64(i))
		put(namespace+16, uint64(i))
	}
	switch scenario {
	case "legacy":
		delete(task.Fields, "nsproxy")
		table.Types["task_struct"] = task
	case "legacy-nsproxy":
		proxy := table.Types["nsproxy"]
		delete(proxy.Fields, "time_ns")
		table.Types["nsproxy"] = proxy
	case "no-offsets":
		delete(ns.Fields, "offsets")
		table.Types["time_namespace"] = ns
	case "null-proxy":
		put(0xa090, 0)
	case "bad-proxy":
		put(0xa090, 0x300000)
	case "bad-namespace":
		put(0x1e000, 0x300000)
	case "bad-offset":
		put(0x1e410, 1000000000)
	case "duplicate-bad-offset":
		put(0x1e510, 1000000000)
	case "negative-offset":
		put(0x1e408, ^uint64(0))
		put(0x1e410, 500000000)
	case "unparsable":
		put(0x1e408, 1700000001)
		put(0x1e410, 0)
	case "no-id":
		delete(table.Types["ns_common"].Fields, "inum")
	}
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

func TestLinuxBoottimePinnedNamespaceGroups(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-boottime-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Groups []struct {
			Name string
			IDs  []*uint64
			Rows []struct {
				ID      *uint64
				Display string
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Groups) != 6 {
		t.Fatal(err)
	}
	for _, tc := range oracle.Groups {
		t.Run(tc.Name, func(t *testing.T) {
			e := openPsaux(t, linuxBootFixture(t, tc.IDs, "control"))
			ctx := context.Background()
			var rows []evidence.Row
			result, err := e.Run(ctx, "linux.boottime", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if err != nil || result.Task.State != "completed" || len(rows) != len(tc.Rows)+1 {
				t.Fatal(result, rows, err)
			}
			for i, want := range tc.Rows {
				c := rows[i].Cells
				actual, err := time.Parse(time.RFC3339Nano, c["Boot Time"].String())
				if err != nil {
					t.Fatal(err)
				}
				expected, err := time.Parse(time.RFC3339Nano, want.Display)
				if err != nil || !actual.Equal(expected) {
					t.Fatal(c, want, err)
				}
				label := "None"
				if want.ID != nil {
					label = fmt.Sprint(*want.ID)
					if c["NamespaceID"].String() != label {
						t.Fatal(c, want)
					}
				}
				if (want.ID == nil || *want.ID == 0) && c["TIME NS"].Reason != "not_available" {
					t.Fatal(c)
				}
				if c["RecordType"].String() != "time_namespace" || c["ClockEvidence"].Kind != "structure" || c["NamespaceEvidence"].Kind != "structure" || c["TimelineType"].String() != "CREATED" || c["TimelineDescription"].String() != "System boot time for time namespace "+label {
					t.Fatal(c)
				}
			}
			saved, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(saved) != len(rows) {
				t.Fatal(saved, err)
			}
			for _, row := range saved {
				if err = row.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			again, err := e.Run(ctx, "linux.boottime", nil, engine.RunOptions{})
			if err != nil || !again.Reused {
				t.Fatal(again, err)
			}
		})
	}
}

func TestLinuxBoottimeNamespaceFaultsAndClockLayouts(t *testing.T) {
	id1, id2 := uint64(42), uint64(43)
	for _, scenario := range []string{"legacy", "legacy-nsproxy", "no-offsets", "null-proxy", "bad-proxy", "bad-namespace", "bad-offset", "duplicate-bad-offset", "negative-offset", "unparsable", "no-id"} {
		t.Run(scenario, func(t *testing.T) {
			ids := []*uint64{&id1, &id2}
			if scenario == "duplicate-bad-offset" {
				ids[1] = &id1
			}
			e := openPsaux(t, linuxBootFixture(t, ids, scenario))
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.boottime", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			bad := scenario == "null-proxy" || scenario == "bad-proxy" || scenario == "bad-namespace" || scenario == "bad-offset" || scenario == "no-id"
			if bad != (err != nil) {
				t.Fatal(result, err)
			}
			if len(rows) < 2 {
				t.Fatal(rows)
			}
			if bad && (rows[0].Cells["RecordType"].String() != "diagnostic" || rows[0].Cells["Error"].Error == "") {
				t.Fatal(rows)
			}
			if scenario == "duplicate-bad-offset" && len(rows) != 2 {
				t.Fatal("duplicate offset unexpectedly read", rows)
			}
			if (scenario == "legacy" || scenario == "legacy-nsproxy") && len(rows) != 2 {
				t.Fatal(rows)
			}
			if scenario == "negative-offset" && rows[0].Cells["BootTimeExact"].String() != "2023-11-14T22:13:20.623456789Z" {
				t.Fatal(rows[0])
			}
			if scenario == "unparsable" && (rows[0].Cells["Boot Time"].Reason != "unparsable_boot_time" || rows[0].Cells["BootEpochNS"].String() != "-876543211") {
				t.Fatal(rows[0])
			}
			for _, r := range rows {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, scenario := range []string{"native", "sleep-seconds", "timekeeper", "tk_core", "tv64", "bad-clock", "null-clock"} {
		t.Run(scenario, func(t *testing.T) {
			e := openPsaux(t, linuxTasksFixture(t, scenario))
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.boottime", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			bad := scenario == "bad-clock" || scenario == "null-clock"
			if bad != (err != nil) {
				t.Fatal(result, err)
			}
			if !bad && (len(rows) != 2 || rows[0].Cells["Boot Time"].Kind != "string") {
				t.Fatal(rows)
			}
		})
	}
	e := openPsaux(t, linuxTasksFixture(t, "native"))
	for _, p := range []map[string]string{{"max-nodes": "0"}, {"max-nodes": "1"}, {"pids": "100"}} {
		if _, err := e.Run(context.Background(), "linux.boottime", p, engine.RunOptions{}); err == nil {
			t.Fatal(p)
		}
	}
	stop := errors.New("output stopped")
	if _, err := e.Run(context.Background(), "linux.boottime", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { return stop }}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Run(ctx, "linux.boottime", nil, engine.RunOptions{Fresh: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestLinuxBoottimeX86AndPAE(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxCapabilityFixture(t, mode)
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, OS: "linux", Arch: mode, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.boottime", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if err != nil || result.Task.State != "completed" || len(rows) != 2 || rows[0].Cells["BootTimeExact"].String() != "2023-11-14T22:13:20.123456789Z" {
				t.Fatal(result, rows, err)
			}
		})
	}
}
