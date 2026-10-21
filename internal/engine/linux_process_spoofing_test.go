package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxSpoofingFixture(t *testing.T, scenario string) testfixture.Fixture {
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
	str := func(a uint64, s string, n int) { clear(data[a : a+uint64(n)]); copy(data[a:], s) }
	mm := table.Types["mm_struct"]
	mm.Size = 72
	mm.Fields["exe_file"] = symbols.Field{Offset: 64, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["mm_struct"] = mm
	table.Bases["i32"] = symbols.Type{Kind: "int", Size: 4, Endian: "little", Signed: true}
	table.Types["atomic_t"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"counter": {Type: symbols.TypeRef{Kind: "base", Name: "i32"}}}}
	inode := table.Types["inode"]
	inode.Size = 40
	inode.Fields["i_count"] = symbols.Field{Offset: 32, Type: symbols.TypeRef{Kind: "struct", Name: "atomic_t"}}
	table.Types["inode"] = inode
	put(0xe040, 0x13000)
	put(0x14020, 0)
	str(0x19000, "init", 32)
	binary.LittleEndian.PutUint32(data[0x14008:], 4)
	put(0x18208, 1)
	put(0x18220, 1)
	switch scenario {
	case "command":
		str(0x1c000, "evil\x00", 32)
		put(0xe038, 0x1c005)
	case "comm":
		str(0xa018, "evil", 16)
	case "deleted":
		put(0x18208, 0)
	case "invalid-inode":
		put(0x18208, 0)
		binary.LittleEndian.PutUint32(data[0x18220:], 0xffffffff)
	case "dynamic-simple", "dynamic-alias", "dynamic-unsupported", "dynamic-socket", "dynamic-invalid-inode", "dynamic-unreadable":
		put(0x14020, 0x1a000)
		put(0x1a000, 0x8100)
		switch scenario {
		case "dynamic-alias":
			table.Symbols["alias"] = symbols.Symbol{Address: 0x8100}
		case "dynamic-unsupported":
			delete(table.Symbols, "simple_dname")
			table.Symbols["custom_dname"] = symbols.Symbol{Address: 0x8100}
		case "dynamic-socket":
			delete(table.Symbols, "simple_dname")
			table.Symbols["sockfs_dname"] = symbols.Symbol{Address: 0x8100}
		case "dynamic-invalid-inode":
			binary.LittleEndian.PutUint32(data[0x18220:], 0xffffffff)
		case "dynamic-unreadable":
			put(0x1a000, 0x300000)
		}
	case "no-mm":
		put(0xa038, 0)
	case "bad-mm":
		put(0xa038, 0x300000)
	case "null-exe":
		put(0xe040, 0)
	case "bad-exe":
		put(0xe040, 0x300000)
	case "empty-arguments":
		put(0xe038, 0x1c000)
	case "reversed-arguments":
		put(0xe038, 0x1bfff)
	case "partial":
		put(0xe030, 0x1fffe)
		put(0xe038, 0x20006)
		copy(data[0x1fffe:], "in")
	case "capped":
		data = append(data, make([]byte, 0x30000)...)
		put(0xe030, 0x30000)
		put(0xe038, 0x30000+131073)
		copy(data[0x30000:], "init\x00")
	case "replacement":
		str(0x1c000, "in\ufffdit\x00", 32)
		put(0xe038, 0x1c009)
	case "qstr-nul":
		str(0x19000, "i\x00it", 32)
	case "qstr-invalid":
		str(0x19000, "\xffnit", 32)
	case "qstr-empty":
		str(0x19000, "", 32)
		binary.LittleEndian.PutUint32(data[0x14008:], 0)
	case "path-cycle":
		put(0x14000, 0x14200)
		put(0x14200, 0x14000)
	case "path-disconnected":
		put(0x14000, 0x14000)
	case "bad-inode":
		put(0x14018, 0x300000)
	case "bad-parent":
		put(0xa028, 0x300000)
	case "parent-tgid":
		put(0xa028, 0xb000)
		binary.LittleEndian.PutUint32(data[0xb014:], 77)
	case "missing-exe-field":
		delete(mm.Fields, "exe_file")
		table.Types["mm_struct"] = mm
	case "pid-fault":
		task := table.Types["task_struct"]
		delete(task.Fields, "pid")
		table.Types["task_struct"] = task
	case "independent":
		copy(data[0xe100:0xe148], data[0xe000:0xe048])
		put(0xb038, 0xe100)
		put(0xe100, 0x1d000)
		put(0x1d000, 0x1e003)
		put(0x1e000, 0x1f003)
		put(0x1f000, 0x83)
		put(0x1f008, 0x83)
		put(0xe130, 0x21c000)
		put(0xe138, 0x21c000+7)
		str(0x1c000, "worker\x00", 32)
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
func TestLinuxProcessSpoofingNativeReaders(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-process-spoofing-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct{ Dynamic map[string]string }
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Dynamic) != 6 {
		t.Fatal(err)
	}
	for _, scenario := range []string{"control", "command", "comm", "deleted", "invalid-inode", "dynamic-simple", "dynamic-alias", "dynamic-unsupported", "dynamic-socket", "dynamic-invalid-inode", "dynamic-unreadable", "no-mm", "bad-mm", "null-exe", "bad-exe", "empty-arguments", "reversed-arguments", "partial", "capped", "replacement", "qstr-nul", "qstr-invalid", "qstr-empty", "path-cycle", "path-disconnected", "bad-inode", "bad-parent", "parent-tgid", "missing-exe-field"} {
		t.Run(scenario, func(t *testing.T) {
			e := openPsaux(t, linuxSpoofingFixture(t, scenario))
			ctx := context.Background()
			var rows []evidence.Row
			result, err := e.Run(ctx, "linux.process_spoofing", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(r evidence.Row) error {
				if err := r.Verify(); err != nil {
					return err
				}
				rows = append(rows, r)
				return nil
			}})
			if err != nil || result.Task.State != "completed" || len(rows) != 2 {
				t.Fatal(result, len(rows), err)
			}
			c := rows[0].Cells
			wantCmd, wantComm, wantError := false, false, false
			switch scenario {
			case "command", "replacement", "partial":
				wantCmd = true
			case "comm":
				wantComm = true
			case "qstr-nul", "qstr-invalid", "qstr-empty", "dynamic-alias", "dynamic-unsupported", "dynamic-socket", "dynamic-invalid-inode", "dynamic-unreadable":
				wantCmd, wantComm = true, true
			}
			switch scenario {
			case "dynamic-unreadable", "bad-mm", "bad-exe", "partial", "path-cycle", "bad-inode", "bad-parent", "missing-exe-field":
				wantError = true
			}
			if c["Cmdline_Spoofed"].Data != wantCmd || c["Comm_Spoofed"].Data != wantComm || (c["Error"].Kind == "structure") != wantError {
				t.Fatal(scenario, c)
			}
			if c["Exe_Deleted"].Data != (scenario == "deleted" || scenario == "dynamic-simple") {
				t.Fatal("deleted state", c)
			}
			if want, ok := oracle.Dynamic[scenario]; ok && c["Exe_Path"].String() != want {
				t.Fatal("dynamic path differs from pinned implementation", scenario, c)
			}

			if scenario == "deleted" && c["Exe_Path"].String() != " /init (deleted)" {
				t.Fatal(c)
			}
			if scenario == "partial" {
				d := c["CommandLineEvidence"].Data.(map[string]evidence.Value)
				if d["CapturedBytes"].String() != "2" || d["ReadComplete"].Data != false || c["Cmdline_Basename"].String() != "in" {
					t.Fatal(c)
				}
			}
			if scenario == "capped" {
				d := c["CommandLineEvidence"].Data.(map[string]evidence.Value)
				if d["RequestedBytes"].String() != "131072" || d["Capped"].Data != true || d["ReadComplete"].Data != true {
					t.Fatal(c)
				}
			}
			if scenario == "parent-tgid" && c["PPID"].String() != "77" {
				t.Fatal(c)
			}
			if scenario == "bad-parent" && c["PPID"].String() != "0" {
				t.Fatal(c)
			}
			// All nested byte captures and errors must retain their sealed identities.
			saved, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 10})
			if err != nil || len(saved) != 2 {
				t.Fatal(saved, err)
			}
			for _, r := range saved {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			again, err := e.Run(ctx, "linux.process_spoofing", map[string]string{"pid": "100"}, engine.RunOptions{})
			if err != nil || !again.Reused {
				t.Fatal(again, err)
			}
		})
	}
}
func TestLinuxProcessSpoofingIndependentLayersAndFailures(t *testing.T) {
	e := openPsaux(t, linuxSpoofingFixture(t, "independent"))
	ctx := context.Background()
	var rows []evidence.Row
	_, err := e.Run(ctx, "linux.process_spoofing", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
	if err != nil || len(rows) != 3 {
		t.Fatal(rows, err)
	}
	if rows[0].Cells["Cmdline_Basename"].String() != "worker" || rows[1].Cells["Cmdline_Basename"].String() != "worker" || rows[0].Cells["ProcessIdentity"].String() == rows[1].Cells["ProcessIdentity"].String() {
		t.Fatal(rows)
	}
	for _, p := range []map[string]string{{"pid": "bad"}, {"max-nodes": "0"}, {"max-nodes": "1"}} {
		if _, err = e.Run(ctx, "linux.process_spoofing", p, engine.RunOptions{}); err == nil {
			t.Fatal(p)
		}
	}
	stop := errors.New("output stopped")
	if _, err = e.Run(ctx, "linux.process_spoofing", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { return stop }}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = e.Run(ctx, "linux.process_spoofing", nil, engine.RunOptions{Fresh: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	e = openPsaux(t, linuxSpoofingFixture(t, "pid-fault"))
	if _, err = e.Run(context.Background(), "linux.process_spoofing", nil, engine.RunOptions{}); err == nil {
		t.Fatal("PID fault became clean")
	}
}

func TestLinuxProcessSpoofingX86AndPAEPointers(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxSpoofingFixture(t, "deleted")
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
			raw, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.Symbols, raw, 0600); err != nil {
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
			for _, item := range []struct{ at, next, prev uint32 }{{0x9000, 0xa000, 0xb000}, {0xa000, 0xb000, 0x9000}, {0xb000, 0x9000, 0xa000}} {
				binary.LittleEndian.PutUint32(data[item.at:], item.next)
				binary.LittleEndian.PutUint32(data[item.at+4:], item.prev)
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.process_spoofing", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if err != nil || result.Task.State != "completed" || len(rows) != 2 {
				t.Fatal(result, rows, err)
			}
			c := rows[0].Cells
			if c["Exe_Path"].String() != " /init (deleted)" || c["Cmdline_Basename"].String() != "init" || c["Cmdline_Spoofed"].Data != false || c["Comm_Spoofed"].Data != false || c["Exe_Deleted"].Data != true || c["Error"].Kind != "missing" {
				t.Fatal(c)
			}
		})
	}
}
