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

func linuxLsofFixture(t *testing.T, scenario string) testfixture.Fixture {
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
	ptr := symbols.TypeRef{Kind: "pointer"}
	base := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: n} }
	field := func(a uint64, r symbols.TypeRef) symbols.Field { return symbols.Field{Offset: a, Type: r} }
	task := table.Types["task_struct"]
	task.Size = 152
	task.Fields["files"] = field(144, ptr)
	table.Types["task_struct"] = task
	table.Types["files_struct"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"fdt": field(0, ptr)}}
	table.Types["fdtable"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"max_fds": field(0, base("u32")), "fd": field(8, ptr)}}
	put(0xa090, 0x1e000)
	put(0x1e000, 0x1e100)
	put(0x1e100, 4)
	put(0x1e108, 0x1f000)
	put(0x1f000, 0x13000)
	put(0x1f010, 0x13100)
	inode := table.Types["inode"]
	inode.Size = 88
	inode.Fields["i_mode"] = field(32, base("u16"))
	for i, n := range []string{"i_ctime", "i_mtime", "i_atime"} {
		inode.Fields[n] = field(uint64(40+i*16), symbols.TypeRef{Kind: "struct", Name: "timespec"})
	}
	table.Types["inode"] = inode
	for _, address := range []uint64{0x18100, 0x18200} {
		binary.LittleEndian.PutUint16(data[address+32:], 0104755)
		for i := 0; i < 3; i++ {
			put(address+40+uint64(i)*16, 1700000000+uint64(i))
			put(address+48+uint64(i)*16, 123456789+uint64(i))
		}
	}
	switch scenario {
	case "namespace-old", "namespace-new":
		table.Symbols["ns_dname"] = symbols.Symbol{Address: 0x8300}
		put(0x1a000, 0x8300)
		d := table.Types["dentry"]
		d.Size = 48
		d.Fields["d_fsdata"] = field(40, ptr)
		table.Types["dentry"] = d
		table.Types["proc_ns_operations"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"name": field(0, ptr)}}
		common := symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"stashed": field(0, ptr), "ops": field(8, ptr)}}
		if scenario == "namespace-old" {
			table.Types["atomic64_t"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"counter": field(0, base("i64"))}}
			common.Fields["stashed"] = field(0, symbols.TypeRef{Kind: "struct", Name: "atomic64_t"})
		}
		table.Types["ns_common"] = common
		inode.Size = 96
		inode.Fields["i_private"] = field(88, ptr)
		table.Types["inode"] = inode
		put(0x14028, 0x1c300)
		put(0x18258, 0x1c200)
		put(0x1c208, 0x1c300)
		put(0x1c300, 0x1c400)
		copy(data[0x1c400:], "mnt\x00")
	case "partial-file":
		file := table.Types["file"]
		file.Size = 224
		table.Types["file"] = file
		put(0x1f000, 0x1fff0)
		copy(data[0x1fff0:], data[0x13000:0x13010])
	case "direct-fd":
		table.Types["files_struct"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"max_fds": field(0, base("u32")), "fd": field(8, ptr)}}
		put(0x1e000, 4)
		put(0x1e008, 0x1f000)
	case "cached-inode":
		file := table.Types["file"]
		file.Size = 24
		file.Fields["f_inode"] = field(16, ptr)
		table.Types["file"] = file
		put(0x13010, 0x18100)
	case "new-clock", "split-clock":
		for i, n := range []string{"i_ctime", "i_mtime", "i_atime"} {
			delete(inode.Fields, n)
			offset := uint64(40 + i*16)
			if scenario == "new-clock" {
				inode.Fields["__"+n] = field(offset, symbols.TypeRef{Kind: "struct", Name: "timespec"})
			} else {
				inode.Fields[n+"_sec"] = field(offset, base("i64"))
				inode.Fields[n+"_nsec"] = field(offset+8, base("u32"))
			}
		}
		table.Types["inode"] = inode
	case "thread":
		copy(data[0x1d000:0x1d098], data[0xa000:0xa098])
		binary.LittleEndian.PutUint32(data[0x1d010:], 200)
		put(0x1d058, 0xa000)
		put(0xa060, 0x1d060)
		put(0xa068, 0x1d060)
		put(0x1d060, 0xa060)
		put(0x1d068, 0xa060)
	case "closed-zero":
		put(0x1f000, 0)
	case "disconnected":
		put(0x14000, 0x14000)
	case "bad-root":
		put(0x1e000, 0)
	case "bad-file":
		put(0x1f000, 0x300000)
	case "bad-count":
		put(0x1e100, 500001)
	case "prefix-slots":
		put(0x1e108, 0x1ffe0)
		put(0x1ffe0, 0x13000)
		put(0x1ffe8, 0x13100)
		data = data[:0x1ffec]
	case "bad-slots":
		put(0x1e108, 0x1fff0)
		put(0x1fff0, 0x13000)
		put(0x1fff8, 0x13100)
	case "bad-nsec":
		put(0x18230, 1000000000)
	case "bad-mode":
		binary.LittleEndian.PutUint16(data[0x18220:], 0600)
	case "null-inode":
		put(0x14018, 0)
	case "negative-time":
		v := int64(-1)
		put(0x18228, uint64(v))
	case "zero-time":
		put(0x18228, 0)
		put(0x18230, 0)
	case "invalid-clock":
		delete(inode.Fields, "i_ctime")
		table.Types["inode"] = inode
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

func TestLinuxLsofLayoutsTimesAndTaskIdentity(t *testing.T) {
	for _, scenario := range []string{"normal", "direct-fd", "cached-inode", "new-clock", "split-clock", "thread", "bad-mode", "zero-time", "negative-time", "closed-zero", "namespace-old", "namespace-new"} {
		t.Run(scenario, func(t *testing.T) {
			e := openLinuxELF(t, linuxLsofFixture(t, scenario), true)
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.lsof", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			want := 2
			if scenario == "closed-zero" {
				want = 1
			}
			if scenario == "thread" {
				want = 4
			}
			if err != nil || result.Task.Rows != int64(want) || len(rows) != want {
				t.Fatal(result, err)
			}
			first := rows[0].Cells
			if scenario == "closed-zero" {
				if first["FD"].String() != "2" {
					t.Fatal(first)
				}
				return
			}
			if first["FD"].String() != "0" || rows[1].Cells["FD"].String() != "2" || first["Device"].String() != "8:1" || first["FileExtent"].Data.(map[string]any)["readable"] != true {
				t.Fatal(rows)
			}
			if scenario == "bad-mode" {
				if first["Type"].Reason != "unknown_inode_type" || first["Mode"].String() != "?rw-------" {
					t.Fatal(first)
				}
			} else if first["Type"].String() != "REG" || first["Mode"].String() != "-rwsr-xr-x" {
				t.Fatal(first)
			}
			changed := "2023-11-14T22:13:20.123456789Z"
			if scenario == "zero-time" {
				changed = "1970-01-01T00:00:00Z"
			}
			if scenario == "negative-time" {
				changed = "1969-12-31T23:59:59.123456789Z"
			}
			if first["Changed"].String() != changed {
				t.Fatal(first["Changed"])
			}
			if scenario == "cached-inode" {
				if first["InodeSource"].String() != "file.f_inode" || first["Inode"].String() != "124" {
					t.Fatal(first)
				}
			}
			if scenario == "thread" {
				if rows[2].Cells["TID"].String() != "200" || rows[2].Cells["ProcessIdentity"].String() != first["ProcessIdentity"].String() || rows[2].Cells["TaskIdentity"].String() == first["TaskIdentity"].String() {
					t.Fatal(rows)
				}
			}
			path := "/memfd:payload"
			if scenario == "namespace-old" || scenario == "namespace-new" {
				path = "mnt:[123]"
			}
			if first["PathScope"].String() != "dynamic_name" || first["Path"].String() != path {
				t.Fatal(first)
			}
		})
	}
}

func TestLinuxLsofFailuresRetainOtherDescriptorsAndExplicitSlotGaps(t *testing.T) {
	for _, scenario := range []string{"bad-root", "bad-count", "bad-file", "bad-slots", "bad-nsec", "invalid-clock", "partial-file", "prefix-slots"} {
		t.Run(scenario, func(t *testing.T) {
			e := openLinuxELF(t, linuxLsofFixture(t, scenario), true)
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.lsof", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			if err == nil || result.Task.State != "failed" || len(rows) == 0 {
				t.Fatal(result, err)
			}
			if scenario == "bad-root" || scenario == "bad-count" {
				if len(rows) != 1 || rows[0].Cells["RecordType"].String() != "diagnostic" {
					t.Fatal(rows)
				}
			}
			if scenario == "partial-file" {
				if len(rows) != 2 || rows[0].Cells["RecordType"].String() != "file_partial" || rows[0].Cells["Path"].Kind != "string" {
					t.Fatal(rows)
				}
			}
			if scenario == "bad-file" {
				if len(rows) != 2 || rows[0].Cells["RecordType"].String() != "file_partial" || rows[0].Cells["Error"].Error == "" || rows[1].Cells["Path"].Kind != "string" {
					t.Fatal(rows)
				}
			}
			if scenario == "prefix-slots" {
				if len(rows) != 2 || rows[0].Cells["FD"].String() != "0" || rows[1].Cells["SkippedSlots"].String() != "3" {
					t.Fatal(rows)
				}
			}
			if scenario == "bad-slots" {
				if len(rows) != 3 || rows[2].Cells["RecordType"].String() != "diagnostic" || rows[2].Cells["SkippedSlots"].String() != "2" {
					t.Fatal(rows)
				}
			}
			if scenario == "bad-nsec" {
				if rows[0].Cells["Changed"].Reason != "invalid_inode_timestamp" || rows[0].Cells["ChangedRaw"].Kind != "structure" {
					t.Fatal(rows)
				}
			}
		})
	}
}

func TestLinuxLsofFilesOnlyFilterBoundsAndCancellation(t *testing.T) {
	e := openLinuxELF(t, linuxLsofFixture(t, "normal"), true)
	// files-only chooses the normal filesystem walk. The inode type is still REG
	// and the dynamic callback is deliberately bypassed.
	var row evidence.Row
	r, err := e.Run(context.Background(), "linux.lsof", map[string]string{"pid": "100", "files-only": "true"}, engine.RunOptions{Emit: func(v evidence.Row) error {
		if row.Cells == nil {
			row = v
		}
		return nil
	}})
	if err != nil || r.Task.Rows != 2 || row.Cells["PathScope"].String() != "process_root" || row.Cells["Path"].String() != "/memfd:payload (deleted)" {
		t.Fatal(r, row, err)
	}
	for _, params := range []map[string]string{{"max-fds": "0"}, {"max-fds": "500001"}, {"max-slots": "0"}, {"max-slots": "100000001"}, {"max-tasks": "0"}} {
		if _, err = e.Run(context.Background(), "linux.lsof", params, engine.RunOptions{}); err == nil {
			t.Fatal(params)
		}
	}
	for _, params := range []map[string]string{{"max-fds": "3"}, {"max-slots": "3"}} {
		r, err = e.Run(context.Background(), "linux.lsof", params, engine.RunOptions{})
		if err == nil || r.Task.State != "failed" {
			t.Fatal(r, err)
		}
	}
	r, err = e.Run(context.Background(), "linux.lsof", map[string]string{"pid": "999"}, engine.RunOptions{})
	if err != nil || r.Task.Rows != 0 {
		t.Fatal(r, err)
	}
	sentinel := errors.New("stop output")
	r, err = e.Run(context.Background(), "linux.lsof", nil, engine.RunOptions{Emit: func(evidence.Row) error { return sentinel }})
	if !errors.Is(err, sentinel) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err = e.Run(ctx, "linux.lsof", nil, engine.RunOptions{Emit: func(evidence.Row) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
}

func TestLinuxLsofFilesOnlyDisconnectedLabelsAreScoped(t *testing.T) {
	e := openLinuxELF(t, linuxLsofFixture(t, "disconnected"), true)
	var first evidence.Row
	result, err := e.Run(context.Background(), "linux.lsof", map[string]string{"pid": "100", "files-only": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if first.Cells == nil {
			first = row
		}
		return nil
	}})
	if err != nil || result.Task.Rows != 2 || first.Cells["PathScope"].String() != "disconnected_dentry" || first.Cells["Path"].String() != "/ (deleted)" || first.Cells["PathInProcessRoot"].Data != false {
		t.Fatal(result, first, err)
	}
}

func TestLinuxLsof32BitPointerTables(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxLsofFixture(t, "normal")
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
			for _, v := range []struct{ at, next, prev uint32 }{{0x9000, 0xa000, 0xb000}, {0xa000, 0xb000, 0x9000}, {0xb000, 0x9000, 0xa000}, {0xa060, 0xa060, 0xa060}, {0xb060, 0xb060, 0xb060}} {
				binary.LittleEndian.PutUint32(data[v.at:], v.next)
				binary.LittleEndian.PutUint32(data[v.at+4:], v.prev)
			}
			clear(data[0x1f000:0x1f020])
			binary.LittleEndian.PutUint32(data[0x1f000:], 0x13000)
			binary.LittleEndian.PutUint32(data[0x1f008:], 0x13100)
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
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			r, err := e.Run(context.Background(), "linux.lsof", nil, engine.RunOptions{})
			if err != nil || r.Task.Rows != 2 {
				t.Fatal(r, err)
			}
		})
	}
}
