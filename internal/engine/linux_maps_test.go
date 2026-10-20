package engine_test

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxMapsFixture(t *testing.T, layout, fault string) testfixture.Fixture {
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
	field := func(offset uint64, ref symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: ref}
	}
	if layout != "list" {
		mm := table.Types["mm_struct"]
		delete(mm.Fields, "mmap")
		values := make([]uint64, 4)
		for i := range values {
			values[i] = binary.LittleEndian.Uint64(data[0xe010+i*8:])
		}
		for i, name := range []string{"start_brk", "brk", "start_stack", "context"} {
			v := mm.Fields[name]
			v.Offset += 16
			mm.Fields[name] = v
			put(0xe020+uint64(i)*8, values[i])
		}
		mm.Fields["mm_mt"] = field(8, symbols.TypeRef{Kind: "struct", Name: "maple_tree"})
		table.Types["mm_struct"] = mm
		table.Types["maple_tree"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"ma_root": field(0, ptr), "ma_flags": field(8, symbols.TypeRef{Kind: "base", Name: "u32"})}}
		slots := symbols.TypeRef{Kind: "array", Count: 4, Subtype: &ptr}
		table.Types["maple_range_test"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"slot": field(32, slots)}}
		table.Types["maple_node"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"parent": field(0, ptr), "slot": field(8, slots), "mr64": field(0, symbols.TypeRef{Kind: "struct", Name: "maple_range_test"}), "ma64": field(0, symbols.TypeRef{Kind: "struct", Name: "maple_range_test"})}}
		height, node, start := uint64(1), uint64(0x1c000), uint64(32)
		entry := node | 10
		if layout == "dense" {
			entry = node | 2
			start = 8
		}
		put(node, 0xe009)
		if layout == "range" || layout == "arange" {
			height = 2
			entry = node | 18
			if layout == "arange" {
				entry = node | 26
			}
			put(node+32, 0x1d00a)
			put(0x1d000, node|6)
			node = 0x1d000
		}
		for i, a := range []uint64{0x10000, 0x11000, 0x12000, 0x12100} {
			put(node+start+uint64(i)*8, a)
		}
		if layout == "direct" {
			entry = 0x10000
			height = 0
		}
		put(0xe008, entry)
		put(0xe010, height<<2)
		switch fault {
		case "parent":
			put(0x1c000, 0xdead001)
		case "duplicate":
			put(node+start+8, 0x10000)
		case "depth":
			put(0xe010, 3<<2)
		case "type":
			put(0xe008, 0x1c022)
		case "cycle":
			put(0xe008, 0x1c012)
			put(0x1c020, 0x1c012)
			put(0xe010, 2<<2)
		case "empty-height":
			put(0xe008, 0)
		}
	}
	switch fault {
	case "list-cycle":
		put(0x12110, 0x10000)
	case "list-previous":
		put(0x11018, 0)
	case "owner":
		put(0x10020, 0xdead000)
	case "overlap":
		put(0x11000, 0x400000)
		put(0x11008, 0x401000)
	case "file-unreadable":
		put(0x13100, 0x300000)
	case "dentry-cycle":
		put(0x14200, 0x14100)
	case "callback":
		put(0x1a000, 0x8200)
	case "legacy-file-root":
		table.Types["file"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"f_dentry": field(0, ptr), "f_vfsmnt": field(8, ptr)}}
		table.Types["fs_struct"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"root": field(0, ptr), "rootmnt": field(8, ptr)}}
	case "hash-len":
		qstr := table.Types["qstr"]
		delete(qstr.Fields, "len")
		qstr.Fields["hash_len"] = field(0, symbols.TypeRef{Kind: "base", Name: "u64"})
		table.Types["qstr"] = qstr
		for _, a := range []uint64{0x14000, 0x14100, 0x14200, 0x17000} {
			n := binary.LittleEndian.Uint32(data[a+8:])
			put(a+8, uint64(n)<<32)
		}
	case "invalid-utf8":
		data[0x19000] = 0xff
	case "global-root":
		put(0x16000, 0x14300)
		put(0x14300, 0x17000)
	case "namespace-root":
		put(0x16000, 0x14200)
	case "embedded-mount", "old-mount":
		put(0x13108, 0x15100)
		put(0x14100, 0x17300)
		put(0x17300, 0x17300)
		put(0x15100, 0x17300)
		if fault == "old-mount" {
			put(0x15108, 0x15000)
			put(0x15110, 0x14200)
		} else {
			vf := table.Types["vfsmount"]
			delete(vf.Fields, "mnt_parent")
			delete(vf.Fields, "mnt_mountpoint")
			table.Types["vfsmount"] = vf
			table.Types["mount"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{"mnt_parent": field(0, ptr), "mnt_mountpoint": field(8, ptr), "mnt": field(16, symbols.TypeRef{Kind: "struct", Name: "vfsmount"})}}
			put(0x14ff0, 0x14ff0)
			put(0x14ff8, 0x17000)
			put(0x150f0, 0x14ff0)
			put(0x150f8, 0x14200)
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

func openLinuxMaps(t *testing.T, f testfixture.Fixture) *engine.Engine {
	t.Helper()
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLinuxListAndAllMapleLayouts(t *testing.T) {
	for _, layout := range []string{"list", "direct", "dense", "leaf", "range", "arange"} {
		t.Run(layout, func(t *testing.T) {
			e := openLinuxMaps(t, linuxMapsFixture(t, layout, ""))
			var processID string
			if _, err := e.Run(context.Background(), "linux.pslist", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { processID = row.Cells["Identity"].String(); return nil }}); err != nil {
				t.Fatal(err)
			}
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.maps", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			want := int64(4)
			if layout == "direct" {
				want = 1
			}
			if err != nil || result.Task.Rows != want {
				t.Fatal(result, err)
			}
			for _, row := range rows {
				if row.Verify() != nil || row.Cells["ProcessIdentity"].String() != processID {
					t.Fatal("invalid sealed row")
				}
			}
			if rows[0].Cells["Path"].String() != "/memfd:payload (deleted)" || rows[0].Cells["Protection"].String() != "r-x" || rows[0].Cells["Deleted"].String() != "true" {
				t.Fatal(rows[0])
			}
			if want == 4 {
				if rows[1].Cells["Path"].String() != "[heap]" || rows[2].Cells["Path"].String() != "/lib/libfoo.so" || rows[3].Cells["FileOffsetPastEOF"].String() != "true" {
					t.Fatal(rows)
				}
				for _, tc := range []struct {
					p map[string]string
					n int64
				}{{map[string]string{"pid": "100", "address": "0x400000,0x700000"}, 2}, {map[string]string{"pid": "100", "address": "0x401000"}, 1}, {map[string]string{"pid": "100", "include-past-eof": "false"}, 3}, {map[string]string{"pid": "4"}, 0}} {
					r, err := e.Run(context.Background(), "linux.maps", tc.p, engine.RunOptions{})
					if err != nil || r.Task.Rows != tc.n {
						t.Fatal(tc, r, err)
					}
				}
			}
		})
	}
}

func TestLinuxVMAFailuresAndPathScopes(t *testing.T) {
	for _, fault := range []string{"list-cycle", "list-previous", "owner", "overlap", "parent", "duplicate", "depth", "type", "cycle", "empty-height", "file-unreadable", "dentry-cycle", "callback", "invalid-utf8", "global-root", "namespace-root", "old-mount", "embedded-mount", "legacy-file-root", "hash-len"} {
		t.Run(fault, func(t *testing.T) {
			layout := "list"
			switch fault {
			case "parent", "duplicate", "depth", "type", "cycle", "empty-height":
				layout = "leaf"
			}
			e := openLinuxMaps(t, linuxMapsFixture(t, layout, fault))
			var rows []evidence.Row
			r, err := e.Run(context.Background(), "linux.maps", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			switch fault {
			case "file-unreadable", "dentry-cycle":
				if err != nil || len(rows) != 4 || rows[2].Cells["Path"].Kind != "missing" || rows[2].Cells["Path"].Error == "" {
					t.Fatal(rows, r, err)
				}
			case "callback":
				if err != nil || len(rows) != 4 || rows[0].Cells["Path"].Kind != "missing" {
					t.Fatal(rows, r, err)
				}
			case "invalid-utf8":
				if err != nil || len(rows) != 4 {
					t.Fatal(r, err)
				}
				raw := rows[0].Cells["PathRaw"].Data.([]byte)
				if raw[1] != 0xff {
					t.Fatal("raw pathname bytes lost", raw)
				}
			case "global-root":
				if err != nil || rows[2].Cells["PathScope"].String() != "global_root" || rows[2].Cells["Path"].String() != "/lib/libfoo.so" {
					t.Fatal(rows, r, err)
				}
			case "namespace-root":
				if err != nil || rows[2].Cells["PathScope"].String() != "process_root" || rows[2].Cells["Path"].String() != "/libfoo.so" {
					t.Fatal(rows, r, err)
				}
			case "old-mount", "embedded-mount", "legacy-file-root", "hash-len":
				if err != nil || rows[2].Cells["Path"].String() != "/lib/libfoo.so" {
					t.Fatal(rows, r, err)
				}
			default:
				if err == nil || r.Task.State != "failed" {
					t.Fatal("corrupt VMA/tree became clean output", r, err)
				}
			}
		})
	}
	e := openLinuxMaps(t, linuxMapsFixture(t, "list", ""))
	for _, p := range []map[string]string{{"max-regions": "1"}, {"address": "0x400000,"}, {"max-regions": "0"}, {"include-past-eof": "maybe"}, {"dump": "true"}} {
		if _, err := e.Run(context.Background(), "linux.maps", p, engine.RunOptions{}); err == nil {
			t.Fatal("invalid parameter or traversal limit accepted", p)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := e.Run(ctx, "linux.maps", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { cancel(); return nil }})
	if err == nil || result.Task.State != "canceled" || result.Task.Rows != 1 {
		t.Fatal("canceled VMA task lost its partial evidence", result, err)
	}
}
