package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxFilesFixture(t *testing.T, scenario string) testfixture.Fixture {
	t.Helper()
	f := linuxLsofFixture(t, "normal")
	s, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, make([]byte, 128<<10)...)
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	ptr := symbols.TypeRef{Kind: "pointer"}
	base := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: n} }
	st := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: n} }
	field := func(o uint64, r symbols.TypeRef) symbols.Field { return symbols.Field{Offset: o, Type: r} }
	task := s.Types["task_struct"]
	task.Size = 160
	task.Fields["nsproxy"] = field(152, ptr)
	s.Types["task_struct"] = task
	put(0xa098, 0x21100)
	put(0xb098, 0x21100)
	put(0x21100, 0x21000)
	s.Types["nsproxy"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"mnt_ns": field(0, ptr)}}
	s.Types["mnt_namespace"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"list": field(0, st("list_head")), "proc_inum": field(16, base("u32"))}}
	put(0x21010, 42)
	s.Types["vfsmount"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"mnt_root": field(0, ptr), "mnt_parent": field(8, ptr), "mnt_mountpoint": field(16, ptr), "mnt_sb": field(24, ptr), "mnt_list": field(32, st("list_head")), "mnt_id": field(48, base("u32")), "mnt_ns": field(56, ptr)}}
	list := func(head uint64, nodes ...uint64) {
		if len(nodes) == 0 {
			put(head, head)
			put(head+8, head)
			return
		}
		put(head, nodes[0])
		put(head+8, nodes[len(nodes)-1])
		for i, a := range nodes {
			next, prev := head, head
			if i+1 < len(nodes) {
				next = nodes[i+1]
			}
			if i > 0 {
				prev = nodes[i-1]
			}
			put(a, next)
			put(a+8, prev)
		}
	}
	put(0x16000, 0x23000)
	put(0x16008, 0x22000)
	put(0x22000, 0x23000)
	put(0x22008, 0x22000)
	put(0x22010, 0x23000)
	put(0x22018, 0x24000)
	put(0x22030, 1)
	put(0x22038, 0x21000)
	list(0x21000, 0x22020)
	sb := s.Types["super_block"]
	sb.Size = 16
	sb.Fields["s_root"] = field(8, ptr)
	s.Types["super_block"] = sb
	put(0x24000, 8<<20|1)
	put(0x24008, 0x23000)
	d := s.Types["dentry"]
	d.Size = 80
	d.Fields["d_subdirs"] = field(48, st("list_head"))
	d.Fields["d_child"] = field(64, st("list_head"))
	s.Types["dentry"] = d
	inode := s.Types["inode"]
	inode.Size = 112
	inode.Fields["i_count"] = field(88, st("atomic_t"))
	inode.Fields["i_mapping"] = field(96, ptr)
	inode.Fields["i_link"] = field(104, ptr)
	s.Types["inode"] = inode
	s.Types["atomic_t"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"counter": field(0, base("i64"))}}
	s.Types["address_space"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"nrpages": field(0, base("u64")), "page_tree": field(8, st("radix_tree_root"))}}
	s.Types["radix_tree_root"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"height": field(0, base("u32")), "rnode": field(8, ptr)}}
	s.Types["radix_tree_node"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{"height": field(0, base("u32")), "slots": field(8, symbols.TypeRef{Kind: "array", Count: 4, Subtype: &ptr})}}
	s.Types["page"] = symbols.Type{Kind: "struct", Size: 56, Fields: map[string]symbols.Field{"flags": field(0, base("u64")), "mapping": field(8, ptr), "index": field(16, base("u64"))}}
	s.Enums = map[string]symbols.Enumeration{"pageflags": {Base: "u32", Size: 4, Constants: map[string]json.Number{"PG_uptodate": "3", "PG_lru": "5"}}}
	s.Symbols["mem_section"] = symbols.Symbol{Address: 0x19000}
	s.Symbols["max_pfn"] = symbols.Symbol{Address: 0x19008}
	put(0x19008, 64)
	put(0x1000+((testVmemmap>>39)&511)*8, 0x2003)
	for i, mode := range []uint64{0040755, 0100644, 0040755, 0120777, 0100600} {
		a := uint64(0x25000 + i*256)
		put(a, 100+uint64(i))
		put(a+8, 1)
		put(a+16, 0x24000)
		put(a+24, 5)
		put(a+32, mode)
		put(a+88, 1)
		put(a+96, uint64(0x26000+i*32))
		for j := 0; j < 3; j++ {
			put(a+40+uint64(j)*16, 1700000000+uint64(j))
			put(a+48+uint64(j)*16, 123456789)
		}
	}
	put(0x25368, 0x29000)
	copy(data[0x29000:], "evidence.bin\x00")
	for i, name := range []string{"/", "evidence.bin", "alias.bin", "dir", "link", "negative", "nested"} {
		a := uint64(0x23000 + i*256)
		parent := uint64(0x23000)
		if i == 6 {
			parent = 0x23300
		}
		put(a, parent)
		put(a+8, uint64(len(name)))
		put(a+16, uint64(0x28000+i*256))
		copy(data[0x28000+i*256:], name)
		ip := []uint64{0x25000, 0x25100, 0x25100, 0x25200, 0x25300, 0, 0x25400}[i]
		put(a+24, ip)
		list(a + 48)
	}
	list(0x23030, 0x23140, 0x23240, 0x23340, 0x23440, 0x23540)
	list(0x23330, 0x23640)
	put(0x26020, 1)
	put(0x26030, testVmemmap+31*56)
	put(31*56, 40)
	put(31*56+8, 0x26020)
	put(31*56+16, 0)
	copy(data[0x1f000:], "HELLO")
	if scenario == "modern" || scenario == "rb-hlist" {
		s.Types["mount"] = symbols.Type{Kind: "struct", Size: 112, Fields: map[string]symbols.Field{"mnt_parent": field(0, ptr), "mnt_mountpoint": field(8, ptr), "mnt_ns": field(16, ptr), "mnt_id": field(24, base("u32")), "mnt": field(32, st("vfsmount")), "mnt_list": field(64, st("list_head")), "mnt_node": field(80, st("rb_node"))}}
		s.Types["vfsmount"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"mnt_root": field(0, ptr), "mnt_sb": field(24, ptr)}}
		clear(data[0x22000:0x22080])
		put(0x22000, 0x22000)
		put(0x22008, 0x23000)
		put(0x22010, 0x21000)
		put(0x22018, 1)
		put(0x22020, 0x23000)
		put(0x22038, 0x24000)
		put(0x16008, 0x22020)
		list(0x21000, 0x22040)
	}
	switch scenario {
	case "rb-hlist":
		s.Types["rb_root"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"rb_node": field(0, ptr)}}
		s.Types["rb_node"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"__rb_parent_color": field(0, base("u64")), "rb_left": field(8, ptr), "rb_right": field(16, ptr)}}
		ns := s.Types["mnt_namespace"]
		delete(ns.Fields, "list")
		ns.Fields["mounts"] = field(0, st("rb_root"))
		s.Types["mnt_namespace"] = ns
		put(0x21000, 0x22050)
		put(0x22050, 1)
		s.Types["hlist_head"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"first": field(0, ptr)}}
		s.Types["hlist_node"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"next": field(0, ptr), "pprev": field(8, ptr)}}
		delete(d.Fields, "d_subdirs")
		delete(d.Fields, "d_child")
		d.Fields["d_children"] = field(48, st("hlist_head"))
		d.Fields["d_sib"] = field(64, st("hlist_node"))
		s.Types["dentry"] = d
		for i := 0; i < 7; i++ {
			put(uint64(0x23030+i*256), 0)
		}
		for _, group := range []struct {
			head  uint64
			nodes []uint64
		}{{0x23030, []uint64{0x23140, 0x23240, 0x23340, 0x23440, 0x23540}}, {0x23330, []uint64{0x23640}}} {
			put(group.head, group.nodes[0])
			previous := group.head
			for i, n := range group.nodes {
				next := uint64(0)
				if i+1 < len(group.nodes) {
					next = group.nodes[i+1]
				}
				put(n, next)
				put(n+8, previous)
				previous = n
			}
		}
	case "union":
		delete(d.Fields, "d_child")
		s.Types["dentry_union"] = symbols.Type{Kind: "union", Size: 16, Fields: map[string]symbols.Field{"d_child": field(0, st("list_head"))}}
		d.Fields["d_u"] = field(64, symbols.TypeRef{Kind: "union", Name: "dentry_union"})
		s.Types["dentry"] = d
	case "bad-parent":
		put(0x23100, 0x23300)
	case "bad-mount":
		put(0x22028, 0)
	case "bad-root":
		put(0x23000, 0x23100)
	case "bad-sb":
		put(0x25110, 0x24008)
	case "bad-name":
		put(0x23108, 4097)
	case "bad-mapping":
		put(0x25160, 0)
	case "bad-target":
		put(0x25368, 0x500000)
	case "cycle":
		put(0x23140, 0x23140)
	case "zero-size":
		put(0x25118, 0)
	}
	encoded, err := s.Encode()
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
func TestLinuxFilesystemLayoutsAliasesAndFilters(t *testing.T) {
	for _, scenario := range []string{"normal", "modern", "union", "rb-hlist", "zero-size"} {
		t.Run(scenario, func(t *testing.T) {
			e := openLinuxELF(t, linuxFilesFixture(t, scenario), true)
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.files", nil, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			if err != nil || result.Task.Rows != 7 {
				t.Fatal(result, err)
			}
			paths := []string{}
			aliases := 0
			for _, r := range rows {
				c := r.Cells
				switch c["RecordType"].String() {
				case "file", "alias":
					paths = append(paths, c["FilePath"].String())
					if c["RecordType"].String() == "alias" {
						aliases++
						if c["FirstDentry"].String() != "0x0000000000023100" {
							t.Fatal(c)
						}
					}
				case "summary":
					proof := c["Coverage"].Data.(map[string]any)
					if proof["traversal_complete"] != true || proof["negative_dentries"] != "1" {
						t.Fatal(proof)
					}
				}
			}
			if aliases != 1 || strings.Join(paths, ",") != "/,/evidence.bin,/alias.bin,/dir,/dir/nested,/link -> evidence.bin" {
				t.Fatal(paths, aliases)
			}
			for _, p := range []map[string]string{{"type": "REG"}, {"type": "DIR LNK"}, {"find": "/alias.bin"}, {"find": "/link", "follow-symlinks": "false"}, {"find": "/missing"}} {
				var filtered []evidence.Row
				r, er := e.Run(context.Background(), "linux.files", p, engine.RunOptions{Emit: func(row evidence.Row) error { filtered = append(filtered, row); return nil }})
				if er != nil {
					t.Fatal(r, er)
				}
				if p["find"] == "/missing" && len(filtered) != 1 {
					t.Fatal(filtered)
				}
				if p["find"] == "/link" && filtered[0].Cells["FilePath"].String() != "/link" {
					t.Fatal(filtered)
				}
			}
			var summary evidence.Row
			r, err := e.Run(context.Background(), "linux.inodepages", map[string]string{"find": "/alias.bin", "dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error { summary = row; return nil }})
			if err != nil || summary.Cells["InodeLookup"].Kind != "structure" {
				t.Fatal(r, err, summary)
			}
			files, err := e.Store.Artifacts(context.Background(), r.Task.ID)
			if err != nil || len(files) != 1 {
				t.Fatal(files, err)
			}
			got, err := os.ReadFile(filepath.Join(e.Store.Dir, files[0].Path))
			want := []byte("HELLO")
			if scenario == "zero-size" {
				want = []byte{}
			}
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal(got, err)
			}
		})
	}
}
func TestLinuxFilesystemFailuresAndCancellation(t *testing.T) {
	for _, scenario := range []string{"bad-parent", "bad-mount", "bad-root", "bad-sb", "bad-name", "bad-mapping", "bad-target", "cycle", "limit", "depth", "type"} {
		t.Run(scenario, func(t *testing.T) {
			e := openLinuxELF(t, linuxFilesFixture(t, scenario), true)
			p := map[string]string{}
			switch scenario {
			case "limit":
				p["max-dentries"] = "2"
			case "depth":
				p["max-depth"] = "1"
			case "type":
				p["type"] = "ANY"
			}
			result, err := e.Run(context.Background(), "linux.files", p, engine.RunOptions{})
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err)
			}
		})
	}
	e := openLinuxELF(t, linuxFilesFixture(t, "normal"), true)
	sentinel := errors.New("consumer done")
	_, err := e.Run(context.Background(), "linux.files", nil, engine.RunOptions{Emit: func(evidence.Row) error { return sentinel }})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = e.Run(ctx, "linux.files", nil, engine.RunOptions{Emit: func(evidence.Row) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, p := range []map[string]string{{"find": "/missing"}, {"find": "/link"}, {"find": "/evidence.bin", "inode": "0x25100"}} {
		r, err := e.Run(context.Background(), "linux.inodepages", p, engine.RunOptions{})
		if err == nil || r.Task.State != "failed" {
			t.Fatal(r, err)
		}
	}
}

func TestLinuxFilesystemDepthBoundAllowsEmptyDirectory(t *testing.T) {
	f := linuxFilesFixture(t, "normal")
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(data[0x23330:], 0x23330)
	binary.LittleEndian.PutUint64(data[0x23338:], 0x23330)
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	e := openLinuxELF(t, f, true)
	result, err := e.Run(context.Background(), "linux.files", map[string]string{"max-depth": "1"}, engine.RunOptions{})
	if err != nil || result.Task.Rows != 6 {
		t.Fatal(result, err)
	}
}

func TestLinuxFilesystemRawNamesAndTruncatedSymlinkTargets(t *testing.T) {
	for _, scenario := range []string{"raw-name", "partial-target", "unterminated-target", "slash-name"} {
		t.Run(scenario, func(t *testing.T) {
			f := linuxFilesFixture(t, "normal")
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "raw-name":
				copy(data[0x28100:], []byte{0xff, 0xfe, 'x'})
				binary.LittleEndian.PutUint64(data[0x23108:], 3)
			case "partial-target":
				binary.LittleEndian.PutUint64(data[0x25368:], uint64(len(data)-3))
				copy(data[len(data)-3:], "abc")
			case "unterminated-target":
				for i := 0; i < 255; i++ {
					data[0x29000+i] = 'x'
				}
			case "slash-name":
				copy(data[0x28100:], "bad/name")
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e := openLinuxELF(t, f, true)
			var target evidence.Row
			result, err := e.Run(context.Background(), "linux.files", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["Dentry"].String() == "0x0000000000023400" && scenario != "raw-name" {
					target = row
				}
				if row.Cells["Dentry"].String() == "0x0000000000023100" && scenario == "raw-name" {
					target = row
				}
				return nil
			}})
			if scenario == "raw-name" {
				if err != nil || target.Cells["FilePath"].String() != "/�x" || !bytes.Equal(target.Cells["PathRaw"].Data.([]byte), []byte{'/', 0xff, 0xfe, 'x'}) {
					t.Fatal(result, target, err)
				}
			} else {
				if err == nil || result.Task.State != "failed" {
					t.Fatal(result, err)
				}
			}
			if scenario == "partial-target" && !bytes.Equal(target.Cells["SymlinkTargetRaw"].Data.([]byte), []byte("abc")) {
				t.Fatal(target)
			}
			if scenario == "unterminated-target" && len(target.Cells["SymlinkTargetRaw"].Data.([]byte)) != 255 {
				t.Fatal(target)
			}
		})
	}
}
