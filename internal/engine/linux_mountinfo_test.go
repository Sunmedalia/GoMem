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

func mountInfoLayout(t *testing.T) testfixture.Fixture {
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
	data = append(data, make([]byte, 0x30000-len(data))...)
	ptr := symbols.TypeRef{Kind: "pointer"}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	i32 := symbols.TypeRef{Kind: "base", Name: "i32"}
	table.Bases["i32"] = symbols.Type{Kind: "int", Size: 4, Endian: "little", Signed: true}
	field := func(off uint64, ref symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: off, Type: ref}
	}
	strct := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	table.Types["mount"] = symbols.Type{Kind: "struct", Size: 112, Fields: map[string]symbols.Field{
		"mnt_list": field(0, strct("list_head")), "mnt_id": field(16, i32), "mnt_parent": field(24, ptr),
		"mnt_mountpoint": field(32, ptr), "mnt": field(40, strct("vfsmount")), "mnt_devname": field(64, ptr),
		"mnt_group_id": field(72, i32), "mnt_master": field(80, ptr), "mnt_share": field(88, strct("list_head")),
		"mnt_ns": field(104, ptr),
	}}
	table.Types["vfsmount"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{
		"mnt_root": field(0, ptr), "mnt_sb": field(8, ptr), "mnt_flags": field(16, u32),
	}}
	table.Types["nsproxy"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"mnt_ns": field(0, ptr)}}
	table.Types["mnt_namespace"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{
		"list": field(0, strct("list_head")), "proc_inum": field(16, u32),
	}}
	table.Types["file_system_type"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"name": field(0, ptr)}}
	table.Types["atomic_t"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"counter": field(0, i32)}}
	sb := table.Types["super_block"]
	sb.Size = 24
	sb.Fields["s_flags"] = field(4, u32)
	sb.Fields["s_type"] = field(8, ptr)
	sb.Fields["s_subtype"] = field(16, ptr)
	table.Types["super_block"] = sb
	inode := table.Types["inode"]
	inode.Size = 48
	inode.Fields["i_count"] = field(32, strct("atomic_t"))
	table.Types["inode"] = inode
	task := table.Types["task_struct"]
	task.Fields["nsproxy"] = field(152, ptr)
	task.Size = 160
	table.Types["task_struct"] = task
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put32 := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(data[a:], v) }
	cstr := func(a uint64, s string) { copy(data[a:], s) }
	// Namespace 7 contains rootfs (id 1, self parent) and ext (id 20).
	// Process root is the ext vfsmount, so rootfs appears at / and ext at /.
	list := func(head uint64, nodes ...uint64) {
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
	ns, rootfs, ext := uint64(0x20000), uint64(0x21000), uint64(0x22000)
	list(ns, rootfs, ext)
	put32(ns+16, 7)
	for _, task := range []uint64{0xa000, 0xb000} {
		put(task+152, 0x23000)
	}
	put(0x23000, ns)
	// Process filesystem root: dentry 0x17000, mount is ext vfsmount.
	put(0x16000, 0x17000)
	put(0x16008, ext+40)
	writeMount := func(a, id, parent, point, root, sb, flags, devname uint64, source, fstype string, nlink uint32) {
		put32(a+16, uint32(id))
		put(a+24, parent)
		put(a+32, point)
		put(a+40, root)
		put(a+48, sb)
		put32(a+56, uint32(flags))
		put(a+64, devname)
		put32(a+72, 0)
		put(a+80, 0)
		list(a+88, a+88) // empty share list points at itself
		// The helper above treats one node as a cycle through head. Rebuild self.
		put(a+88, a+88)
		put(a+96, a+88)
		put(a+104, ns)
		cstr(devname, source)
		put32(sb, uint32(id<<20|1))
		put32(sb+4, 0)
		put(sb+8, sb+0x100)
		put(sb+0x100, sb+0x180)
		cstr(sb+0x180, fstype)
		put(root, root)
		put32(root+8, 1)
		put(root+16, root+0x80)
		cstr(root+0x80, "/")
		put(root+24, root+0x100)
		put(root+0x100, 11)
		put32(root+0x108, nlink)
		put(root+0x110, sb)
		put32(root+0x120, 1)
	}
	// rootfs is its own parent. Its mountpoint is the global root dentry.
	writeMount(rootfs, 1, rootfs, 0x17000, 0x24000, 0x25000, 0, 0x26000, "rootfs", "rootfs", 2)
	// ext is mounted on rootfs at /ext. Its own root dentry is not deleted.
	writeMount(ext, 20, rootfs, 0x27000, 0x28000, 0x29000, 0x21, 0x2a000, "/dev/disk", "ext4", 2)
	// /ext dentry hangs from the global root and has a zero link count.
	put(0x27000, 0x17000)
	put32(0x27008, 3)
	put(0x27010, 0x2b000)
	cstr(0x2b000, "ext")
	put(0x27018, 0x2c000)
	put(0x2c000, 22)
	put32(0x2c008, 0)
	put(0x2c010, 0x25000)
	put32(0x2c020, 1)
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

func TestLinuxMountInfoSynthetic(t *testing.T) {
	f := mountInfoLayout(t)
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "linux.mountinfo", map[string]string{"mount-format": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error {
		rows = append(rows, r)
		return nil
	}})
	if err != nil || result.Task.State != "completed" || len(rows) != 3 {
		t.Fatal(result, err, len(rows))
	}
	want := []struct{ id, parent, dev, point, opts, kind, src, sb, fields, root, ns string }{
		{"1", "1", "1:1", "/", "rw", "rootfs", "rootfs", "rw", "", "/", "7"},
		{"20", "1", "20:1", " /ext (deleted)", "rw,nosuid,relatime", "ext4", "/dev/disk", "rw", "", "/", "7"},
	}
	for i, row := range rows[:2] {
		c := row.Cells
		if c["RecordType"].String() != "mount" || c["MOUNT ID"].String() != want[i].id || c["PARENT_ID"].String() != want[i].parent || c["MAJOR:MINOR"].String() != want[i].dev || c["MOUNT_POINT"].String() != want[i].point || c["MOUNT_OPTIONS"].String() != want[i].opts || c["FSTYPE"].String() != want[i].kind || c["MOUNT_SRC"].String() != want[i].src || c["SB_OPTIONS"].String() != want[i].sb || c["FIELDS"].String() != want[i].fields || c["ROOT"].String() != want[i].root || c["MNT_NS_ID"].String() != want[i].ns || c["PATH"].String() != want[i].point || c["DEVNAME"].String() != want[i].src {
			t.Fatalf("row %d %+v", i, c)
		}
		if captures := verifyModuleParameterWireCaptures(t, e, c["FieldEvidence"]); captures != 7 {
			t.Fatalf("row %d verified %d captures, expected all seven scalar/text captures", i, captures)
		}
	}
	if rows[2].Cells["RecordType"].String() != "summary" {
		t.Fatal(rows[2].Cells["RecordType"])
	}
}
