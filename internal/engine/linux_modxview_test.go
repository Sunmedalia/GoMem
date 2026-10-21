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

func modxFixture(t *testing.T, arch, layout, fault string) testfixture.Fixture {
	t.Helper()
	f := linuxCapabilityFixture(t, arch)
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	char := symbols.TypeRef{Kind: "base", Name: "char"}
	i32 := symbols.TypeRef{Kind: "base", Name: "i32"}
	table.Bases["i32"] = symbols.Type{Kind: "int", Size: 4, Endian: "little", Signed: true}
	strct := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	field := func(offset uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: typ}
	}
	table.Types["kobject"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{"entry": field(0, strct("list_head")), "name": field(16, ptr), "kref": field(24, strct("kref"))}}
	table.Types["kref"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"refcount": field(0, strct("atomic_t"))}}
	table.Types["atomic_t"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"counter": field(0, i32)}}
	table.Types["module_kobject"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"mod": field(0, ptr), "kobj": field(16, strct("kobject"))}}
	table.Types["kset"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"list": field(0, strct("list_head"))}}
	table.Types["module"] = symbols.Type{Kind: "struct", Size: 256, Fields: map[string]symbols.Field{"list": field(0, strct("list_head")), "name": field(32, symbols.TypeRef{Kind: "array", Count: 16, Subtype: &char}), "module_core": field(48, ptr), "core_size": field(56, u64), "core_text_size": field(64, u32), "init_size": field(68, u32), "taints": field(112, u64), "mkobj": field(128, strct("module_kobject"))}}
	table.Symbols["modules"] = symbols.Symbol{Address: 0x1d000}
	table.Symbols["module_kset"] = symbols.Symbol{Address: 0x1d100, Type: &ptr}
	table.Symbols["module_addr_min"] = symbols.Symbol{Address: 0x1d108, Type: &u64}
	table.Symbols["module_addr_max"] = symbols.Symbol{Address: 0x1d110, Type: &u64}
	word := func(at, v uint64) { binary.LittleEndian.PutUint32(data[at:], uint32(v)) }
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
	pointer := func(at, v uint64) {
		if table.PointerSize() == 4 {
			word(at, v)
		} else {
			put(at, v)
		}
	}
	list := func(at, next, prev uint64) { pointer(at, next); pointer(at+uint64(table.PointerSize()), prev) }
	list(0x1d000, 0xc000, 0xc000)
	list(0xc000, 0x1d000, 0x1d000)
	pointer(0x1d100, 0xe000)
	list(0xe000, 0xc090, 0xc490)
	list(0xc090, 0xc490, 0xe000)
	list(0xc490, 0xe000, 0xc090)
	put(0x1d108, 0xc000)
	put(0x1d110, 0xcd00)
	for i, a := range []uint64{0xc000, 0xc400, 0xc800, 0xcc00} {
		name := []string{"active", "sys-only", "scan-only", "invalid"}[i]
		copy(data[a+32:], name)
		pointer(a+48, uint64(0x10000+i*0x2000))
		put(a+56, 4096)
		word(a+64, 2048)
		word(a+68, 0)
		put(a+112, 1<<uint(i*10))
		pointer(a+128, a)
		pointer(a+160, uint64(0x18000+i*64))
		clear(data[0x18000+i*64 : 0x18000+i*64+32])
		copy(data[0x18000+i*64:], name)
		word(a+168, 3)
	}
	put(0xcc38, 0)
	switch layout {
	case "layout":
		table.Types["module_layout"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"base": field(0, ptr), "size": field(8, u64), "text_size": field(16, u32)}}
		for _, name := range []string{"module_core", "core_size", "core_text_size", "init_size"} {
			delete(table.Types["module"].Fields, name)
		}
		table.Types["module"].Fields["core_layout"] = field(48, strct("module_layout"))
		table.Types["module"].Fields["init_layout"] = field(80, strct("module_layout"))
	case "mem":
		table.Types["module_memory"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"base": field(0, ptr), "size": field(8, u64)}}
		if table.Enums == nil {
			table.Enums = map[string]symbols.Enumeration{}
		}
		enum := symbols.Enumeration{Base: "u32", Size: 4, Constants: map[string]json.Number{}}
		for i, n := range []string{"MOD_TEXT", "MOD_DATA", "MOD_RODATA", "MOD_RO_AFTER_INIT", "MOD_INIT_TEXT", "MOD_INIT_DATA", "MOD_INIT_RODATA"} {
			enum.Constants[n] = json.Number(string(rune('0' + i)))
		}
		table.Enums["mod_mem_type"] = enum
		ref := strct("module_memory")
		table.Types["module"].Fields["mem"] = field(256, symbols.TypeRef{Kind: "array", Count: 7, Subtype: &ref})
		typ := table.Types["module"]
		typ.Size = 368
		table.Types["module"] = typ
		for i, a := range []uint64{0xc000, 0xc400, 0xc800, 0xcc00} {
			for j := 0; j < 4; j++ {
				pointer(a+256+uint64(j*16), uint64(0x10000+i*0x2000+j*1024))
				size := uint64(1024)
				if i == 3 {
					size = 0
				}
				put(a+264+uint64(j*16), size)
			}
		}
	}
	switch fault {
	case "modern-kref":
		table.Types["refcount_t"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"refs": field(0, strct("atomic_t"))}}
		table.Types["kref"].Fields["refcount"] = field(0, strct("refcount_t"))
	case "mod-tree":
		table.Types["latch_tree_root"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"addr_min": field(0, u64), "addr_max": field(8, u64)}}
		ref := strct("latch_tree_root")
		table.Symbols["mod_tree"] = symbols.Symbol{Address: 0x1d108, Type: &ref}
	case "duplicate-name":
		copy(data[0x18040:], "active\x00")
	case "low-ref":
		word(0xc4a8, 2)
	case "negative-ref":
		word(0xc4a8, 0xffffffff)
	case "zero-name":
		pointer(0xc4a0, 0)
	case "bad-name":
		pointer(0xc4a0, 0x300000)
	case "partial-name":
		pointer(0xc4a0, 0x1fff8)
	case "bad-module":
		pointer(0xc480, 0x300000)
	case "bad-active-tail":
		pointer(0x1d000+uint64(table.PointerSize()), 0)
	case "bad-sysfs-backlink":
		pointer(0xc490+uint64(table.PointerSize()), 0)
	case "null-kset":
		pointer(0x1d100, 0)
	case "missing-kset":
		delete(table.Symbols, "module_kset")
	case "missing-bound-type":
		v := table.Symbols["module_addr_min"]
		v.Type = nil
		table.Symbols["module_addr_min"] = v
	case "bad-bounds":
		put(0x1d108, 0xcd00)
		put(0x1d110, 0xc000)
	case "scan-hole":
		put(0x1d108, 0x2f000)
		put(0x1d110, 0x31000)
	case "missing-core":
		delete(table.Types["module"].Fields, "core_size")
		if layout == "layout" {
			delete(table.Types["module_layout"].Fields, "size")
		}
	case "bad-self":
		pointer(0xc880, 0xc400)
	case "unknown-mem-enum":
		delete(table.Enums["mod_mem_type"].Constants, "MOD_DATA")
	case "short-mem-array":
		v := table.Types["module"].Fields["mem"]
		v.Type.Count = 2
		table.Types["module"].Fields["mem"] = v
	case "dynamic-taints":
		table.Types["taint_flag"] = symbols.Type{Kind: "struct", Size: 12, Fields: map[string]symbols.Field{"c_true": field(0, u32), "c_false": field(4, u32), "module": field(8, u32)}}
		ref := strct("taint_flag")
		array := symbols.TypeRef{Kind: "array", Count: 5, Subtype: &ref}
		table.Symbols["taint_flags"] = symbols.Symbol{Address: 0x19000, Type: &array}
		for i, flag := range []struct{ yes, no, mod uint64 }{{'P', 'G', 1}, {'F', ' ', 0}, {'?', '-', 1}, {0x110000, ' ', 1}, {'O', ' ', 1}} {
			at := uint64(0x19000 + i*12)
			word(at, flag.yes)
			word(at+4, flag.no)
			word(at+8, flag.mod)
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
func openModx(t *testing.T, f testfixture.Fixture, arch string) *engine.Engine {
	t.Helper()
	if arch == "control" {
		arch = "x64"
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func TestLinuxModxviewSources(t *testing.T) {
	for _, arch := range []string{"control", "x86", "pae"} {
		for _, layout := range []string{"legacy", "layout", "mem"} {
			t.Run(arch+"/"+layout, func(t *testing.T) {
				e := openModx(t, modxFixture(t, arch, layout, ""), arch)
				var rows []evidence.Row
				result, err := e.Run(context.Background(), "linux.modxview", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
					if r.Cells["RecordType"].String() == "module_observation" {
						address, _ := r.Cells["Address"].Uint()
						base, _ := r.Cells["Base"].Uint()
						size, _ := r.Cells["Size"].Uint()
						end, _ := r.Cells["End"].Uint()
						if base != 0x10000+(address-0xc000)*8 || size != 4096 || end != base+size {
							t.Fatal("module extent mismatch", r)
						}
					}
					if r.Cells["RecordType"].String() == "module" {
						rows = append(rows, r)
					}
					return nil
				}})
				if err != nil || result.Task.State != "completed" || len(rows) != 3 {
					t.Fatal(result, err, len(rows))
				}
				for i, r := range rows {
					if err := r.Verify(); err != nil {
						t.Fatal(err)
					}
					if r.Cells["In procfs"].Data != (i == 0) || r.Cells["In sysfs"].Data != (i < 2) || r.Cells["In scan"].Data != true {
						t.Fatal(r)
					}
				}
				cached, err := e.Run(context.Background(), "linux.modxview", nil, engine.RunOptions{})
				if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
					t.Fatal(cached, err)
				}
			})
		}
	}
}
func TestLinuxModxviewVariantsAndFailures(t *testing.T) {
	for _, fault := range []string{"modern-kref", "mod-tree", "duplicate-name", "low-ref", "negative-ref", "zero-name", "bad-name", "partial-name", "bad-module", "bad-active-tail", "bad-sysfs-backlink", "null-kset", "missing-kset", "missing-bound-type", "bad-bounds", "scan-hole", "missing-core", "bad-self", "dynamic-taints"} {
		t.Run(fault, func(t *testing.T) {
			e := openModx(t, modxFixture(t, "control", "legacy", fault), "control")
			result, err := e.Run(context.Background(), "linux.modxview", nil, engine.RunOptions{})
			failed := fault == "bad-name" || fault == "partial-name" || fault == "bad-module" || fault == "bad-active-tail" || fault == "bad-sysfs-backlink" || fault == "null-kset" || fault == "missing-kset" || fault == "missing-bound-type" || fault == "bad-bounds" || fault == "missing-core"
			if failed != (err != nil) {
				t.Fatal(fault, result, err)
			}
			rows, queryErr := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if queryErr != nil || len(rows) == 0 {
				t.Fatal(queryErr)
			}
			modules := 0
			for _, r := range rows {
				if r.Cells["RecordType"].String() != "module" {
					continue
				}
				modules++
				name := r.Cells["Name"].String()
				if name == "sys-only" && (fault == "low-ref" || fault == "negative-ref" || fault == "zero-name") && r.Cells["In sysfs"].Data != false {
					t.Fatal(r)
				}
				if name == "active" && fault == "duplicate-name" && r.Cells["In sysfs"].Data != false {
					t.Fatal(r)
				}
				if name == "scan-only" && fault == "bad-self" {
					t.Fatal("bad self pointer passed scanning", r)
				}
			}
			if fault == "bad-self" && modules != 2 {
				t.Fatal(modules)
			}
			for _, r := range rows {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, fault := range []string{"unknown-mem-enum", "short-mem-array"} {
		t.Run(fault, func(t *testing.T) {
			e := openModx(t, modxFixture(t, "control", "mem", fault), "control")
			_, err := e.Run(context.Background(), "linux.modxview", nil, engine.RunOptions{})
			if err == nil {
				t.Fatal("bad module memory layout accepted")
			}
		})
	}
}
func TestLinuxModxviewCancellationAndBounds(t *testing.T) {
	for _, p := range []map[string]string{{"max-nodes": "1"}, {"max-scan-bytes": "1"}, {"max-scan-bytes": "0"}, {"max-scan-bytes": "8589934593"}} {
		e := openModx(t, modxFixture(t, "control", "legacy", ""), "control")
		if _, err := e.Run(context.Background(), "linux.modxview", p, engine.RunOptions{}); err == nil {
			t.Fatal("ignored bound", p)
		}
	}
	for _, cancelled := range []bool{true, false} {
		e := openModx(t, modxFixture(t, "control", "legacy", ""), "control")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sentinel := errors.New("output stopped")
		count := 0
		result, err := e.Run(ctx, "linux.modxview", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
			count++
			if cancelled {
				cancel()
				return nil
			}
			return sentinel
		}})
		want := sentinel
		if cancelled {
			want = context.Canceled
		}
		if !errors.Is(err, want) || count != 1 {
			t.Fatal(result, err, count)
		}
		if cancelled {
			rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(rows) != 1 {
				t.Fatal(err, len(rows))
			}
		}
	}
}
