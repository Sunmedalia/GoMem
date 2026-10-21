package engine_test

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func moduleExportEngine(t *testing.T, arch, layout, fault string) *engine.Engine {
	t.Helper()
	f := modxFixture(t, arch, "legacy", "")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, make([]byte, 0x40000-len(data))...)
	pointer := func(at, value uint64) {
		if table.PointerSize() == 4 {
			binary.LittleEndian.PutUint32(data[at:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(data[at:], value)
		}
	}
	put32 := func(at uint64, value uint32) { binary.LittleEndian.PutUint32(data[at:], value) }
	ref := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: name} }
	ptr := symbols.TypeRef{Kind: "pointer"}
	field := func(at uint64, typ symbols.TypeRef) symbols.Field { return symbols.Field{Offset: at, Type: typ} }
	strct := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	table.Types["module"].Fields["sect_attrs"] = field(208, ptr)
	table.Types["module_sect_attrs"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"nsections": field(0, ref("u32")), "attrs": field(8, symbols.TypeRef{Kind: "array", Count: 0, Subtype: &symbols.TypeRef{Kind: "struct", Name: "module_sect_attr"}})}}
	table.Types["module_sect_attr"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"name": field(0, ptr), "address": field(8, ptr)}}
	symSize := uint64(24)
	symType := "Elf64_Sym"
	symFields := map[string]symbols.Field{"st_name": field(0, ref("u32")), "st_info": field(4, ref("char")), "st_other": field(5, ref("char")), "st_shndx": field(6, ref("u16")), "st_value": field(8, ref("u64")), "st_size": field(16, ref("u64"))}
	if table.PointerSize() == 4 {
		symSize = 16
		symType = "Elf32_Sym"
		symFields = map[string]symbols.Field{"st_name": field(0, ref("u32")), "st_value": field(4, ref("u32")), "st_size": field(8, ref("u32")), "st_info": field(12, ref("char")), "st_other": field(13, ref("char")), "st_shndx": field(14, ref("u16"))}
	}
	table.Types[symType] = symbols.Type{Kind: "struct", Size: symSize, Fields: symFields}
	table.Types["mod_kallsyms"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"symtab": field(0, ptr), "strtab": field(8, ptr), "num_symtab": field(16, ref("u32"))}}
	for _, module := range []uint64{0xc000, 0xc400} {
		pointer(module+208, 0x23000)
		base := module + 216
		if layout == "pointer" {
			table.Types["module"].Fields["kallsyms"] = field(216, ptr)
			pointer(base, 0x22000)
			base = 0x22000
		} else if layout == "inline" {
			table.Types["module"].Fields["kallsyms"] = field(216, strct("mod_kallsyms"))
		} else {
			table.Types["module"].Fields["symtab"] = field(216, ptr)
			table.Types["module"].Fields["strtab"] = field(224, ptr)
			table.Types["module"].Fields["num_symtab"] = field(232, ref("u32"))
		}
		pointer(base, 0x25000)
		pointer(base+8, 0x26000)
		put32(base+16, 3)
	}
	binary.LittleEndian.PutUint64(data[0x1d108:], 0x10000)
	binary.LittleEndian.PutUint64(data[0x1d110:], 0x40000)
	names := []string{".text", ".data", ".strtab", ".symtab"}
	addresses := []uint64{0x10000, 0x10010, 0x10020, 0x10040}
	if fault == "gaps" || fault == "limit" {
		names = append(names, ".bss")
		addresses = append(addresses, 0x30000)
	}

	sectionStride := 16
	if fault == "modern-sections" {
		delete(table.Types["module_sect_attrs"].Fields, "nsections")
		table.Types["module_sect_attrs"].Fields["grp"] = field(0, strct("attribute_group"))
		table.Types["attribute_group"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"bin_attrs": field(0, ptr)}}
	}
	if fault == "battr-names" {
		delete(table.Types["module_sect_attr"].Fields, "name")
		table.Types["module_sect_attr"].Fields["battr"] = field(0, strct("bin_attribute"))
		table.Types["bin_attribute"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"attr": field(0, strct("attribute"))}}
		table.Types["attribute"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"name": field(0, ptr)}}
	}
	if fault == "inline-names" {
		sectionStride = 32
		st := table.Types["module_sect_attr"]
		st.Size = 32
		char := ref("char")
		st.Fields["name"] = field(0, symbols.TypeRef{Kind: "array", Count: 16, Subtype: &char})
		st.Fields["address"] = field(16, ptr)
		table.Types["module_sect_attr"] = st
	}
	put32(0x23000, uint32(len(names)))
	for i, name := range names {
		at := uint64(0x23008 + i*sectionStride)
		pointer(at, uint64(0x24000+i*256))
		pointer(at+8, addresses[i])
		copy(data[0x24000+i*256:], name+"\x00")
		if fault == "inline-names" {
			clear(data[at : at+32])
			copy(data[at:at+16], name+"\x00")
			pointer(at+16, addresses[i])
		}

	}
	if fault == "modern-sections" {
		pointer(0x23000, 0x27000)
		for i := range names {
			pointer(uint64(0x27000+i*table.PointerSize()), uint64(0x23008+i*16))
		}
	}
	copy(data[0x10000:], bytes.Repeat([]byte{0x90}, 16))
	copy(data[0x10010:], bytes.Repeat([]byte{0xab}, 16))
	copy(data[0x26000:], "\x00func\x00value\x00\x00")
	for i, value := range []uint64{0, 0x10000, 0x10010} {
		at := uint64(0x25000) + uint64(i)*symSize
		put32(at, uint32(i))
		if symSize == 24 {
			binary.LittleEndian.PutUint64(data[at+8:], value)
			binary.LittleEndian.PutUint64(data[at+16:], 4)
		} else {
			put32(at+4, uint32(value))
			put32(at+8, 4)
		}
	}
	if fault == "missing-symtab" {
		copy(data[0x24300:], ".no_sym\x00")
	}
	if fault == "metadata" {
		pointer(0xc000+208, 0x500000)
	}

	if fault == "name-hole" {
		mt := table.Types["module"]
		mt.Size = 0x34020
		f := mt.Fields["name"]
		f.Offset = 0x33fff
		mt.Fields["name"] = f
		table.Types["module"] = mt
	}
	if fault == "symbol-hole" {
		pointer(0xc000+216, 0x3fff0)
	}
	if fault == "symbol-limit" {
		put32(0xc000+232, 65537)
	}
	if fault == "section-limit" {
		put32(0x23000, 4097)
	}
	if fault == "gaps" {
		data = data[:0x31000]
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
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLinuxModuleELFExportAndCache(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, layout := range []string{"legacy", "inline", "pointer"} {
			t.Run(arch+"/"+layout, func(t *testing.T) {
				e := moduleExportEngine(t, arch, layout, "")
				ctx := context.Background()
				var fresh, replay bytes.Buffer
				result, err := e.Run(ctx, "linux.lsmod", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { return json.NewEncoder(&fresh).Encode(r) }})
				if err != nil || result.Task.State != "completed" || result.Task.Rows != 1 {
					t.Fatal(result, err)
				}
				artifacts, err := e.Store.Artifacts(ctx, result.Task.ID)
				if err != nil || len(artifacts) != 1 {
					t.Fatal(artifacts, err)
				}
				a := artifacts[0]
				if a.State != "completed" || a.MissingBytes != "0" || a.Name != "kernel_module.active.0xc000.elf" || a.Provenance.ImageSHA256 != e.Hash {
					t.Fatal(a)
				}
				raw, err := os.ReadFile(filepath.Join(e.Config.CaseDir, a.Path))
				if err != nil {
					t.Fatal(err)
				}
				file, err := elf.NewFile(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if file.Type != elf.ET_REL || file.Section(".text") == nil || file.Section(".symtab") == nil {
					t.Fatal(file)
				}
				if err = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); err != nil {
					t.Fatal(err)
				}
				cached, err := e.Run(ctx, "linux.lsmod", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { return json.NewEncoder(&replay).Encode(r) }})
				if err != nil || !cached.Reused || !bytes.Equal(fresh.Bytes(), replay.Bytes()) {
					t.Fatal(cached, err)
				}
				hidden, err := e.Run(ctx, "linux.check_modules", map[string]string{"dump": "true"}, engine.RunOptions{})
				if err != nil {
					t.Fatal(hidden, err)
				}
				artifacts, err = e.Store.Artifacts(ctx, hidden.Task.ID)
				if err != nil || len(artifacts) != 1 || artifacts[0].Name != "kernel_module.sys-only.0xc400.elf" {
					t.Fatal(artifacts, err)
				}
			})
		}
	}
}

func TestLinuxModuleELFExportFailuresAndPadding(t *testing.T) {
	for _, fault := range []string{"missing-symtab", "metadata", "gaps", "limit", "symbol-hole", "symbol-limit", "section-limit", "name-hole"} {
		t.Run(fault, func(t *testing.T) {
			e := moduleExportEngine(t, "x64", "legacy", fault)
			ctx := context.Background()
			params := map[string]string{"dump": "true"}
			if fault == "limit" {
				params["max-module-bytes"] = "4096"
			}
			result, err := e.Run(ctx, "linux.lsmod", params, engine.RunOptions{Emit: func(row evidence.Row) error {
				if fault == "name-hole" && row.Cells["DumpEvidence"].Reason != "module_name_unavailable" {
					t.Fatal(row)
				}
				if fault == "symbol-hole" {
					fields := bashProofFields(t, row.Cells["DumpEvidence"])
					proof := bashProofFields(t, fields["SymbolTableRaw"])
					count, err := proof["CapturedBytes"].Uint()
					if err != nil || count != 16 || proof["ReadComplete"].Data != false || proof["Error"].Error == "" {
						t.Fatal(proof, err)
					}
				}
				return nil
			}})
			if fault == "gaps" {
				if err != nil {
					t.Fatal(result, err)
				}
				artifacts, err := e.Store.Artifacts(ctx, result.Task.ID)
				if err != nil || len(artifacts) != 1 || artifacts[0].State != "completed_with_gaps" || artifacts[0].MissingBytes != "61440" {
					t.Fatal(artifacts, err)
				}
				if err = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); err != nil {
					t.Fatal(err)
				}

			} else {
				if err == nil || result.Task.State != "failed" {
					t.Fatal(result, err)
				}
				artifacts, err := e.Store.Artifacts(ctx, result.Task.ID)
				if err != nil || len(artifacts) != 0 {
					t.Fatal(artifacts, err)
				}
				again, err := e.Run(ctx, "linux.lsmod", params, engine.RunOptions{})
				if err == nil || again.Reused {
					t.Fatal(again, err)
				}
			}
		})
	}
}

func TestLinuxModuleELFSectionLayouts(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, layout := range []string{"modern-sections", "battr-names", "inline-names"} {
			t.Run(arch+"/"+layout, func(t *testing.T) {
				e := moduleExportEngine(t, arch, "pointer", layout)
				result, err := e.Run(context.Background(), "linux.lsmod", map[string]string{"dump": "true"}, engine.RunOptions{})
				if err != nil || result.Task.State != "completed" {
					t.Fatal(result, err)
				}
				artifacts, err := e.Store.Artifacts(context.Background(), result.Task.ID)
				if err != nil || len(artifacts) != 1 || artifacts[0].State != "completed" {
					t.Fatal(artifacts, err)
				}
			})
		}
	}
}
