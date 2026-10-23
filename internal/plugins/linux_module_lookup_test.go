package plugins

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func moduleLookupFixture(width int, big bool) (capabilityLayer, plugin.Environment, *linuxModuleRead) {
	mem := capabilityLayer(make([]byte, 200000))
	endian := "little"
	if big {
		endian = "big"
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: uint64(width), Endian: endian}, "u32": {Kind: "int", Size: 4, Endian: endian}}, Types: map[string]symbols.Type{"module": {Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"symtab": {Type: ptr}, "strtab": {Offset: 8, Type: ptr}, "num_symtab": {Offset: 16, Type: u32}}}}, Symbols: map[string]symbols.Symbol{"a_entry": {Address: 320}, "z_entry": {Address: 320}}}
	arch := "x64"
	if width == 4 {
		arch = "x86"
	}
	env := plugin.Environment{Kernel: mem, Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}, Architecture: arch, OS: "linux"}
	n := &linuxModuleRead{context.Background(), env, map[string]evidence.Value{}, &pluginFailures{}}
	return mem, env, n
}

func TestLinuxModuleAddressMask(t *testing.T) {
	for _, tc := range []struct {
		arch string
		mask uint64
		bad  bool
	}{
		{"x64", 0xffffffffffff, false},
		{"arm64", 0xffffffffffff, false},
		{"x86", 0xffffffff, false},
		{"pae", 0xffffffff, false},
		{"arm", 0, true},
		{"", 0, true},
	} {
		mask, err := linuxModuleAddressMask(plugin.Environment{Architecture: tc.arch})
		if (err != nil) != tc.bad || !tc.bad && mask != tc.mask {
			t.Fatal(tc, mask, err)
		}
	}
}

func TestLinuxModuleLookupPinnedPolicies(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-kthreads-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Lookups []struct {
			Name                string
			Ranges              [][]any
			Target              uint64
			Module, Symbol      *string
			SelectedOwnerSymbol *string `json:"selected_owner_symbol"`
		}
		SymbolWindows []struct {
			Count, Visited uint64
		} `json:"symbol_windows"`
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Lookups) != 9 || len(oracle.SymbolWindows) != 5 {
		t.Fatal(err)
	}
	for _, width := range []int{4, 8} {
		for _, big := range []bool{false, true} {
			for _, tc := range oracle.Lookups {
				mem, env, n := moduleLookupFixture(width, big)
				var order binary.ByteOrder = binary.LittleEndian
				if big {
					order = binary.BigEndian
				}
				put := func(at, v uint64) {
					if width == 8 {
						order.PutUint64(mem[at:], v)
					} else {
						order.PutUint32(mem[at:], uint32(v))
					}
				}
				var modules []linuxModuleInfo
				for i, v := range tc.Ranges {
					offset := uint64(0x100 + i*0x40)
					name := v[1].(string)
					modules = append(modules, linuxModuleInfo{offset, uint64(v[2].(float64)), uint64(v[3].(float64) - v[2].(float64)), name, "test"})
					if name == "__kernel__" {
						continue
					}
					symtab, strtab := uint64(0x1000+i*0x400), uint64(0x4000+i*0x1000)
					put(offset, symtab)
					put(offset+8, strtab)
					values := []struct {
						name string
						at   uint64
					}{{"entry", 100}, {"overlap", 160}}
					if name == "two" {
						values = []struct {
							name string
							at   uint64
						}{{"other", 160}}
					}
					if name == "qualified" {
						values = []struct {
							name string
							at   uint64
						}{{"table!entry!tail", 520}}
					}
					order.PutUint32(mem[offset+16:], uint32(len(values)))
					stride := uint64(16)
					if width == 8 {
						stride = 24
					}
					for j, s := range values {
						order.PutUint32(mem[symtab+uint64(j)*stride:], uint32(j*64))
						if width == 8 {
							order.PutUint64(mem[symtab+uint64(j)*stride+8:], s.at)
						} else {
							order.PutUint32(mem[symtab+uint64(j)*stride+4:], uint32(s.at))
						}
						copy(mem[strtab+uint64(j*64):], s.name)
					}
				}
				mask, _ := linuxModuleAddressMask(env)
				index, err := linuxKernelSymbolIndex(context.Background(), env, mask)
				if err != nil {
					t.Fatal(err)
				}
				got, sym, matches, err := linuxModuleLookup(n, modules, index, tc.Target)
				if err != nil {
					t.Fatal(tc.Name, err)
				}
				if tc.Module == nil {
					if got != nil {
						t.Fatal(tc.Name, got)
					}
				} else if got == nil || got.name != *tc.Module {
					t.Fatal(tc.Name, got)
				}
				if tc.SelectedOwnerSymbol == nil {
					if sym != "" {
						t.Fatal(tc.Name, sym)
					}
				} else if sym != *tc.SelectedOwnerSymbol {
					t.Fatal(tc.Name, sym, *tc.SelectedOwnerSymbol)
				}
				if len(tc.Name) >= 7 && tc.Name[:7] == "overlap" && len(matches) != 2 {
					t.Fatal(tc, matches)
				}
			}
			for _, tc := range oracle.SymbolWindows {
				mem, _, n := moduleLookupFixture(width, big)
				var order binary.ByteOrder = binary.LittleEndian
				if big {
					order = binary.BigEndian
				}
				put := func(at, v uint64) {
					if width == 8 {
						order.PutUint64(mem[at:], v)
					} else {
						order.PutUint32(mem[at:], uint32(v))
					}
				}
				put(0x100, 0x1000)
				put(0x108, 0x20000)
				order.PutUint32(mem[0x110:], uint32(tc.Count))
				copy(mem[0x20000:], "entry")
				_, err := linuxModuleELFSymbol(n, 0x100, 0x777, 0xffffffffffff)
				if err != nil {
					t.Fatal(width, big, tc, err)
				}
				visited := uint64(0)
				for key := range n.fields {
					if len(key) >= 8 && key[:8] == "elf_sym_" {
						visited++
					}
				}
				// All zero st_values are not the requested address, so the whole window is visited.
				if visited != tc.Visited {
					t.Fatal(width, big, tc, visited)
				}
			}
		}
	}
}
func TestLinuxModuleLookupBoundsAndCancellation(t *testing.T) {
	for _, arch := range []string{"x64", "arm64"} {
		_, env, n := moduleLookupFixture(8, false)
		env.Architecture = arch
		env.KernelSlide = 0x1000
		index, err := linuxKernelSymbolIndex(context.Background(), env, 0xffffffffffff)
		if err != nil || index[0x1140] != "a_entry" {
			t.Fatal(arch, index, err)
		}
		n.e = env
		mods := []linuxModuleInfo{{1, 0xffff000000001000, 0x200, "__kernel__", "kernel"}}
		got, symbol, _, err := linuxModuleLookup(n, mods, index, 0xffff000000001140)
		if err != nil || got == nil || symbol != "a_entry" {
			t.Fatal(arch, got, symbol, err)
		}
	}
	if _, err := linuxModuleMatches([]linuxModuleInfo{{base: ^uint64(0) - 1, size: 4}}, ^uint64(0), 1); err == nil {
		t.Fatal("range overflow accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, env, _ := moduleLookupFixture(8, false)
	if _, err := linuxKernelSymbolIndex(ctx, env, 0xffffffffffff); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	mem, _, n := moduleLookupFixture(8, false)
	binary.LittleEndian.PutUint64(mem[0x100:], 0x1000)
	binary.LittleEndian.PutUint64(mem[0x108:], ^uint64(0))
	binary.LittleEndian.PutUint32(mem[0x110:], 1)
	binary.LittleEndian.PutUint32(mem[0x1000:], 1)
	if _, err := linuxModuleELFSymbol(n, 0x100, 0, 0xffffffffffff); err == nil {
		t.Fatal("string address overflow accepted")
	}
}

func FuzzLinuxModuleELFSymbols(f *testing.F) {
	f.Add(uint64(0x400), uint64(0x600), uint32(2), uint32(1), false, false)
	f.Add(^uint64(0), ^uint64(0), ^uint32(0), ^uint32(0), true, true)
	f.Fuzz(func(t *testing.T, symtab, strtab uint64, count, nameOffset uint32, narrow, big bool) {
		width := 8
		if narrow {
			width = 4
		}
		mem, _, n := moduleLookupFixture(width, big)
		mem = mem[:2048]
		n.e.Kernel = mem
		n.e.Objects.Layer = mem
		var order binary.ByteOrder = binary.LittleEndian
		if big {
			order = binary.BigEndian
		}
		if narrow {
			order.PutUint32(mem[0x100:], uint32(symtab))
			order.PutUint32(mem[0x108:], uint32(strtab))
		} else {
			order.PutUint64(mem[0x100:], symtab)
			order.PutUint64(mem[0x108:], strtab)
		}
		order.PutUint32(mem[0x110:], count)
		order.PutUint32(mem[0x400:], nameOffset)
		if _, err := linuxModuleELFSymbol(n, 0x100, 0x1234, 0xffffffffffff); err == nil && len(n.fields) > 8198 {
			t.Fatal("unbounded symbol capture")
		}
	})
}
