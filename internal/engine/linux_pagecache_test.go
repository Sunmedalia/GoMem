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

const testVmemmap = uint64(0xffffea0000000000)

func linuxCacheFixture(t *testing.T, scenario string) testfixture.Fixture {
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
	st := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: n} }
	field := func(o uint64, r symbols.TypeRef) symbols.Field { return symbols.Field{Offset: o, Type: r} }
	table.Types["atomic_t"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"counter": field(0, base("i64"))}}
	table.Types["inode"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{"i_ino": field(0, base("u64")), "i_count": field(8, st("atomic_t")), "i_mode": field(16, base("u16")), "i_size": field(24, base("i64")), "i_mapping": field(32, ptr)}}
	table.Types["address_space"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"nrpages": field(0, base("u64")), "page_tree": field(8, st("radix_tree_root"))}}
	table.Types["radix_tree_root"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"height": field(0, base("u32")), "rnode": field(8, ptr)}}
	table.Types["radix_tree_node"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{"height": field(0, base("u32")), "slots": field(8, symbols.TypeRef{Kind: "array", Count: 4, Subtype: &ptr})}}
	table.Types["page"] = symbols.Type{Kind: "struct", Size: 56, Fields: map[string]symbols.Field{"flags": field(0, base("u64")), "mapping": field(8, ptr), "index": field(16, base("u64"))}}
	table.Enums = map[string]symbols.Enumeration{"pageflags": {Base: "u32", Size: 4, Constants: map[string]json.Number{"PG_uptodate": "3", "PG_lru": "5"}}}
	table.Symbols["mem_section"] = symbols.Symbol{Address: 0x19000}
	table.Symbols["max_pfn"] = symbols.Symbol{Address: 0x19008}
	put(0x19008, 64)
	put(0x1000+((testVmemmap>>39)&511)*8, 0x2003)
	put(0x15000, 123)
	put(0x15008, 1)
	put(0x15010, 0100644)
	put(0x15018, 3*4096+5)
	put(0x15020, 0x16000)
	clear(data[0x17000:0x17028])
	put(0x16000, 2)
	put(0x16008, 1)
	put(0x16010, 0x17001)
	put(0x17000, 1)
	for i, pfn := range []uint64{30, 31} {
		index := uint64(1 + i*2)
		page := pfn * 56
		put(page, 40)
		put(page+8, 0x16000)
		put(page+16, index)
		put(0x17008+index*8, testVmemmap+page)
		for j := pfn * 4096; j < (pfn+1)*4096; j++ {
			data[j] = byte(j % 251)
		}
	}
	switch scenario {
	case "xarray", "folio", "exceptional", "sibling":
		root := table.Types["radix_tree_root"]
		delete(root.Fields, "height")
		delete(root.Fields, "rnode")
		root.Fields["xa_head"] = field(8, ptr)
		table.Types["radix_tree_root"] = root
		node := table.Types["radix_tree_node"]
		delete(node.Fields, "height")
		node.Fields["shift"] = field(0, base("u32"))
		table.Types["xa_node"] = node
		put(0x16010, 0x17002)
		put(0x17000, 0)
		if scenario == "folio" {
			put(0x17000, 2)
			put(30*56+16, 4)
			put(31*56+16, 12)
		}
		if scenario == "sibling" {
			put(0x17018, 6)
		}
		if scenario == "exceptional" {
			put(0x17018, 0x101)
		}
	case "tree-error":
		put(0x17020, 0x18001)
	case "mapping":
		put(30*56+8, 0x16008)
	case "index":
		put(30*56+16, 2)
	case "flags":
		delete(table.Enums, "pageflags")
	case "payload":
		data = data[:0x1f002]
	case "empty", "uncached":
		put(0x16010, 0)
		put(0x16008, 0)
		put(0x16000, 0)
		if scenario == "empty" {
			put(0x15018, 0)
		}
	case "direct", "pfn-zero":
		pfn := uint64(30)
		if scenario == "pfn-zero" {
			pfn = 0
		}
		put(pfn*56, 40)
		put(pfn*56+8, 0x16000)
		put(pfn*56+16, 0)
		put(0x16010, testVmemmap+pfn*56)
		put(0x16008, 0)
		put(0x16000, 1)
		put(0x15018, 5)
	case "unaligned":
		put(0x17010, testVmemmap+30*56+8)
	case "max-pfn":
		put(0x19008, 30)
	case "dynamic":
		table.Symbols["vmemmap_base"] = symbols.Symbol{Address: 0x19010}
		put(0x19010, testVmemmap)
	case "flatmem":
		delete(table.Symbols, "mem_section")
		table.Symbols["mem_map"] = symbols.Symbol{Address: 0x19010}
		put(0x19010, testVmemmap)
	case "unsupported":
		delete(table.Symbols, "mem_section")
	case "nonregular":
		put(0x15010, 0040755)
	case "negative-size":
		put(0x15018, ^uint64(0))
	case "negative-count":
		put(0x15008, ^uint64(0))
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
func TestLinuxPageCacheRecoveryEvidence(t *testing.T) {
	for _, scenario := range []string{"normal", "xarray", "direct", "pfn-zero", "dynamic", "flatmem", "empty", "uncached", "exceptional", "payload", "tree-error", "mapping", "index", "flags", "unaligned", "max-pfn", "folio", "sibling"} {
		t.Run(scenario, func(t *testing.T) {
			f := linuxCacheFixture(t, scenario)
			e := openLinuxELF(t, f, true)
			ctx := context.Background()
			var rows []evidence.Row
			result, err := e.Run(ctx, "linux.inodepages", map[string]string{"inode": "0x15000", "dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
			failed := strings.Contains(" payload tree-error mapping index flags unaligned max-pfn folio sibling ", " "+scenario+" ")
			if failed != (err != nil) || failed != (result.Task.State == "failed") {
				t.Fatal(result, err)
			}
			if len(rows) == 0 || rows[len(rows)-1].Cells["RecordType"].String() != "summary" {
				t.Fatal(rows)
			}
			files, er := e.Store.Artifacts(ctx, result.Task.ID)
			if er != nil || len(files) != 1 {
				t.Fatal(files, er)
			}
			a := files[0]
			data, er := os.ReadFile(filepath.Join(e.Store.Dir, a.Path))
			if er != nil {
				t.Fatal(er)
			}
			original, _ := os.ReadFile(f.Image)
			switch scenario {
			case "empty":
				if len(data) != 0 || a.MissingBytes != "0" || a.State != "completed" {
					t.Fatal(a)
				}
			case "direct", "pfn-zero":
				offset := 0x1e000
				if scenario == "pfn-zero" {
					offset = 0
				}
				if !bytes.Equal(data, original[offset:offset+5]) || a.MissingBytes != "0" {
					t.Fatal(a)
				}
			default:
				if len(data) != 12293 || !bytes.Equal(data[:4096], make([]byte, 4096)) {
					t.Fatal(a)
				}
				if scenario == "normal" || scenario == "xarray" || scenario == "dynamic" || scenario == "flatmem" || scenario == "exceptional" {
					if !bytes.Equal(data[4096:8192], original[0x1e000:0x1f000]) || !bytes.Equal(data[12288:], original[0x1f000:0x1f005]) || a.MissingBytes != "8192" {
						t.Fatal(a)
					}
				}
				if scenario == "payload" && (!bytes.Equal(data[12288:12290], original[0x1f000:]) || !bytes.Equal(data[12290:], []byte{0, 0, 0})) {
					t.Fatal(a)
				}
			}
			raw, er := os.ReadFile(filepath.Join(e.Store.Dir, a.GapsPath))
			if er != nil {
				t.Fatal(er)
			}
			if scenario == "payload" && !bytes.Contains(raw, []byte(`"address":"0x1f002"`)) {
				t.Fatal("lost physical source address", string(raw))
			}
			if failed && scenario != "payload" && !bytes.Contains(raw, []byte("coverage_unknown_due_to_cache_error")) {
				t.Fatal(string(raw))
			}
			if er = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); er != nil {
				t.Fatal(er)
			}
			if !failed {
				again, er := e.Run(ctx, "linux.inodepages", map[string]string{"inode": "0x15000", "dump": "true"}, engine.RunOptions{})
				if er != nil || !again.Reused {
					t.Fatal(again, er)
				}
			}
		})
	}
}
func TestLinuxPageCacheRejectsInvalidInputsAndPropagatesOutput(t *testing.T) {
	for _, scenario := range []string{"nonregular", "negative-size", "negative-count", "unsupported", "size-limit", "no-case", "bad-inode", "zero-nodes", "entry-limit", "node-limit"} {
		t.Run(scenario, func(t *testing.T) {
			e := openLinuxELF(t, linuxCacheFixture(t, scenario), scenario != "no-case")
			p := map[string]string{"inode": "0x15000", "dump": "true"}
			switch scenario {
			case "size-limit":
				p["maxsize"] = "12292"
			case "bad-inode":
				p["inode"] = "0"
			case "zero-nodes":
				p["max-nodes"] = "0"
			case "entry-limit":
				p["max-pages"] = "1"
			case "node-limit":
				p["max-nodes"] = "1000001"
			}
			r, err := e.Run(context.Background(), "linux.inodepages", p, engine.RunOptions{})
			if err == nil || r.Task.State != "failed" {
				t.Fatal(r, err)
			}
		})
	}
	e := openLinuxELF(t, linuxCacheFixture(t, "normal"), true)
	sentinel := errors.New("consumer stopped")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := e.Run(ctx, "linux.inodepages", map[string]string{"inode": "0x15000"}, engine.RunOptions{Emit: func(evidence.Row) error { return sentinel }})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	_, err = e.Run(ctx, "linux.inodepages", map[string]string{"inode": "0x15000"}, engine.RunOptions{Emit: func(evidence.Row) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestLinuxPageCacheFlatmem32Bit(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxCacheFixture(t, "flatmem")
			table, err := symbols.Load(f.Symbols)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			pointer := table.Bases["pointer"]
			pointer.Size = 4
			table.Bases["pointer"] = pointer
			clear(data[0x1000:0x4000])
			if mode == "x86" {
				binary.LittleEndian.PutUint32(data[0x1000:], 0x83)
			} else {
				binary.LittleEndian.PutUint64(data[0x1000:], 0x2001)
				binary.LittleEndian.PutUint64(data[0x2000:], 0x83)
			}
			put := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(data[a:], v) }
			put(0x19010, 0x4000)
			clear(data[0x17008:0x17028])
			for i, pfn := range []uint64{30, 31} {
				page := pfn * 56
				copy(data[0x4000+page:0x4000+page+56], data[page:page+56])
				put(0x17008+uint64(1+i*2)*4, uint32(0x4000+page))
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
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			result, err := e.Run(context.Background(), "linux.inodepages", map[string]string{"inode": "0x15000", "dump": "true"}, engine.RunOptions{})
			if err != nil || result.Task.Rows != 3 {
				t.Fatal(result, err)
			}
		})
	}
}
