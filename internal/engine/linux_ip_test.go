package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func ipFixture(t *testing.T, arch, fault string, addresses, cycle int) testfixture.Fixture {
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
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
	char := symbols.TypeRef{Kind: "base", Name: "char"}
	array := func(count uint64) symbols.TypeRef {
		return symbols.TypeRef{Kind: "array", Count: count, Subtype: &char}
	}
	strct := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	field := func(offset uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: typ}
	}
	table.Bases["i32"] = symbols.Type{Kind: "int", Size: 4, Endian: "little", Signed: true}
	table.Types["net"] = symbols.Type{Kind: "struct", Size: 80, Fields: map[string]symbols.Field{"list": field(0, strct("list_head")), "dev_base_head": field(32, strct("list_head")), "proc_inum": field(64, u32)}}
	table.Types["net_device"] = symbols.Type{Kind: "struct", Size: 144, Fields: map[string]symbols.Field{"dev_list": field(0, strct("list_head")), "name": field(16, array(16)), "addr_len": field(32, u32), "perm_addr": field(36, array(8)), "dev_addr": field(48, ptr), "operstate": field(56, char), "mtu": field(60, u32), "tx_queue_len": field(64, u32), "qdisc": field(72, ptr), "flags": field(80, u32), "gflags": field(84, u32), "state": field(88, u64), "nd_net": field(96, ptr), "ifindex": field(104, symbols.TypeRef{Kind: "base", Name: "i32"}), "ip_ptr": field(112, ptr), "ip6_ptr": field(120, ptr)}}
	table.Types["Qdisc"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"ops": field(8, ptr)}}
	table.Types["Qdisc_ops"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"id": field(0, array(16))}}
	table.Types["in_device"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"ifa_list": field(8, ptr)}}
	table.Types["in_ifaddr"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"ifa_next": field(0, ptr), "ifa_address": field(8, u32), "ifa_prefixlen": field(12, u32), "ifa_scope": field(16, u32)}}
	table.Types["inet6_dev"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"addr_list": field(8, strct("list_head"))}}
	table.Types["inet6_ifaddr"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"if_list": field(0, strct("list_head")), "addr": field(16, strct("in6_addr")), "prefix_len": field(32, u32), "scope": field(36, u32)}}
	table.Types["in6_addr"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"in6_u": field(0, symbols.TypeRef{Kind: "union", Name: "in6_union"})}}
	table.Types["in6_union"] = symbols.Type{Kind: "union", Size: 16, Fields: map[string]symbols.Field{"u6_addr32": field(0, symbols.TypeRef{Kind: "array", Count: 4, Subtype: &u32})}}
	if table.Enums == nil {
		table.Enums = map[string]symbols.Enumeration{}
	}
	table.Enums["netdev_state_t"] = symbols.Enumeration{Size: 4, Base: "u32", Constants: map[string]json.Number{"__LINK_STATE_START": "0", "__LINK_STATE_NOCARRIER": "1", "__LINK_STATE_DORMANT": "2"}}
	table.Enums["rt_scope_t"] = symbols.Enumeration{Size: 4, Base: "u32", Constants: map[string]json.Number{"RT_SCOPE_UNIVERSE": "0", "RT_SCOPE_HOST": "254", "RT_SCOPE_LINK": "253"}}
	table.Symbols["net_namespace_list"] = symbols.Symbol{Address: 0x1d000}
	word := func(at, v uint64) { binary.LittleEndian.PutUint32(data[at:], uint32(v)) }
	pointer := func(at, v uint64) {
		if table.PointerSize() == 4 {
			word(at, v)
		} else {
			binary.LittleEndian.PutUint64(data[at:], v)
		}
	}
	list := func(at, next, prev uint64) { pointer(at, next); pointer(at+uint64(table.PointerSize()), prev) }
	list(0x1d000, 0xc000, 0xc000)
	list(0xc000, 0x1d000, 0x1d000)
	list(0xc020, 0xd000, 0xd100)
	list(0xd000, 0xd100, 0xc020)
	list(0xd100, 0xc020, 0xd000)
	word(0xc040, 42)
	for i, a := range []uint64{0xd000, 0xd100} {
		copy(data[a+16:], fmt.Sprintf("eth%d", i))
		word(a+32, 6)
		copy(data[a+36:], []byte{1, 2, 3, 4, 5, byte(i + 6)})
		pointer(a+48, 0xe200)
		data[a+56] = 6
		word(a+60, 1500)
		word(a+64, 1000)
		pointer(a+72, 0xe000)
		word(a+80, 0x1103)
		binary.LittleEndian.PutUint64(data[a+88:], 1)
		pointer(a+96, 0xc000)
		word(a+104, uint64(i+1))
	}
	pointer(0xe008, 0xe100)
	copy(data[0xe100:], "fq_codel")
	copy(data[0xe200:], []byte{9, 8, 7, 6, 5, 4})
	pointer(0xd070, 0xf000)
	pointer(0xd078, 0xf100)
	pointer(0xf008, 0)
	if addresses > 0 {
		pointer(0xf008, 0x1b000)
	}
	for i := 0; i < addresses; i++ {
		a := uint64(0x1b000 + i*32)
		next := uint64(0)
		if i+1 < addresses {
			next = a + 32
		} else if cycle >= 0 {
			next = uint64(0x1b000 + cycle*32)
		}
		pointer(a, next)
		word(a+8, 0x0100007f)
		word(a+12, 8)
		word(a+16, 254)
	}
	list(0xf108, 0x1a000, 0x1a000)
	list(0x1a000, 0xf108, 0xf108)
	data[0x1a01f] = 1
	word(0x1a020, 128)
	word(0x1a024, 0x10)
	switch fault {
	case "modern":
		table.Types["possible_net_t"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"net": field(0, ptr)}}
		table.Types["net_device"].Fields["nd_net"] = field(96, strct("possible_net_t"))
		delete(table.Types["net"].Fields, "proc_inum")
		table.Types["net"].Fields["ns"] = field(64, strct("ns_common"))
		table.Types["ns_common"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"inum": field(0, u32)}}
	case "missing-inode":
		delete(table.Types["net"].Fields, "proc_inum")
	case "zero-inode":
		word(0xc040, 0)
	case "device-namespace":
		pointer(0xd060, 0xe300)
		word(0xe340, 99)
	case "signed-prefix":
		table.Types["inet6_ifaddr"].Fields["prefix_len"] = field(32, symbols.TypeRef{Kind: "base", Name: "i32"})
		word(0x1a020, 0xffffffff)
		word(0xd068, 0xffffffff)
	case "big-endian-ip6":
		table.Bases["u32be"] = symbols.Type{Kind: "int", Size: 4, Endian: "big"}
		subtype := symbols.TypeRef{Kind: "base", Name: "u32be"}
		table.Types["in6_union"].Fields["u6_addr32"] = field(0, symbols.TypeRef{Kind: "array", Count: 4, Subtype: &subtype})
		clear(data[0x1a010:0x1a020])
		copy(data[0x1a010:], []byte{1, 2, 3, 4})
	case "unknown-scope":
		word(0x1b010, 255)
	case "no-permanent":
		delete(table.Types["net_device"].Fields, "perm_addr")
	case "zero-mac":
		word(0xd020, 0)
	case "malformed-permanent":
		table.Types["net_device"].Fields["perm_addr"] = field(500, array(8))
	case "malformed-inode":
		table.Types["net"].Fields["proc_inum"] = field(500, u32)
	case "zero-permanent":
		clear(data[0xd024:0xd02c])
	case "partial-mac":
		clear(data[0xd024:0xd02c])
		pointer(0xd030, 0x1fffe)
	case "huge-mac":
		word(0xd020, 4097)
	case "bad-qdisc":
		pointer(0xd048, 0x300000)
	case "bad-namespace":
		pointer(0xd060, 0x300000)
	case "ambiguous-scope":
		table.Enums["rt_scope_t"].Constants["RT_SCOPE_LINK"] = "254"
	case "wrong-ip6-array":
		table.Types["in6_union"].Fields["u6_addr32"] = field(0, array(16))
	case "bad-index":
		delete(table.Types["net_device"].Fields, "ifindex")
	case "bad-ip4-root":
		pointer(0xd070, 0x300000)
	case "bad-ip6-root":
		pointer(0xd078, 0x300000)
	case "legacy-ip6":
		table.Types["inet6_dev"].Fields["addr_list"] = field(8, ptr)
	case "bad-dev-backlink":
		pointer(0xd000+uint64(table.PointerSize()), 0)
	case "bad-net-tail":
		pointer(0x1d000+uint64(table.PointerSize()), 0)
	case "no-state-enum":
		delete(table.Enums, "netdev_state_t")
	case "no-promisc":
		table.Enums["net_device_flags"] = symbols.Enumeration{Size: 4, Base: "u32", Constants: map[string]json.Number{"IFF_UP": "1"}}
	case "bad-flag-enum":
		table.Enums["net_device_flags"] = symbols.Enumeration{Base: "u32", Constants: map[string]json.Number{"IFF_PROMISC": "256"}}
	case "bad-scope-enum":
		delete(table.Enums, "rt_scope_t")
	case "invalid-oper":
		data[0xd038] = 255
	case "bad-ip4-next":
		pointer(0x1b000, 0x300000)
	case "empty":
		list(0xc020, 0xc020, 0xc020)
	}
	raw, err := table.Encode()
	if fault == "malformed-permanent" || fault == "malformed-inode" || fault == "bad-flag-enum" {
		raw, err = json.Marshal(table)
	}
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

func TestLinuxIPNativeReaders(t *testing.T) {
	for _, arch := range []string{"control", "x86", "pae"} {
		for _, fault := range []string{"", "modern", "missing-inode", "zero-inode", "device-namespace", "zero-permanent", "no-permanent", "zero-mac", "signed-prefix", "big-endian-ip6", "unknown-scope", "invalid-oper", "empty"} {
			t.Run(arch+"/"+fault, func(t *testing.T) {
				f := ipFixture(t, arch, fault, 1, -1)
				mode := arch
				if mode == "control" {
					mode = "x64"
				}
				e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", CaseDir: t.TempDir(), Offline: true})
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				ctx := context.Background()
				for _, name := range []string{"linux.ip.link", "linux.ip.addr"} {
					var got []evidence.Row
					result, err := e.Run(ctx, name, nil, engine.RunOptions{Emit: func(r evidence.Row) error { got = append(got, r); return nil }})
					if err != nil || result.Task.State != "completed" {
						t.Fatal(result, err)
					}
					entities := 0
					for _, r := range got {
						if err := r.Verify(); err != nil {
							t.Fatal(err)
						}
						kind := r.Cells["RecordType"].String()
						if kind == "diagnostic" {
							t.Fatal(r)
						}
						if kind != "interface" && kind != "address" {
							continue
						}
						entities++
						if r.Cells["Interface"].String() == "eth0" {
							ns := "NS"
							if name == "linux.ip.addr" {
								ns = "NetNS"
							}
							if fault == "missing-inode" || fault == "zero-inode" {
								if r.Cells[ns].Kind != "missing" {
									t.Fatal(r)
								}
							} else {
								want := uint64(42)
								if fault == "device-namespace" {
									want = 99
								}
								value, err := r.Cells[ns].Uint()
								if err != nil || value != want {
									t.Fatal(r, err)
								}
							}
							if (fault == "zero-permanent" || fault == "no-permanent") && r.Cells["MAC"].String() != "09:08:07:06:05:04" {
								t.Fatal(r)
							}
							if name == "linux.ip.addr" && r.Cells["Family"].String() == "IPv6" {
								if fault == "signed-prefix" && (r.Cells["Prefix"].String() != "-1" || r.Cells["Index"].String() != "-1") {
									t.Fatal(r)
								}
								if fault == "big-endian-ip6" && r.Cells["IP"].String() != "403:201::" {
									t.Fatal(r)
								}
							}
							if name == "linux.ip.addr" && fault == "unknown-scope" && r.Cells["Family"].String() == "IPv4" && r.Cells["Scope Type"].String() != "unknown" {
								t.Fatal(r)
							}
							if fault == "invalid-oper" && r.Cells["State"].Reason != "state_unparsable" {
								t.Fatal(r)
							}
						}
					}
					want := 2
					if fault == "empty" {
						want = 0
					}
					if entities != want {
						t.Fatal(entities, want)
					}
					cached, err := e.Run(ctx, name, nil, engine.RunOptions{})
					if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
						t.Fatal(cached, err)
					}
				}
			})
		}
	}
}

func TestLinuxIPFailuresAndCancellation(t *testing.T) {
	for _, tc := range []struct{ fault, name string }{{"partial-mac", "link"}, {"huge-mac", "link"}, {"bad-qdisc", "link"}, {"bad-namespace", "link"}, {"no-state-enum", "link"}, {"bad-dev-backlink", "link"}, {"bad-net-tail", "link"}, {"bad-index", "addr"}, {"bad-ip4-root", "addr"}, {"bad-ip6-root", "addr"}, {"legacy-ip6", "addr"}, {"no-promisc", "addr"}, {"bad-scope-enum", "addr"}, {"ambiguous-scope", "addr"}, {"wrong-ip6-array", "addr"}, {"bad-ip4-next", "addr"}} {
		t.Run(tc.fault, func(t *testing.T) {
			e := openPsaux(t, ipFixture(t, "control", tc.fault, 1, -1))
			count := 0
			result, err := e.Run(context.Background(), "linux.ip."+tc.name, nil, engine.RunOptions{Emit: func(r evidence.Row) error { count++; return nil }})
			if err == nil || result.Task.State != "failed" || count == 0 {
				t.Fatal(result, err, count)
			}
		})
	}
	t.Run("bound", func(t *testing.T) {
		e := openPsaux(t, ipFixture(t, "control", "", 1, -1))
		result, err := e.Run(context.Background(), "linux.ip.addr", map[string]string{"max-nodes": "1"}, engine.RunOptions{})
		if err == nil || result.Task.State != "failed" {
			t.Fatal(result, err)
		}
	})
	t.Run("output-error", func(t *testing.T) {
		e := openPsaux(t, ipFixture(t, "control", "", 1, -1))
		sentinel := errors.New("output stopped")
		_, err := e.Run(context.Background(), "linux.ip.addr", nil, engine.RunOptions{Emit: func(r evidence.Row) error { return sentinel }})
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	})
	for _, name := range []string{"linux.ip.link", "linux.ip.addr"} {
		t.Run(name, func(t *testing.T) {
			e := openPsaux(t, ipFixture(t, "control", "", 1, -1))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			emitted := 0
			result, err := e.Run(ctx, name, nil, engine.RunOptions{Emit: func(r evidence.Row) error { emitted++; cancel(); return nil }})
			if !errors.Is(err, context.Canceled) || emitted != 1 || result.Task.State != "canceled" {
				t.Fatal(result, err, emitted)
			}
			rows, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(rows) != 1 {
				t.Fatal(len(rows), err)
			}
		})
	}
}

func TestLinuxIPPinnedIPv4Chains(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-ip-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Chains []struct {
			Size, Cycle int
			Indices     []int
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	for _, tc := range oracle.Chains {
		t.Run(fmt.Sprintf("%d/%d", tc.Size, tc.Cycle), func(t *testing.T) {
			e := openPsaux(t, ipFixture(t, "control", "", tc.Size, tc.Cycle))
			var got []uint64
			_, err := e.Run(context.Background(), "linux.ip.addr", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
				if r.Cells["RecordType"].String() == "address" && r.Cells["Family"].String() == "IPv4" {
					v, _ := r.Cells["AddressOffset"].Uint()
					got = append(got, (v-0x1b000)/32)
				}
				return nil
			}})
			if len(got) != len(tc.Indices) {
				t.Fatal(len(got), len(tc.Indices), err)
			}
			for i, v := range got {
				if v != uint64(tc.Indices[i]) {
					t.Fatal(got, tc.Indices)
				}
			}
			if (tc.Cycle >= 0 || tc.Size > 129) != (err != nil) {
				t.Fatal(err)
			}
		})
	}
}

func TestLinuxIPRejectMalformedSymbolExtents(t *testing.T) {
	for _, fault := range []string{"malformed-permanent", "malformed-inode", "bad-flag-enum"} {
		t.Run(fault, func(t *testing.T) {
			f := ipFixture(t, "control", fault, 1, -1)
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, OS: "linux", CaseDir: t.TempDir(), Offline: true})
			if err == nil {
				e.Close()
				t.Fatal("malformed symbol extent accepted")
			}
		})
	}
}
