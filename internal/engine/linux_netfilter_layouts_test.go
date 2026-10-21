package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// These fixtures deliberately put a different callback in the inline hook
// entry: enumeration must follow orig_ops, including after flexible arrays.
func netfilterLayoutEngine(t *testing.T, kind string, device bool, fault string) *engine.Engine {
	return netfilterArchLayoutEngine(t, "x64", kind, device, fault)
}

func netfilterArchLayoutEngine(t *testing.T, arch, kind string, device bool, fault string) *engine.Engine {
	return netfilterConfiguredArchEngine(t, arch, 0x8500, "", func(table *symbols.ISF, data []byte) {
		if fault != "global" {
			delete(table.Symbols, "nf_hooks")
		}
		put := func(at, value uint64) {
			if table.PointerSize() == 4 {
				binary.LittleEndian.PutUint32(data[at:], uint32(value))
			} else {
				binary.LittleEndian.PutUint64(data[at:], value)
			}
		}
		word := func(at uint64, value uint32) { binary.LittleEndian.PutUint32(data[at:], value) }
		structure := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
		pointer := func(name string) symbols.TypeRef {
			typ := structure(name)
			return symbols.TypeRef{Kind: "pointer", Subtype: &typ}
		}
		array := func(typ symbols.TypeRef, count uint64) symbols.TypeRef {
			return symbols.TypeRef{Kind: "array", Count: count, Subtype: &typ}
		}
		field := func(at uint64, typ symbols.TypeRef) symbols.Field { return symbols.Field{Offset: at, Type: typ} }
		list := func(at, next, prev uint64) { put(at, next); put(at+uint64(table.PointerSize()), prev) }
		table.Types["ns_common"] = symbols.Type{Kind: "struct", Size: 4, Fields: map[string]symbols.Field{"inum": field(0, symbols.TypeRef{Kind: "base", Name: "unsigned int"})}}
		table.Types["net"] = symbols.Type{Kind: "struct", Size: 2048, Fields: map[string]symbols.Field{"list": field(0, structure("list_head")), "ns": field(16, structure("ns_common")), "nf": field(256, structure("netns_nf")), "dev_base_head": field(32, structure("list_head"))}}
		table.Symbols["net_namespace_list"] = symbols.Symbol{Address: 0x20f00}
		list(0x20f00, 0x20000, 0x20000)
		list(0x20000, 0x20f00, 0x20f00)
		word(0x20010, 42)
		table.Types["nf_hook_entry"] = symbols.Type{Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"hook": field(0, pointer("void")), "next": field(8, pointer("nf_hook_entry")), "orig_ops": field(16, pointer("nf_hook_ops"))}}
		table.Types["nf_hook_entries"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"num_hook_entries": field(0, symbols.TypeRef{Kind: "base", Name: "unsigned int"}), "hooks": field(16, array(structure("nf_hook_entry"), 0))}}
		leaf := structure("list_head")
		containerKind := kind
		if kind == "split" {
			containerKind = "entries"
		}
		if containerKind != "list" {
			leaf = pointer("nf_hook_" + containerKind)
		}
		nfFields := map[string]symbols.Field{}
		stride := uint64(table.PointerSize())
		if containerKind == "list" {
			stride = 16
		}
		if kind == "split" {
			nfFields["hooks_ipv4"] = field(0, array(leaf, 5))
		} else {
			nfFields["hooks"] = field(0, array(array(leaf, 8), 13))
		}
		table.Types["netns_nf"] = symbols.Type{Kind: "struct", Size: 1664, Fields: nfFields}
		clear(data[0x20100:0x20780])
		if containerKind == "list" {
			for i := uint64(0); i < 104; i++ {
				at := uint64(0x20100) + i*16
				list(at, at, at)
			}
		}
		slot := uint64(0x20100) + 17*stride
		if kind == "split" {
			slot = 0x20100 + stride
		}
		fill := func(slot, container, ops uint64) {
			put(ops+16, 0x8500)
			word(ops+40, 0xffffffff)
			switch containerKind {
			case "list":
				list(slot, ops, ops)
				list(ops, slot, slot)
			case "entry":
				put(slot, container)
				put(container, 0xdeadbeef)
				put(container+8, 0)
				put(container+16, ops)
			case "entries":
				put(slot, container)
				word(container, 1)
				put(container+16, 0xdeadbeef)
				put(container+40, ops)
			}
		}
		fill(slot, 0x21800, 0x22000)
		if device {
			table.Types["net_device"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"dev_list": field(0, structure("list_head")), "nf_hooks_ingress": field(32, leaf), "nf_hooks_egress": field(48, leaf)}}
			list(0x20020, 0x20800, 0x20800)
			list(0x20800, 0x20020, 0x20020)
			fill(0x20820, 0x21900, 0x22080)
			fill(0x20830, 0x21a00, 0x22100)
		}
		switch fault {
		case "device-only":
			delete(table.Types, "netns_nf")
		case "no-egress":
			delete(table.Types["net_device"].Fields, "nf_hooks_egress")
		case "namespaces":
			list(0x20f00, 0x20000, 0x20900)
			list(0x20000, 0x20900, 0x20f00)
			list(0x20900, 0x20f00, 0x20000)
			word(0x20910, 43)
			put(0x20a08, 0x21800)
		case "null-original":
			put(0x21828, 0)
		case "missing-original":
			delete(table.Types["nf_hook_entry"].Fields, "orig_ops")
		case "short-matrix":
			field := table.Types["netns_nf"].Fields["hooks"]
			field.Type.Count = 2
			table.Types["netns_nf"].Fields["hooks"] = field
		case "cycle":
			put(0x21808, 0x21800)
		case "count":
			word(0x21800, 1000001)
		case "empty":
			word(0x21800, 0)
		case "two":
			word(0x21800, 2)
			put(0x21840, 0x22000)
			put(0x21848, 0x22080)
			put(0x22090, 0x8500)
			word(0x220a8, 0xffffffff)
		case "bad-original":
			put(0x21828, 0x40000000)
		case "bad-next":
			put(0x21808, 0x40000000)
		case "bad-namespace":
			list(0x20000, 0, 0x20f00)
		}
	})
}

type netfilterOracleRow struct {
	Netns          uint64
	Proto, Hook    string
	Priority       int64
	Handler        uint64
	Module, Symbol string
	Hooked         bool
}

func TestLinuxNetfilterNamespaceAndDeviceLayouts(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-netfilter-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Commit string
		Cases  []struct {
			Bits   int
			Kind   string
			Device bool
			Rows   []netfilterOracleRow
			Reads  []uint64 `json:"original_array_reads"`
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 16 {
		t.Fatal(err)
	}

	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, kind := range []string{"list", "entry", "entries", "split"} {
			for _, device := range []bool{false, true} {
				name := arch + "/" + kind
				if device {
					name += "-device"
				}
				t.Run(name, func(t *testing.T) {
					e := netfilterArchLayoutEngine(t, arch, kind, device, "")
					var fresh, cached bytes.Buffer
					var retained []evidence.Row
					var actual []netfilterOracleRow
					var reads []uint64
					hooks, captures := 0, 0
					result, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
						retained = append(retained, row)
						typ := row.Cells["RecordType"].String()
						if typ == "netfilter_hook" {
							hooks++
							ns, nsErr := row.Cells["Net NS"].Uint()
							handler, handlerErr := row.Cells["Handler"].Uint()
							priority, priorityErr := row.Cells["Priority"].Int()
							if nsErr != nil || handlerErr != nil || priorityErr != nil {
								t.Fatal(nsErr, handlerErr, priorityErr)
							}
							actual = append(actual, netfilterOracleRow{ns, row.Cells["Proto"].String(), row.Cells["Hook"].String(), priority, handler, row.Cells["Module"].String(), row.Cells["Symbol"].String(), row.Cells["Is Hooked"].String() == "True"})
							if kind == "entries" || kind == "split" {
								fields := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
								route := fields["Route"].Data.(map[string]evidence.Value)
								at, err := route["OriginalArray"].Uint()
								if err != nil {
									t.Fatal(err)
								}
								reads = append(reads, at)
							}
							if row.Cells["Net NS"].String() != "42" || row.Cells["Namespace"].String() != "0x0000000000020000" || row.Cells["Handler"].String() != "0x0000000000008500" || row.Cells["Priority"].String() != "-1" {
								t.Fatal(row)
							}
							if hooks == 1 && (row.Cells["Proto"].String() != "IPV4" || row.Cells["Hook"].String() != "LOCAL_IN") {
								t.Fatal(row)
							}
							if hooks > 1 && (row.Cells["Proto"].String() != "NETDEV" || row.Cells["Device"].String() != "0x0000000000020800") {
								t.Fatal(row)
							}
						}
						if typ == "netfilter_hook" || typ == "netfilter_slot" || typ == "netfilter_list" || typ == "netfilter_namespace" {
							captures += verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
						}
						return json.NewEncoder(&fresh).Encode(row)
					}})
					want := 1
					if device {
						want = 3
					}
					if err != nil || result.Task.State != "completed" || hooks != want || captures < 5 {
						t.Fatal(result, err, hooks, captures)
					}
					bits := 32
					if arch == "x64" {
						bits = 64
					}
					matched := false
					for _, tc := range oracle.Cases {
						if tc.Bits == bits && tc.Kind == kind && tc.Device == device {
							matched = true
							if !reflect.DeepEqual(actual, tc.Rows) || !reflect.DeepEqual(reads, tc.Reads) && len(reads)+len(tc.Reads) > 0 {
								t.Fatal("pinned traversal differs", actual, tc.Rows, reads, tc.Reads)
							}
						}
					}
					if !matched {
						t.Fatal("missing pinned oracle")
					}
					// Verify after all emission, detecting mutation of already sealed routes.
					for _, row := range retained {
						if err := row.Verify(); err != nil {
							t.Fatal(err)
						}
					}
					replay, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
						if err := row.Verify(); err != nil {
							return err
						}
						return json.NewEncoder(&cached).Encode(row)
					}})
					if err != nil || !replay.Reused || !bytes.Equal(fresh.Bytes(), cached.Bytes()) {
						t.Fatal(replay, err)
					}
				})
			}
		}
	}

}

func TestLinuxNetfilterModernFailuresAndBounds(t *testing.T) {
	for _, tc := range []struct {
		kind, fault string
		hooks       int
		failed      bool
	}{
		{"entry", "missing-original", 0, true}, {"entry", "short-matrix", 0, true}, {"entries", "null-original", 0, true}, {"entry", "cycle", 1, true}, {"entry", "bad-next", 1, true}, {"entries", "count", 0, true}, {"entries", "empty", 0, false}, {"entries", "two", 2, false}, {"entries", "bad-original", 1, true}, {"entries", "bad-namespace", 1, true},
	} {
		t.Run(tc.kind+"/"+tc.fault, func(t *testing.T) {
			e := netfilterLayoutEngine(t, tc.kind, false, tc.fault)
			hooks, diagnostics := 0, 0
			result, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "netfilter_hook" {
					hooks++
				}
				if row.Cells["RecordType"].String() == "netfilter_error" {
					diagnostics++
					if tc.fault == "bad-next" || tc.fault == "null-original" || tc.fault == "count" {
						fields := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
						key := "OriginalOps"
						if tc.fault == "count" {
							key = "Count"
						}
						if fields[key].Kind != "structure" {
							t.Fatal("failed read lost source evidence", row)
						}
						if tc.fault == "null-original" || tc.fault == "count" {
							verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
						}
					}
				}
				return row.Verify()
			}})
			if (err != nil) != tc.failed || hooks != tc.hooks || tc.failed && result.Task.State != "failed" {
				t.Fatal(result, err, hooks, diagnostics)
			}
			if tc.failed && tc.fault != "bad-original" && diagnostics == 0 {
				t.Fatal("missing container diagnostic")
			}
		})
	}
	for _, kind := range []string{"entry", "entries", "split"} {
		t.Run(kind+"/stop", func(t *testing.T) {
			e := netfilterLayoutEngine(t, kind, true, "")
			sentinel := errors.New("stop modern hook output")
			calls := 0
			_, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "netfilter_hook" {
					calls++
					return sentinel
				}
				return nil
			}})
			if !errors.Is(err, sentinel) || calls != 1 {
				t.Fatal(err, calls)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls = 0
			_, err = e.Run(ctx, "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "netfilter_hook" {
					calls++
					cancel()
				}
				return nil
			}})
			if !errors.Is(err, context.Canceled) || calls != 1 {
				t.Fatal(err, calls)
			}
		})
	}
}

func TestLinuxNetfilterSimultaneousAndIndependentScopes(t *testing.T) {
	for _, tc := range []struct {
		kind, fault string
		device      bool
		want        int
	}{
		{"entries", "global", false, 2}, {"entries", "device-only", true, 2}, {"entries", "no-egress", true, 2}, {"split", "namespaces", false, 2},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			e := netfilterLayoutEngine(t, tc.kind, tc.device, tc.fault)
			var rows []evidence.Row
			_, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "netfilter_hook" {
					rows = append(rows, row)
				}
				return nil
			}})
			if err != nil || len(rows) != tc.want {
				t.Fatal(err, len(rows))
			}
			if rows[0].ID == rows[1].ID {
				t.Fatal("scope identities collapsed")
			}
			for _, row := range rows {
				if err := row.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			if tc.fault == "namespaces" && (rows[0].Cells["Net NS"].String() != "42" || rows[1].Cells["Net NS"].String() != "43" || rows[0].Cells["Offset"].String() != rows[1].Cells["Offset"].String()) {
				t.Fatal(rows)
			}
		})
	}
}
