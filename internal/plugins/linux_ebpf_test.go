package plugins

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func ebpfEnvironment(width int, layout string) (plugin.Environment, flatMemory, func(uint64, uint64)) {
	ptr := symbols.TypeRef{Kind: "pointer"}
	u32 := symbols.TypeRef{Kind: "base", Name: "u32"}
	byteRef := symbols.TypeRef{Kind: "base", Name: "u8"}
	f := func(offset uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: typ}
	}
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: uint64(width), Endian: "little"}, "u32": {Kind: "int", Size: 4, Endian: "little"}, "u8": {Kind: "int", Size: 1, Endian: "little"}}, Types: map[string]symbols.Type{}, Enums: map[string]symbols.Enumeration{"bpf_prog_type": {Size: 4, Base: "u32", Constants: map[string]json.Number{"BPF_PROG_TYPE_SOCKET_FILTER": "1", "BPF_PROG_TYPE_KPROBE": "2"}}}, Symbols: map[string]symbols.Symbol{"prog_idr": {Address: 0x100}}}
	root, node, head, tag := "radix_tree_root", "radix_tree_node", "rnode", uint64(1)
	if layout == "xarray" {
		root, node, head, tag = "xarray", "xa_node", "xa_head", 2
	}
	table.Types["idr"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"idr_rt": f(8, symbols.TypeRef{Kind: "struct", Name: root}), "idr_base": f(0, u32)}}
	table.Types[root] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{head: f(0, ptr)}}
	table.Types[node] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"shift": f(0, u32), "slots": f(16, symbols.TypeRef{Kind: "array", Count: 4, Subtype: &ptr})}}
	table.Types["bpf_prog"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"type": f(0, symbols.TypeRef{Kind: "enum", Name: "bpf_prog_type"}), "tag": f(4, symbols.TypeRef{Kind: "array", Count: 8, Subtype: &byteRef}), "aux": f(16, ptr)}}
	table.Types["bpf_prog_aux"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"name": f(8, symbols.TypeRef{Kind: "array", Count: 16, Subtype: &byteRef}), "prog_type": f(0, symbols.TypeRef{Kind: "enum", Name: "bpf_prog_type"})}}
	data := make(flatMemory, 0x10000)
	put := func(at, value uint64) {
		if width == 4 {
			binary.LittleEndian.PutUint32(data[at:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(data[at:], value)
		}
	}
	put(0x108, 0x1000|tag)
	put(0x1010, 0x2000)
	put(0x1010+uint64(width)*2, 0x2100)
	if layout == "direct" {
		put(0x108, 0x2000)
	}
	if layout == "empty" {
		put(0x108, 0)
	}
	if layout == "legacy" {
		table.Types["idr"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"cur": f(0, u32), "top": f(8, ptr)}}
		table.Types["idr_layer"] = symbols.Type{Kind: "struct", Size: 16 + 256*uint64(width), Fields: map[string]symbols.Field{"layer": f(0, u32), "ary": f(16, symbols.TypeRef{Kind: "array", Count: 256, Subtype: &ptr})}}
		put(0x100, 64)
		put(0x108, 0x1000)
		clear(data[0x1000:0x1800])
		put(0x1010+uint64(width), 0x2000)
		put(0x1010+uint64(width)*32, 0x2100)
	}
	binary.LittleEndian.PutUint32(data[0x2000:], 1)
	binary.LittleEndian.PutUint32(data[0x2100:], 2)
	for i := 0; i < 8; i++ {
		data[0x2004+i] = byte(i)
		data[0x2104+i] = 0xff - byte(i)
	}
	put(0x2010, 0x3000)
	put(0x2110, 0x3100)
	copy(data[0x3008:], "trace_one\x00")
	copy(data[0x3108:], "trace_two\x00")
	arch := "x64"
	if width == 4 {
		arch = "x86"
	}
	e := plugin.Environment{Kernel: data, Physical: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}, Architecture: arch, OS: "linux"}
	return e, data, put
}

func ebpfParams() map[string]string {
	return map[string]string{"max-nodes": "100", "max-programs": "100"}
}
func TestLinuxEBPFLayoutsMetadataAndIndexProof(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, layout := range []string{"radix", "xarray", "legacy", "direct", "empty"} {
			t.Run(fmt.Sprintf("%d/%s", width, layout), func(t *testing.T) {
				e, data, _ := ebpfEnvironment(width, layout)
				programs, selected, reads, summaries := 0, 0, 0, 0
				err := linuxEBPF(context.Background(), e, ebpfParams(), func(row evidence.Row) error {
					switch row.Cells["RecordType"].String() {
					case "ebpf_program":
						programs++
						if row.Cells["Selected"].Data == true {
							selected++
						}
						if row.Cells["Name"].String() == "" || row.Cells["Type"].Kind != "string" || row.Cells["Tag"].Kind != "string" {
							t.Fatal(row)
						}
					case "idr_read":
						reads++
						fields := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
						at, _ := fields["Address"].Uint()
						raw := fields["Raw"].Data.([]byte)
						if string(raw) != string(data[at:at+uint64(len(raw))]) {
							t.Fatal("read proof mismatch")
						}
					case "idr_summary":
						summaries++
						fields := row.Cells["Coverage"].Data.(map[string]evidence.Value)
						if fields["Completed"].Data != true {
							t.Fatal(row)
						}
						entries, _ := fields["Entries"].Uint()
						if entries != uint64(programs) {
							t.Fatal("IDR stats lost", fields)
						}
					default:
						t.Fatal(row)
					}
					return nil
				})
				want, wantSelected := 2, 2
				if layout == "direct" {
					want, wantSelected = 1, 1
				}
				if layout == "empty" {
					want, wantSelected = 0, 0
				}
				if layout == "legacy" {
					wantSelected = 1
				}
				if err != nil || programs != want || selected != wantSelected || reads == 0 || summaries != 1 {
					t.Fatal(err, programs, selected, reads, summaries)
				}
			})
		}
	}
}
func TestLinuxEBPFUnavailableVersusReadErrorsAndLegacyType(t *testing.T) {
	for _, scenario := range []string{"missing-fields", "null-aux", "aux-type", "unknown-type", "name-hole", "tag-hole", "index-hole", "cycle", "node-limit", "entry-limit", "bad-array", "bad-aux"} {
		t.Run(scenario, func(t *testing.T) {
			e, _, put := ebpfEnvironment(8, "xarray")
			table := e.Symbols.(*symbols.ISF)
			params := ebpfParams()
			failed := true
			switch scenario {
			case "missing-fields":
				p := table.Types["bpf_prog"]
				delete(p.Fields, "tag")
				delete(p.Fields, "type")
				delete(p.Fields, "aux")
				table.Types["bpf_prog"] = p
				failed = false
			case "null-aux":
				put(0x2010, 0)
				put(0x2110, 0)
				failed = false
			case "aux-type":
				p := table.Types["bpf_prog"]
				delete(p.Fields, "type")
				table.Types["bpf_prog"] = p
				put(0x3000, 1)
				put(0x3100, 2)
				failed = false
			case "unknown-type":
				put(0x2000, 99)
			case "name-hole":
				put(0x2010, 0xfff0)
			case "tag-hole":
				p := table.Types["bpf_prog"]
				p.Size = 0x10000
				p.Fields["tag"] = symbols.Field{Offset: 0xe000, Type: p.Fields["tag"].Type}
				table.Types["bpf_prog"] = p
			case "index-hole":
				put(0x108, 0xfff2)
			case "cycle":
				put(0x1000, 2)
				put(0x1010, 0x1002)
			case "node-limit":
				put(0x1000, 2)
				put(0x1010, 0x1102)
				put(0x1100, 0)
				put(0x1110, 0x2000)
				params["max-nodes"] = "1"
			case "entry-limit":
				params["max-programs"] = "1"
			case "bad-aux":
				p := table.Types["bpf_prog"]
				field := p.Fields["aux"]
				field.Type = symbols.TypeRef{Kind: "base", Name: "u32"}
				p.Fields["aux"] = field
				table.Types["bpf_prog"] = p
			case "bad-array":
				p := table.Types["bpf_prog"]
				field := p.Fields["tag"]
				field.Type.Count = 0
				p.Fields["tag"] = field
				table.Types["bpf_prog"] = p
			}
			programs, summaryErrors := 0, 0
			err := linuxEBPF(context.Background(), e, params, func(r evidence.Row) error {
				if r.Cells["RecordType"].String() == "ebpf_program" {
					programs++
				}
				if r.Cells["RecordType"].String() == "idr_summary" && r.Cells["Error"].Error != "" {
					summaryErrors++
				}
				return nil
			})
			if (err != nil) != failed || failed && summaryErrors != 1 || !failed && programs != 2 {
				t.Fatal(err, programs, summaryErrors)
			}
		})
	}
}
func TestLinuxEBPFLegacyRejectsScalarTop(t *testing.T) {
	e, _, _ := ebpfEnvironment(8, "legacy")
	table := e.Symbols.(*symbols.ISF)
	layout := table.Types["idr"]
	field := layout.Fields["top"]
	field.Type = symbols.TypeRef{Kind: "base", Name: "u32"}
	layout.Fields["top"] = field
	table.Types["idr"] = layout
	programs := 0
	err := linuxEBPF(context.Background(), e, ebpfParams(), func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "ebpf_program" {
			programs++
		}
		return nil
	})
	if err == nil || programs != 0 {
		t.Fatal("scalar field was dereferenced as IDR pointer", err, programs)
	}
}

func TestLinuxEBPFCancellationAndEmitterFailure(t *testing.T) {
	for _, kind := range []string{"idr_read", "ebpf_program", "idr_summary"} {
		t.Run(kind, func(t *testing.T) {
			e, _, _ := ebpfEnvironment(8, "xarray")
			stop := errors.New("output stopped")
			failed := false
			err := linuxEBPF(context.Background(), e, ebpfParams(), func(row evidence.Row) error {
				if failed {
					t.Fatal("output after emitter failure")
				}
				if row.Cells["RecordType"].String() == kind {
					failed = true
					return stop
				}
				return nil
			})
			if !errors.Is(err, stop) || !failed {
				t.Fatal(err)
			}
		})
	}
	e, _, _ := ebpfEnvironment(8, "xarray")
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := linuxEBPF(ctx, e, ebpfParams(), func(evidence.Row) error { calls++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
}
func FuzzLinuxEBPFIDR(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0}, byte(0))
	f.Add([]byte{2, 0x10, 0, 0}, byte(1))
	f.Add([]byte{64, 0, 0, 0}, byte(2))
	f.Fuzz(func(t *testing.T, b []byte, kind byte) {
		e, data, _ := ebpfEnvironment(8, []string{"xarray", "radix", "legacy"}[int(kind)%3])
		copy(data[0x100:0x120], b)
		if len(b) > 32 {
			copy(data[0x1000:0x1100], b[32:])
		}
		_, _ = walkLinuxIDR(context.Background(), e.Objects, 0x100, 16, 32, func(linuxIDREntry) error { return nil })
	})
}
