package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestSuspiciousThreadNoteOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-suspicious-thread-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ExePath  string `json:"exe_path"`
			Address  uint64
			Ranges   [][]json.RawMessage
			Expected [][]string
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 721 {
		t.Fatal(len(fixture.Cases))
	}
	for i, c := range fixture.Cases {
		var ranges []analysisVADRange
		for _, row := range c.Ranges {
			var region analysisVADRange
			var path *string
			targets := []any{&region.start, &region.end, &region.protection, &path}
			for j, target := range targets {
				if err = json.Unmarshal(row[j], target); err != nil {
					t.Fatal(err)
				}
			}
			region.file = evidence.Missing("not_file_backed", nil)
			if path != nil {
				region.file = evidence.Text(*path)
			}
			ranges = append(ranges, region)
		}
		var got [][]string
		for _, note := range suspiciousThreadNotes(c.ExePath, ranges, c.Address) {
			got = append(got, []string{note.path, note.note})
		}
		if len(got) != len(c.Expected) || len(got) > 0 && !reflect.DeepEqual(got, c.Expected) {
			t.Fatalf("case %d: got %v want %v", i, got, c.Expected)
		}
	}
}

func suspiciousThreadFixture(t testing.TB) (plugin.Environment, flatMemory) {
	t.Helper()
	mem := make(flatMemory, 0x10000)
	b := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: name} }
	s := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	ptr := symbols.TypeRef{Kind: "pointer"}
	field := func(off uint64, ref symbols.TypeRef) symbols.Field { return symbols.Field{Offset: off, Type: ref} }
	typ := func(size uint64, fields map[string]symbols.Field) symbols.Type {
		return symbols.Type{Kind: "struct", Size: size, Fields: fields}
	}
	array := func(n uint64) symbols.TypeRef {
		sub := b("u8")
		return symbols.TypeRef{Kind: "array", Count: n, Subtype: &sub}
	}
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: 8}, "u8": {Kind: "int", Size: 1}, "u16": {Kind: "int", Size: 2}, "u32": {Kind: "int", Size: 4}, "u64": {Kind: "int", Size: 8}, "s64": {Kind: "int", Size: 8, Signed: true}}, Types: map[string]symbols.Type{}, Symbols: map[string]symbols.Symbol{"PsActiveProcessHead": {Address: 0x80}, "MmProtectToValue": {Address: 0x300}}}
	table.Types["_LIST_ENTRY"] = typ(16, map[string]symbols.Field{"Flink": field(0, ptr), "Blink": field(8, ptr)})
	table.Types["_LARGE_INTEGER"] = typ(8, map[string]symbols.Field{"QuadPart": field(0, b("s64"))})
	table.Types["_RTL_AVL_TREE"] = typ(8, map[string]symbols.Field{"Root": field(0, ptr)})
	table.Types["_RTL_BALANCED_NODE"] = typ(24, map[string]symbols.Field{"Left": field(0, ptr), "Right": field(8, ptr), "ParentValue": field(16, b("u64"))})
	table.Types["_EPROCESS"] = typ(80, map[string]symbols.Field{"ActiveProcessLinks": field(0, s("_LIST_ENTRY")), "UniqueProcessId": field(16, ptr), "ImageFileName": field(24, array(16)), "CreateTime": field(40, s("_LARGE_INTEGER")), "VadRoot": field(48, s("_RTL_AVL_TREE")), "SectionBaseAddress": field(56, ptr), "ThreadListHead": field(64, s("_LIST_ENTRY"))})
	table.Types["_CLIENT_ID"] = typ(16, map[string]symbols.Field{"UniqueProcess": field(0, ptr), "UniqueThread": field(8, ptr)})
	table.Types["_KTHREAD"] = typ(8, map[string]symbols.Field{"State": field(0, b("u32"))})
	table.Types["_ETHREAD"] = typ(72, map[string]symbols.Field{"ThreadListEntry": field(0, s("_LIST_ENTRY")), "Cid": field(16, s("_CLIENT_ID")), "StartAddress": field(32, ptr), "Win32StartAddress": field(40, ptr), "CreateTime": field(48, s("_LARGE_INTEGER")), "ExitTime": field(56, s("_LARGE_INTEGER")), "Tcb": field(64, s("_KTHREAD"))})
	table.Types["_FLAGS"] = typ(4, map[string]symbols.Field{"Protection": field(0, b("u32"))})
	table.Types["_VAD_UNION"] = typ(4, map[string]symbols.Field{"VadFlags": field(0, s("_FLAGS"))})
	short := map[string]symbols.Field{"VadNode": field(0, s("_RTL_BALANCED_NODE")), "StartingVpn": field(24, b("u32")), "EndingVpn": field(28, b("u32")), "u": field(32, s("_VAD_UNION"))}
	table.Types["_MMVAD_SHORT"] = typ(48, short)
	full := maps.Clone(short)
	full["Subsection"] = field(40, ptr)
	table.Types["_MMVAD"] = typ(48, full)
	table.Types["_SUBSECTION"] = typ(8, map[string]symbols.Field{"ControlArea": field(0, ptr)})
	table.Types["_CONTROL_AREA"] = typ(8, map[string]symbols.Field{"FilePointer": field(0, s("_EX_FAST_REF"))})
	table.Types["_EX_FAST_REF"] = typ(8, map[string]symbols.Field{"Value": field(0, b("u64"))})
	table.Types["_UNICODE_STRING"] = typ(16, map[string]symbols.Field{"Length": field(0, b("u16")), "MaximumLength": field(2, b("u16")), "Buffer": field(8, ptr)})
	table.Types["_FILE_OBJECT"] = typ(16, map[string]symbols.Field{"FileName": field(0, s("_UNICODE_STRING"))})
	putU64(mem, 0x80, 0x400)
	putU64(mem, 0x88, 0x400)
	putU64(mem, 0x400, 0x80)
	putU64(mem, 0x408, 0x80)
	putU64(mem, 0x410, 104)
	copy(mem[0x418:], "main.exe")
	putU64(mem, 0x428, 133000000000000000)
	putU64(mem, 0x430, 0x1000)
	putU64(mem, 0x438, 0x100000)
	putU32(mem, 0x304, 64)
	putU32(mem, 0x31c, 128)
	for i := uint64(0); i < 5; i++ {
		address := 0x1000 + i*0x200
		vpn := 0x100 + i*0x10
		tag := "Vadl"
		if i == 1 || i == 4 {
			tag = "VadS"
		}
		copy(mem[address-12:], tag)
		if i < 4 {
			putU64(mem, address+8, address+0x200)
		}
		if i > 0 {
			putU64(mem, address+16, address-0x200)
		}
		putU32(mem, address+24, uint32(vpn))
		putU32(mem, address+28, uint32(vpn))
		putU32(mem, address+32, 7)
		if i == 1 {
			putU32(mem, address+32, 1)
		}
		putU64(mem, address+40, 0x2000+i*0x100)
		putU64(mem, 0x2000+i*0x100, 0x3000+i*0x100)
		putU64(mem, 0x3000+i*0x100, 0x4003+i*0x100)
		path := `C:\main.exe`
		if i == 2 {
			path = `C:\other.exe`
		}
		if i == 3 {
			path = `C:\module.dll`
		}
		putHandleUnicode(mem, 0x4000+i*0x100, 0x5000+i*0x200, path)
	}
	threads := []uint64{0x600, 0x700, 0x800, 0x900, 0xa00, 0xb00, 0xc00}
	putU64(mem, 0x440, threads[0])
	putU64(mem, 0x448, threads[len(threads)-1])
	for i, thread := range threads {
		prev, next := uint64(0x440), uint64(0x440)
		if i > 0 {
			prev = threads[i-1]
		}
		if i+1 < len(threads) {
			next = threads[i+1]
		}
		putU64(mem, thread, next)
		putU64(mem, thread+8, prev)
		putU64(mem, thread+16, 104)
		putU64(mem, thread+24, uint64(8+i*4))
		putU64(mem, thread+32, 0x110100)
		putU64(mem, thread+40, 0x110100)
		putU64(mem, thread+48, 133000000000000000)
	}
	putU64(mem, 0x820, 0x120100)
	putU64(mem, 0x828, 0x100100)
	putU64(mem, 0x938, 1)
	putU32(mem, 0xa40, 4)
	putU64(mem, 0xb10, 3)
	putU64(mem, 0xc20, 0x900000)
	putU64(mem, 0xc28, 0x130100)
	return plugin.Environment{Kernel: mem, Objects: &object.Reader{Layer: mem, Symbols: table}, Symbols: table, OS: "windows", ImageHash: "sample"}, mem
}
func runSuspiciousThreadFixture(t *testing.T, e plugin.Environment, p map[string]string) ([]evidence.Row, error) {
	t.Helper()
	b := windowsSuspiciousThreadPlugins()[0]
	parameters, err := plugin.Parameters(b.Spec(), p)
	if err != nil {
		return nil, err
	}
	var rows []evidence.Row
	err = b.Run(context.Background(), e, parameters, func(row evidence.Row) error {

		rows = append(rows, row)
		return nil
	})
	return rows, err
}
func TestSuspiciousThreadPipeline(t *testing.T) {
	e, _ := suspiciousThreadFixture(t)
	rows, err := runSuspiciousThreadFixture(t, e, nil)
	if err != nil || len(rows) != 4 {
		t.Fatal(len(rows), err)
	}
	for i, rule := range []string{"non_file_backed", "unexpected_protection", "other_executable"} {
		if rows[i].Cells["Rule"].String() != rule {
			t.Fatal(rows[i].Cells)
		}
		for _, name := range []string{"ProcessIdentity", "ThreadIdentity", "ThreadOffset", "VADOffset"} {
			if rows[i].Cells[name].Kind == "missing" {
				t.Fatal("missing evidence link", name)
			}
		}
	}
	if rows[0].Cells["TID"].String() != "8" || rows[2].Cells["TID"].String() != "16" || rows[2].Cells["Context"].String() != "Start" {
		t.Fatal(rows)
	}
	coverage := rows[3].Cells["Coverage"].Data.(map[string]any)
	for key, want := range map[string]string{"processes": "1", "threads": "7", "exited": "2", "findings": "3", "gather_skipped": "1", "duplicates": "3"} {
		if coverage[key] != want {
			t.Fatal(key, coverage)
		}
	}
	filtered, err := runSuspiciousThreadFixture(t, e, map[string]string{"pid": "999"})
	if err != nil || len(filtered) != 1 {
		t.Fatal(filtered, err)
	}
	for _, p := range []map[string]string{{"max-threads": "1"}, {"max-nodes": "1"}, {"pid": "bad"}, {"unexpected": "x"}} {
		if _, err := runSuspiciousThreadFixture(t, e, p); err == nil {
			t.Fatal("bad limit or filter accepted", p)
		}
	}
	b := windowsSuspiciousThreadPlugins()[0]
	parameters, _ := plugin.Parameters(b.Spec(), nil)
	failure := errors.New("output failed")
	if err := b.Run(context.Background(), e, parameters, func(evidence.Row) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Run(ctx, e, parameters, func(evidence.Row) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSuspiciousThreadControlsLayoutsAndFaults(t *testing.T) {
	for _, scenario := range []string{"control", "core", "short-vads", "empty-vads", "invalid-index", "unknown-bits", "unused-table-hole", "gather-fault", "exit-fault", "protection-fault", "path-fault"} {
		t.Run(scenario, func(t *testing.T) {
			e, mem := suspiciousThreadFixture(t)
			table := e.Symbols.(*symbols.ISF)
			var fault uint64
			switch scenario {
			case "control":
				copy(mem[0x1200-12:], "Vadl")
				putU32(mem, 0x1220, 7)
				putHandleUnicode(mem, 0x4200, 0x5400, `C:\main.exe`)
			case "core":
				table.Types["_MMVAD"] = symbols.Type{Kind: "struct", Size: 48, Fields: map[string]symbols.Field{"Core": {Offset: 0, Type: symbols.TypeRef{Kind: "struct", Name: "_MMVAD_SHORT"}}, "Subsection": table.Types["_MMVAD"].Fields["Subsection"]}}
			case "short-vads":
				putU64(mem, 0x1608, 0)
			case "empty-vads":
				putU64(mem, 0x430, 0)
			case "invalid-index":
				putU32(mem, 0x1220, 99)
			case "unknown-bits":
				putU32(mem, 0x31c, 0x80000080)
			case "unused-table-hole":
				fault = 0x37c
			case "gather-fault":
				fault = 0x620
			case "exit-fault":
				fault = 0x638
			case "protection-fault":
				fault = 0x304
			case "path-fault":
				fault = 0x4208
			}
			if fault != 0 {
				layer := failRange{flatMemory: mem, at: fault}
				e.Kernel = layer
				e.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
			}
			rows, err := runSuspiciousThreadFixture(t, e, nil)
			if scenario == "exit-fault" || scenario == "protection-fault" {
				if err == nil {
					t.Fatal("read fault became clean output", rows)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			findings, diagnostics := 0, 0
			for _, row := range rows {
				switch row.Cells["RecordType"].String() {
				case "finding":
					findings++
					if scenario == "path-fault" && row.Cells["TID"].String() == "16" && row.Cells["PathError"].Error == "" {
						t.Fatal("lost file error", row)
					}
				case "diagnostic":
					diagnostics++
					if row.Cells["Error"].Kind != "string" || row.Cells["Error"].String() == "" {
						t.Fatal(row)
					}
				}
			}
			want := 3
			if scenario == "control" || scenario == "short-vads" || scenario == "empty-vads" {
				want = 0
			}
			if findings != want {
				t.Fatal(findings, want, rows)
			}
			if scenario == "gather-fault" && diagnostics != 1 {
				t.Fatal("missing diagnostic", rows)
			}
			if scenario == "invalid-index" && rows[1].Cells["Protection"].String() != "" {
				t.Fatal(rows[1])
			}
		})
	}
}
