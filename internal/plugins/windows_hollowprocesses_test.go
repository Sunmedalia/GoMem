package plugins

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestHollowProcessNoteOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-hollowprocess-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Section uint64
			Image   *uint64
			VADs    []struct {
				Base       uint64
				Protection string
				Path       *string
			}
			DLLs []struct {
				Base uint64
				Path *string
			}
			Expected []string
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil || len(fixture.Cases) != 576 {
		t.Fatal(len(fixture.Cases), err)
	}
	for i, c := range fixture.Cases {
		var ranges []analysisVADRange
		var dlls []hollowDLL
		for _, v := range c.VADs {
			value := evidence.Missing("not_file_backed", nil)
			if v.Path != nil {
				value = evidence.Text(*v.Path)
			}
			ranges = append(ranges, analysisVADRange{windowsVADPath: windowsVADPath{start: v.Base, file: value}, protection: v.Protection})
		}
		for _, v := range c.DLLs {
			value := evidence.Missing("dll_path_unreadable", errors.New("missing page"))
			if v.Path != nil {
				value = evidence.Text(*v.Path)
			}
			dlls = append(dlls, hollowDLL{base: v.Base, path: value})
		}
		var got []string
		for _, finding := range hollowProcessNotes(c.Section, c.Image, hollowVADMap(ranges), dlls) {
			got = append(got, finding.note)
		}
		if len(got) != len(c.Expected) || len(got) > 0 && !reflect.DeepEqual(got, c.Expected) {
			t.Fatalf("case %d got %v want %v", i, got, c.Expected)
		}
	}
}

// Reuse the process/VAD fixture, adding actual identity-mapped x64 page tables
// and PEB loader objects so the complete plugin uses a real process translator.
func hollowProcessFixture(t *testing.T) (plugin.Environment, flatMemory) {
	t.Helper()
	e, original := suspiciousThreadFixture(t)
	mem := make(flatMemory, 0x40000)
	copy(mem, original)
	table := e.Symbols.(*symbols.ISF)
	ptr := symbols.TypeRef{Kind: "pointer"}
	u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
	s := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	field := func(offset uint64, ref symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: ref}
	}
	process := table.Types["_EPROCESS"]
	process.Size = 104
	process.Fields["Pcb"] = field(80, s("_KPROCESS"))
	process.Fields["Peb"] = field(88, ptr)
	process.Fields["WoW64Process"] = field(96, ptr)
	table.Types["_EPROCESS"] = process
	table.Types["_KPROCESS"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"DirectoryTableBase": field(0, u64)}}
	table.Types["_PEB"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Ldr": field(0, ptr), "ImageBaseAddress": field(8, ptr)}}
	table.Types["_PEB_LDR_DATA"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"InLoadOrderModuleList": field(0, s("_LIST_ENTRY"))}}
	table.Types["_LDR_DATA_TABLE_ENTRY"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{"InLoadOrderLinks": field(0, s("_LIST_ENTRY")), "DllBase": field(16, ptr), "FullDllName": field(24, s("_UNICODE_STRING"))}}
	putU64(mem, 0x450, 0x10000)
	putU64(mem, 0x458, 0x7000)
	putU64(mem, 0x10000, 0x11003)
	putU64(mem, 0x11000, 0x12003)
	putU64(mem, 0x12000, 0x83)
	putU64(mem, 0x7000, 0x7100)
	putU64(mem, 0x7008, 0x100000)
	putU64(mem, 0x7100, 0x7400)
	putU64(mem, 0x7108, 0x7600)
	for i := uint64(0); i < 3; i++ {
		entry := 0x7400 + i*0x100
		next, prev := uint64(0x7100), uint64(0x7100)
		if i < 2 {
			next = entry + 0x100
		}
		if i > 0 {
			prev = entry - 0x100
		}
		putU64(mem, entry, next)
		putU64(mem, entry+8, prev)
		putU64(mem, entry+16, 0x100000+i*0x10000)
		putHandleUnicode(mem, entry+24, 0x9000+i*0x100, `C:\module.dll`)
	}
	e.Physical, e.Kernel, e.Architecture = mem, mem, "x64"
	e.Objects = &object.Reader{Layer: mem, Symbols: table}
	return e, mem
}

func runHollowProcessFixture(t *testing.T, e plugin.Environment, p map[string]string) ([]evidence.Row, error) {
	t.Helper()
	b := windowsHollowProcessPlugins()[0]
	parameters, err := plugin.Parameters(b.Spec(), p)
	if err != nil {
		return nil, err
	}
	var rows []evidence.Row
	err = b.Run(context.Background(), e, parameters, func(row evidence.Row) error { rows = append(rows, row); return nil })
	return rows, err
}

func TestHollowProcessPipeline(t *testing.T) {
	e, mem := hollowProcessFixture(t)
	putU64(mem, 0x7008, 0x200000)
	putU32(mem, 0x1020, 1)
	rows, err := runHollowProcessFixture(t, e, nil)
	if err != nil || len(rows) != 5 {
		t.Fatal(len(rows), err, rows)
	}
	for i, want := range []string{"image_base_mismatch", "executable_protection", "dll_protection", "dll_protection"} {
		if rows[i].Cells["Rule"].String() != want || rows[i].Provenance.Offset != "0x400" || rows[i].Cells["ProcessIdentity"].Kind != "string" {
			t.Fatal(i, rows[i])
		}
	}
	if rows[2].Cells["LoaderOffset"].String() != evidence.Address(0x7400).String() || rows[3].Cells["VADOffset"].String() != evidence.Address(0x1200).String() {
		t.Fatal(rows)
	}
	for key, want := range map[string]string{"processes": "1", "checked": "1", "findings": "4", "diagnostics": "0"} {
		if rows[4].Cells["Coverage"].Data.(map[string]any)[key] != want {
			t.Fatal(rows[4])
		}
	}
	filtered, err := runHollowProcessFixture(t, e, map[string]string{"pid": "999"})
	if err != nil || len(filtered) != 1 {
		t.Fatal(filtered, err)
	}
	for _, p := range []map[string]string{{"max-nodes": "1"}, {"pid": "invalid"}, {"bad": "x"}} {
		if _, err = runHollowProcessFixture(t, e, p); err == nil {
			t.Fatal("accepted bad parameters", p)
		}
	}
	b := windowsHollowProcessPlugins()[0]
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

func TestHollowProcessControlsAndFaults(t *testing.T) {
	for _, scenario := range []string{"control", "exe-missing", "inside-not-base", "short-dlls", "short-vads", "duplicate-dll", "duplicate-vad", "peb-fault", "image-fault", "base-fault", "path-fault", "list-hole", "no-space", "vad-fault", "section-fault", "protection-fault"} {
		t.Run(scenario, func(t *testing.T) {
			e, mem := hollowProcessFixture(t)
			putU32(mem, 0x1220, 7)
			var fault uint64
			wantFindings, wantDiagnostics := 0, 0
			switch scenario {
			case "exe-missing":
				putU64(mem, 0x438, 0x900000)
				wantFindings = 2
			case "inside-not-base":
				putU64(mem, 0x438, 0x100001)
				putU64(mem, 0x7008, 0x100001)
				wantFindings = 1
			case "short-dlls":
				putU64(mem, 0x7500, 0x7100)
			case "short-vads":
				putU64(mem, 0x1608, 0)
			case "duplicate-dll":
				putU64(mem, 0x7610, 0x100000)
			case "duplicate-vad":
				putU32(mem, 0x1818, 0x100)
				putU32(mem, 0x181c, 0x100)
			case "peb-fault":
				fault, wantDiagnostics = 0x7000, 1
			case "image-fault":
				fault, wantDiagnostics = 0x7008, 1
			case "base-fault":
				fault, wantDiagnostics = 0x7410, 1
			case "path-fault":
				fault, wantDiagnostics = 0x7518, 1
				putU32(mem, 0x1220, 1)
				wantFindings = 1
			case "list-hole":
				putU64(mem, 0x7600, 0x50000)
				wantDiagnostics = 1
			case "no-space":
				putU64(mem, 0x450, 0)
				wantDiagnostics = 1
			case "vad-fault":
				fault = 0x1018
			case "section-fault":
				fault = 0x438
			case "protection-fault":
				fault = 0x31c
			}
			if fault != 0 {
				layer := failRange{flatMemory: mem, at: fault}
				e.Physical, e.Kernel = layer, layer
				e.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
			}
			rows, err := runHollowProcessFixture(t, e, nil)
			if scenario == "vad-fault" || scenario == "section-fault" || scenario == "protection-fault" {
				if err == nil {
					t.Fatal("fault became clean output", rows)
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
					if scenario == "path-fault" && (row.Cells["PathError"].Error == "" || row.Cells["Path"].Kind != "missing") {
						t.Fatal("path error lost", row)
					}
				case "diagnostic":
					diagnostics++
					if row.Cells["Error"].Error == "" {
						t.Fatal("error lost", row)
					}
				}
			}
			if findings != wantFindings || diagnostics != wantDiagnostics {
				t.Fatal(findings, diagnostics, rows)
			}
		})
	}
}

func TestHollowProcessDuplicateMaps(t *testing.T) {
	entries := []hollowDLL{{base: 2, address: 20}, {base: 1, address: 10}, {base: 2, address: 21}, {base: 3, address: 30}}
	if got := hollowDLLMap(entries); !reflect.DeepEqual(got, []hollowDLL{entries[2], entries[1], entries[3]}) {
		t.Fatal(got)
	}
	ranges := []analysisVADRange{{windowsVADPath: windowsVADPath{start: 2, address: 20}}, {windowsVADPath: windowsVADPath{start: 2, address: 21}}}
	if got := hollowVADMap(ranges); len(got) != 1 || got[2].address != 21 {
		t.Fatal(got)
	}
}

func TestHollowProcessWowLoaderTargets(t *testing.T) {
	for _, wrapper := range []string{"direct", "_EWOW64PROCESS", "_WOW64_PROCESS", "unreadable"} {
		t.Run(wrapper, func(t *testing.T) {
			e, mem := hollowProcessFixture(t)
			table := e.Symbols.(*symbols.ISF)
			putU64(mem, 0x460, 0xa000)
			if wrapper != "direct" {
				putU64(mem, 0x460, 0xc000)
				putU64(mem, 0xc000, 0xa000)
				typ, path := wrapper, "Peb"
				if wrapper == "_WOW64_PROCESS" {
					path = "Wow64"
				}
				if wrapper == "unreadable" {
					typ = "_EWOW64PROCESS"
				}
				table.Types[typ] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{path: {Offset: 0, Type: symbols.TypeRef{Kind: "pointer"}}}}
			}
			// A second, 32-bit load list deliberately repeats native base 0x110000.
			putU32(mem, 0xa00c, 0xa100)
			putU32(mem, 0xa10c, 0xa400)
			for i := uint64(0); i < 3; i++ {
				entry, next := uint64(0xa400+i*0x100), uint64(0xa10c)
				if i < 2 {
					next = entry + 0x100
				}
				putU32(mem, entry, uint32(next))
				putU32(mem, entry+24, uint32(0x110000+i*0x10000))
				raw := fileUTF16Bytes(`C:\wow.dll`)
				binary.LittleEndian.PutUint16(mem[entry+36:], uint16(len(raw)))
				putU32(mem, entry+40, uint32(0xb000+i*0x100))
				copy(mem[0xb000+i*0x100:], raw)
			}
			if wrapper == "unreadable" {
				layer := failRange{flatMemory: mem, at: 0xc000}
				e.Kernel = layer
				e.Objects = &object.Reader{Layer: layer, Symbols: table}
			}
			var issues []string
			issue := func(stage string, err error) error { issues = append(issues, stage); return nil }
			targets, err := hollowLoaderTargets(context.Background(), e, 0x400, mem, issue)
			if err != nil {
				t.Fatal(err)
			}
			if wrapper == "unreadable" {
				if len(targets) != 1 || !reflect.DeepEqual(issues, []string{"wow64_peb_unreadable"}) {
					t.Fatal(targets, issues)
				}
				return
			}
			if len(targets) != 2 || targets[0].peb != 0x7000 || targets[1].peb != 0xa000 || targets[1].env.Symbols.PointerSize() != 4 {
				t.Fatal(targets)
			}
			dlls, err := hollowLoadDLLs(context.Background(), targets, 100, issue)
			if err != nil || len(dlls) != 4 || len(issues) != 0 {
				t.Fatal(dlls, issues, err)
			}
			for i, want := range []uint64{0x100000, 0x110000, 0x120000, 0x130000} {
				if dlls[i].base != want || i > 0 && dlls[i].path.String() != `C:\wow.dll` {
					t.Fatal(dlls)
				}
			}
			// Native x86 is a single PEB with the same 32-bit loader layout.
			user32 := targets[1].env
			user32.Objects = &object.Reader{Layer: mem, Symbols: user32.Symbols}
			dlls, err = hollowLoadDLLs(context.Background(), []hollowLoaderTarget{{0xa000, user32}}, 100, issue)
			if err != nil || len(dlls) != 3 {
				t.Fatal(dlls, err)
			}
		})
	}
}

func TestHollowProcessLoaderStringSemantics(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  []byte
		want string
	}{{"empty", nil, ""}, {"odd", []byte{'A', 0, 'B'}, "A\ufffd"}, {"nul", []byte{'A', 0, 0, 0, 'B', 0}, "A"}, {"surrogate", []byte{0, 0xd8}, "\ufffd"}} {
		t.Run(c.name, func(t *testing.T) {
			e, mem := hollowProcessFixture(t)
			binary.LittleEndian.PutUint16(mem[0x7418:], uint16(len(c.raw)))
			copy(mem[0x9000:], c.raw)
			var issues []string
			issue := func(stage string, err error) error { issues = append(issues, stage); return nil }
			targets, err := hollowLoaderTargets(context.Background(), e, 0x400, mem, issue)
			if err != nil {
				t.Fatal(err)
			}
			dlls, err := hollowLoadDLLs(context.Background(), targets, 100, issue)
			if err != nil || len(dlls) != 3 || len(issues) != 0 || dlls[0].path.String() != c.want {
				t.Fatal(dlls, issues, err)
			}
		})
	}
}
