package plugins

import (
	"context"
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

func ghostFixture(t *testing.T) (plugin.Environment, flatMemory) {
	t.Helper()
	e, mem := hollowProcessFixture(t)
	table := e.Symbols.(*symbols.ISF)
	field := func(offset uint64, ref symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: ref}
	}
	u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
	ptr := symbols.TypeRef{Kind: "pointer"}
	u8 := symbols.TypeRef{Kind: "base", Name: "u8"}
	s := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	process := table.Types["_EPROCESS"]
	process.Size = 160
	process.Fields["ExitTime"] = field(104, s("_LARGE_INTEGER"))
	process.Fields["ActiveThreads"] = field(112, u64)
	process.Fields["InheritedFromUniqueProcessId"] = field(120, u64)
	process.Fields["ObjectTable"] = field(128, ptr)
	process.Fields["ImageFilePointer"] = field(136, ptr)
	process.Fields["ThreadListHead"] = field(144, s("_LIST_ENTRY"))
	table.Types["_EPROCESS"] = process
	table.Types["_HANDLE_TABLE"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"HandleCount": field(0, u64)}}
	putU64(mem, 0x470, 2)
	putU64(mem, 0x478, 100)
	putU64(mem, 0x480, 0x9200)
	putU64(mem, 0x488, 0x4000)
	putU64(mem, 0x490, 0xffff800000006000)
	putU64(mem, 0x498, 0xffff800000006000)
	putU64(mem, 0x9200, 10)
	file := table.Types["_FILE_OBJECT"]
	file.Size = 24
	file.Fields["DeletePending"] = field(16, u8)
	table.Types["_FILE_OBJECT"] = file
	flags := table.Types["_FLAGS"]
	flags.Fields["PrivateMemory"] = field(0, symbols.TypeRef{Kind: "bitfield", BitPosition: 8, BitLength: 1, BitType: &u64})
	table.Types["_FLAGS"] = flags
	table.Types["_SECTION_FLAGS"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"DeleteOnClose": field(0, u64)}}
	table.Types["_SECTION_UNION"] = symbols.Type{Kind: "union", Size: 8, Fields: map[string]symbols.Field{"Flags": field(0, s("_SECTION_FLAGS"))}}
	control := table.Types["_CONTROL_AREA"]
	control.Size = 16
	control.Fields["u"] = field(8, s("_SECTION_UNION"))
	table.Types["_CONTROL_AREA"] = control
	return e, mem
}
func runGhostFixture(t *testing.T, e plugin.Environment, p map[string]string) ([]evidence.Row, error) {
	t.Helper()
	b := windowsProcessGhostingPlugins()[0]
	params, err := plugin.Parameters(b.Spec(), p)
	if err != nil {
		t.Fatal(err)
	}
	var rows []evidence.Row
	err = b.Run(context.Background(), e, params, func(r evidence.Row) error {
		r.Provenance.ImageSHA256 = e.ImageHash
		r.Provenance.Plugin = b.Spec().Name
		r.Seal()
		rows = append(rows, r)
		return nil
	})
	return rows, err
}
func ghostFindings(rows []evidence.Row) []evidence.Row {
	var result []evidence.Row
	for _, r := range rows {
		if r.Cells["RecordType"].String() == "finding" {
			result = append(result, r)
		}
	}
	return result
}

func TestProcessGhostingPinnedHelpersAndActiveFilter(t *testing.T) {
	data, err := os.ReadFile("testdata/windows-processghosting-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Processes []struct {
			Member       bool
			Slot, Target uint64
			Pending      *uint64
			Expected     [][]*uint64
		}
		VADs []struct {
			Path           string
			Pending, Close *uint64
			Expected       [][]*uint64
		}
		Active []struct {
			Valid                        bool
			Threads, PID, Parent, Exited uint64
			Handles, Expected            bool
		}
	}
	if err = json.Unmarshal(data, &oracle); err != nil || len(oracle.Processes) != 40 || len(oracle.VADs) != 180 || len(oracle.Active) != 64 {
		t.Fatal(err)
	}
	numeric := func(list []ghostFinding, vad bool) [][]*uint64 {
		var result [][]*uint64
		for _, f := range list {
			file := f.file
			values := []*uint64{&file, f.pending, f.close}
			if !vad {
				base := f.base
				values = append(values, &base)
			}
			result = append(result, values)
		}
		return result
	}
	for i, c := range oracle.Processes {
		var got []ghostFinding
		if c.Member {
			file, pending := c.Target, c.Pending
			if c.Slot == 0 || c.Pending == nil {
				file = 0
				pending = nil
			}
			got = ghostProcessFindings(file, 0x1000, pending)
		}
		result := numeric(got, false)
		if len(result) != len(c.Expected) || len(result) > 0 && !reflect.DeepEqual(result, c.Expected) {
			t.Fatalf("process %d got %v want %v", i, result, c.Expected)
		}
	}
	for i, c := range oracle.VADs {
		result := numeric(ghostVADFindings(0x4000, 0, c.Path, c.Pending, c.Close), true)
		if len(result) != len(c.Expected) || len(result) > 0 && !reflect.DeepEqual(result, c.Expected) {
			t.Fatalf("VAD %d got %v want %v", i, result, c.Expected)
		}
	}
	for i, c := range oracle.Active {
		e, mem := ghostFixture(t)
		if !c.Valid {
			mem[0x418] = 0
		}
		putU64(mem, 0x410, c.PID)
		putU64(mem, 0x470, c.Threads)
		putU64(mem, 0x478, c.Parent)
		putU64(mem, 0x468, c.Exited)
		if !c.Handles {
			delete(e.Symbols.(*symbols.ISF).Types["_HANDLE_TABLE"].Fields, "HandleCount")
		}
		got, err := ghostActiveProcess(context.Background(), e, 0x400, c.PID, func(string, error) error { return nil })
		if err != nil || got != c.Expected {
			t.Fatalf("active %d got %v want %v err %v", i, got, c.Expected, err)
		}
	}
}

func TestProcessGhostingCompleteReaderAndDuplicateSignals(t *testing.T) {
	e, mem := ghostFixture(t)
	mem[0x4010] = 1
	putU64(mem, 0x3008, 1)
	rows, err := runGhostFixture(t, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	findings := ghostFindings(rows)
	if len(findings) != 3 {
		t.Fatal(len(findings), rows)
	}
	for i, rule := range []string{"image_file_state", "vad_delete_on_close", "vad_delete_pending"} {
		r := findings[i]
		if r.Verify() != nil || r.Cells["Rule"].String() != rule || r.Cells["ProcessOffset"].String() != evidence.Address(0x400).String() || r.Cells["FILE_OBJECT"].String() != evidence.Address(0x4000).String() || r.Cells["Path"].String() != `C:\main.exe` {
			t.Fatal(r)
		}
	}
	if findings[1].Cells["DeletePending"].Kind != "missing" || findings[2].Cells["DeleteOnClose"].Kind != "missing" || findings[0].Cells["ImageFilePointerOffset"].String() != evidence.Address(0x488).String() {
		t.Fatal(findings)
	}
	coverage := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
	if coverage["processes"] != "1" || coverage["active"] != "1" || coverage["vads"] != "5" || coverage["mapped_files"] != "3" || coverage["findings"] != "3" {
		t.Fatal(coverage)
	}
}

func TestProcessGhostingControlsAndApplicability(t *testing.T) {
	for _, scenario := range []string{"normal", "no-image-member", "no-handles-member", "system", "system-child", "no-threads", "exited", "private", "non-image-extension", "smear", "null-image", "zero-mapped-image", "image-read-failure", "vad-read-failure", "pending-read-failure", "close-read-failure", "empty-path", "duplicate-base", "direct-control", "pointer-file", "fastref-object", "missing-delete-layout", "limit", "total-limit", "bad-limit", "cycle"} {
		t.Run(scenario, func(t *testing.T) {
			e, mem := ghostFixture(t)
			table := e.Symbols.(*symbols.ISF)
			p := map[string]string{}
			want, diagnostics := 0, false
			switch scenario {
			case "no-image-member":
				delete(table.Types["_EPROCESS"].Fields, "ImageFilePointer")
				mem[0x4010] = 1
				want = 1
			case "no-handles-member":
				delete(table.Types["_HANDLE_TABLE"].Fields, "HandleCount")
				mem[0x4010] = 1
				want = 2
			case "system":
				putU64(mem, 0x410, 4)
				mem[0x4010] = 1
			case "system-child":
				putU64(mem, 0x478, 4)
				mem[0x4010] = 1
			case "no-threads":
				putU64(mem, 0x470, 0)
				mem[0x4010] = 1
			case "exited":
				putU64(mem, 0x468, 133000000000000001)
				mem[0x4010] = 1
			case "private":
				putU64(mem, 0x1020, 0x107)
				putU64(mem, 0x3008, 1)
			case "non-image-extension":
				putHandleUnicode(mem, 0x4000, 0x5000, `C:\main.exe.tmp`)
				putU64(mem, 0x3008, 2)
			case "smear":
				mem[0x4010] = 2
			case "null-image":
				putU64(mem, 0x488, 0)
				want = 1
			case "zero-mapped-image":
				putU64(mem, 0x488, 0)
				mem[16] = 1
				want = 1
			case "image-read-failure":
				putU64(mem, 0x488, uint64(len(mem))+0x100)
				want = 1
				diagnostics = true
			case "vad-read-failure":
				putU64(mem, 0x1028, uint64(len(mem))+0x100)
				diagnostics = true
			case "pending-read-failure":
				// A precise fault leaves the path readable, and close emits first.
				putU64(mem, 0x3008, 1)
				e.Kernel = psxviewFieldFault{flatMemory: mem, at: 0x4010}
				e.Objects = &object.Reader{Layer: e.Kernel, Symbols: table}
				want = 2
				diagnostics = true
			case "close-read-failure":
				e.Kernel = psxviewFieldFault{flatMemory: mem, at: 0x3008}
				e.Objects = &object.Reader{Layer: e.Kernel, Symbols: table}
				mem[0x4010] = 1
				want = 2
				diagnostics = true
			case "empty-path":
				putHandleUnicode(mem, 0x4000, 0x5000, "")
				putU64(mem, 0x3008, 1)
			case "duplicate-base":
				putU32(mem, 0x1418, 0x100)
				putU32(mem, 0x141c, 0x100)
				putU64(mem, 0x3008, 1)
			case "direct-control":
				full := table.Types["_MMVAD"]
				delete(full.Fields, "Subsection")
				full.Fields["ControlArea"] = symbols.Field{Offset: 40, Type: symbols.TypeRef{Kind: "pointer"}}
				table.Types["_MMVAD"] = full
				for i := uint64(0); i < 5; i++ {
					putU64(mem, 0x1028+i*0x200, 0x3000+i*0x100)
				}
				mem[0x4010] = 1
				want = 2
			case "pointer-file":
				control := table.Types["_CONTROL_AREA"]
				control.Fields["FilePointer"] = symbols.Field{Type: symbols.TypeRef{Kind: "pointer"}}
				table.Types["_CONTROL_AREA"] = control
				for i := uint64(0); i < 5; i++ {
					putU64(mem, 0x3000+i*0x100, 0x4000+i*0x100)
				}
				mem[0x4010] = 1
				want = 2
			case "fastref-object":
				fast := table.Types["_EX_FAST_REF"]
				fast.Fields["Object"] = fast.Fields["Value"]
				delete(fast.Fields, "Value")
				table.Types["_EX_FAST_REF"] = fast
				mem[0x4010] = 1
				want = 2
			case "missing-delete-layout":
				delete(table.Types["_FILE_OBJECT"].Fields, "DeletePending")
			case "limit":
				p["max-nodes"] = "2"
			case "total-limit":
				p["max-vads"] = "2"
			case "bad-limit":
				p["max-vads"] = "0"
			case "cycle":
				putU64(mem, 0x1008, 0x1000)
			}
			rows, err := runGhostFixture(t, e, p)
			if scenario == "limit" || scenario == "total-limit" || scenario == "bad-limit" || scenario == "cycle" || scenario == "missing-delete-layout" {
				if err == nil {
					t.Fatal("accepted malformed input")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			findings := ghostFindings(rows)
			if len(findings) != want {
				t.Fatal("findings", len(findings), "want", want, rows)
			}
			coverage := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
			if (coverage["diagnostics"] != "0") != diagnostics {
				t.Fatal(coverage)
			}
		})
	}
}

func TestProcessGhostingCancellationAndOutputFailure(t *testing.T) {
	e, _ := ghostFixture(t)
	b := windowsProcessGhostingPlugins()[0]
	p, _ := plugin.Parameters(b.Spec(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Run(ctx, e, p, func(evidence.Row) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	failure := errors.New("write failed")
	if err := b.Run(context.Background(), e, p, func(evidence.Row) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestProcessGhostingFileNameAndFastRefWidths(t *testing.T) {
	for _, scenario := range []string{"zero-length-buffer-unreadable", "embedded-nul", "decoded-empty", "odd-utf16", "x86-fastref"} {
		t.Run(scenario, func(t *testing.T) {
			e, mem := ghostFixture(t)
			want := 2
			path := `C:\main.exe`
			mem[0x4010] = 1
			switch scenario {
			case "zero-length-buffer-unreadable":
				putHandleUnicode(mem, 0x4000, 0x5000, "")
				e.Kernel = psxviewFieldFault{flatMemory: mem, at: 0x4008}
				e.Objects = &object.Reader{Layer: e.Kernel, Symbols: e.Symbols}
				want = 1
				path = "<not_available>"
			case "embedded-nul":
				putHandleUnicode(mem, 0x4000, 0x5000, "C:\\main.exe\x00ignored")
			case "decoded-empty":
				putHandleUnicode(mem, 0x4000, 0x5000, "\x00ignored")
				path = ""
			case "odd-utf16":
				mem[0x4000] = 1
				mem[0x4001] = 0
				mem[0x5000] = 65
				path = "\ufffd"
			case "x86-fastref":
				table := e.Symbols.(*symbols.ISF)
				ptr := table.Bases["pointer"]
				ptr.Size = 4
				table.Bases["pointer"] = ptr
				putU32(mem, 0x84, 0x400)
				putU32(mem, 0x404, 0x80)
				putU64(mem, 0x490, 0x80006000)
				putU64(mem, 0x498, 0x80006000)
				for i := uint64(0); i < 5; i++ {
					copy(mem[0x1000+i*0x200-4:], mem[0x1000+i*0x200-12:0x1000+i*0x200-8])
					putU64(mem, 0x3000+i*0x100, 0x4007+i*0x100)
				}
			}
			rows, err := runGhostFixture(t, e, nil)
			findings := ghostFindings(rows)
			if err != nil || len(findings) != want {
				t.Fatal(len(findings), err, rows)
			}
			for _, finding := range findings {
				if finding.Cells["Path"].String() != path {
					t.Fatal(finding)
				}
			}
			coverage := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
			if coverage["diagnostics"] != "0" {
				t.Fatal(coverage)
			}
		})
	}
}
