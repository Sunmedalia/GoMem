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

func TestPebMasqueradePinnedGenerator(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-pebmasquerade-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Text, Command   *string
			Length, Maximum uint64
			CommandLength   uint64 `json:"command_length"`
			CommandMaximum  uint64 `json:"command_maximum"`
			Mode            string
			PathSpoofed     bool `json:"path_spoofed"`
			CommandSpoofed  bool `json:"command_spoofed"`
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Cases) != 288 {
		t.Fatal(err, len(oracle.Cases))
	}
	for i, c := range oracle.Cases {
		path, command := false, false
		if c.Mode != "no_peb" {
			if c.Text != nil && c.Mode != "maximum_fault" {
				path = pebLengthMismatch(*c.Text, c.Length, c.Maximum)
			}
			if c.Command != nil {
				command = pebLengthMismatch(*c.Command, c.CommandLength, c.CommandMaximum)
			}
		}
		if command != c.PathSpoofed || path != c.CommandSpoofed {
			t.Fatalf("case %d: path %v command %v oracle %+v", i, path, command, c)
		}
	}
}

func pebMasqueradeFixture(t *testing.T) (plugin.Environment, flatMemory) {
	t.Helper()
	e, mem := hollowProcessFixture(t)
	table := e.Symbols.(*symbols.ISF)
	ptr := symbols.TypeRef{Kind: "pointer"}
	s := func(name string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: name} }
	field := func(offset uint64, ref symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: ref}
	}
	process := table.Types["_EPROCESS"]
	process.Size = 112
	process.Fields["SeAuditProcessCreationInfo"] = field(104, s("_SE_AUDIT_PROCESS_CREATION_INFO"))
	table.Types["_EPROCESS"] = process
	table.Types["_SE_AUDIT_PROCESS_CREATION_INFO"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"ImageFileName": field(0, ptr)}}
	table.Types["_OBJECT_NAME_INFORMATION"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"Name": field(0, s("_UNICODE_STRING"))}}
	peb := table.Types["_PEB"]
	peb.Size = 24
	peb.Fields["ProcessParameters"] = field(16, ptr)
	table.Types["_PEB"] = peb
	table.Types["_RTL_USER_PROCESS_PARAMETERS"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"ImagePathName": field(0, s("_UNICODE_STRING")), "CommandLine": field(16, s("_UNICODE_STRING"))}}
	putU64(mem, 0x468, 0x9400)
	putHandleUnicode(mem, 0x9400, 0x9500, `\Device\disk\proc.exe`)
	putU64(mem, 0x7010, 0x9600)
	for _, c := range []struct {
		descriptor, buffer uint64
		text               string
	}{{0x9600, 0x9700, `C:\proc.exe`}, {0x9610, 0x9800, `proc.exe --normal`}} {
		putHandleUnicode(mem, c.descriptor, c.buffer, c.text)
		binary.LittleEndian.PutUint16(mem[c.descriptor+2:], uint16(len(fileUTF16Bytes(c.text))+2))
	}
	return e, mem
}
func runPebFixture(t *testing.T, e plugin.Environment, p map[string]string) ([]evidence.Row, error) {
	t.Helper()
	b := windowsPebMasqueradePlugins()[0]
	params, err := plugin.Parameters(b.Spec(), p)
	if err != nil {
		return nil, err
	}
	var rows []evidence.Row
	err = b.Run(context.Background(), e, params, func(row evidence.Row) error { rows = append(rows, row); return nil })
	return rows, err
}
func TestPebMasqueradePipeline(t *testing.T) {
	for _, scenario := range []string{"control", "path-length", "command-length", "astral", "embedded-nul", "odd", "surrogate", "empty", "empty-nul", "null-parameters", "mapped-zero-peb", "name-fault", "audit-fault", "path-fault", "command-fault", "maximum-fault", "peb-fault", "layer-fault", "audit-zero"} {
		t.Run(scenario, func(t *testing.T) {
			e, mem := pebMasqueradeFixture(t)
			var fault uint64
			pathMismatch, commandMismatch, hasErrors := false, false, false
			pathChecked, commandChecked := true, true
			pathText, commandText := true, true
			switch scenario {
			case "path-length":
				binary.LittleEndian.PutUint16(mem[0x9602:], 100)
				pathMismatch = true
			case "command-length":
				binary.LittleEndian.PutUint16(mem[0x9612:], 100)
				commandMismatch = true
			case "astral":
				putHandleUnicode(mem, 0x9600, 0x9700, "😀")
				binary.LittleEndian.PutUint16(mem[0x9602:], 6)
				pathMismatch = true
			case "embedded-nul":
				putHandleUnicode(mem, 0x9600, 0x9700, "A\x00B")
				binary.LittleEndian.PutUint16(mem[0x9602:], 8)
				pathMismatch = true
			case "odd":
				binary.LittleEndian.PutUint16(mem[0x9600:], 3)
				binary.LittleEndian.PutUint16(mem[0x9602:], 6)
				pathMismatch = true
			case "surrogate":
				binary.LittleEndian.PutUint16(mem[0x9600:], 2)
				binary.LittleEndian.PutUint16(mem[0x9602:], 4)
				copy(mem[0x9700:], []byte{0, 0xd8})
			case "empty":
				binary.LittleEndian.PutUint16(mem[0x9600:], 0)
				putU64(mem, 0x9608, 0x500000)
				pathText, pathChecked = false, false
			case "empty-nul":
				binary.LittleEndian.PutUint16(mem[0x9600:], 2)
				copy(mem[0x9700:], []byte{0, 0})
				pathText, pathChecked = false, false
			case "null-parameters":
				putU64(mem, 0x7010, 0)
				pathText, commandText, pathChecked, commandChecked = false, false, false, false
			case "mapped-zero-peb":
				putU64(mem, 0x458, 0)
				putU64(mem, 16, 0x9600)
			case "name-fault":
				fault, hasErrors = 0x418, true
			case "audit-fault":
				fault, hasErrors = 0x9500, true
			case "path-fault":
				fault, hasErrors, pathText, pathChecked = 0x9700, true, false, false
			case "command-fault":
				fault, hasErrors, commandText, commandChecked = 0x9800, true, false, false
			case "maximum-fault":
				fault, hasErrors, pathChecked = 0x9602, true, false
			case "peb-fault":
				fault, hasErrors, pathText, commandText, pathChecked, commandChecked = 0x7000, true, false, false, false, false
			case "layer-fault":
				putU64(mem, 0x450, 0)
				hasErrors, pathText, commandText, pathChecked, commandChecked = true, false, false, false, false
			case "audit-zero":
				putU64(mem, 0x468, 0)
				putHandleUnicode(mem, 0, 0x9500, "zero-name")
			}
			if fault != 0 {
				layer := psxviewFieldFault{flatMemory: mem, at: fault}
				e.Kernel, e.Physical = layer, layer
				e.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
			}
			rows, err := runPebFixture(t, e, nil)
			if err != nil || len(rows) != 2 {
				t.Fatal(len(rows), err)
			}
			r := rows[0]
			for key, want := range map[string]bool{"PEB_ImageFilePath_Spoofed": commandMismatch, "PEB_CommandLine_Spoofed": pathMismatch} {
				if r.Cells[key].Data != want {
					t.Fatal(key, r.Cells)
				}
			}
			for key, want := range map[string]bool{"ImagePathLengthMismatch": pathChecked, "CommandLineLengthMismatch": commandChecked} {
				if (r.Cells[key].Kind == "bool") != want {
					t.Fatal(key, r.Cells)
				}
			}
			for key, want := range map[string]bool{"PEB_ImageFilePath": pathText, "PEB_CommandLine": commandText} {
				if (r.Cells[key].Kind == "string") != want {
					t.Fatal(key, r.Cells)
				}
			}
			if (r.Cells["Error"].Kind == "structure") != hasErrors {
				t.Fatal("errors", r.Cells)
			}
			if scenario == "maximum-fault" && r.Cells["PEB_ImageFilePath"].String() != `C:\proc.exe` {
				t.Fatal("maximum erased text", r.Cells)
			}
			if scenario == "embedded-nul" && r.Cells["PEB_ImageFilePath"].String() != "A" {
				t.Fatal(r.Cells)
			}
			if scenario == "audit-zero" && r.Cells["EPROCESS_SeAudit_ImageFileName"].String() != "zero-name" {
				t.Fatal(r.Cells)
			}
			if r.Cells["ProcessIdentity"].String() == "" || r.Provenance.Offset != "0x400" || rows[1].Cells["RecordType"].String() != "summary" {
				t.Fatal(rows)
			}
			r.Seal()
			if err = r.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPebMasqueradeFailuresAndFilters(t *testing.T) {
	e, mem := pebMasqueradeFixture(t)
	rows, err := runPebFixture(t, e, map[string]string{"pid": "100000"})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	for _, p := range []map[string]string{{"pid": "bad"}, {"max-nodes": "0"}} {
		if _, err = runPebFixture(t, e, p); err == nil {
			t.Fatal(p)
		}
	}
	b := windowsPebMasqueradePlugins()[0]
	params, _ := plugin.Parameters(b.Spec(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = b.Run(ctx, e, params, func(evidence.Row) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	stop := errors.New("output stopped")
	if err = b.Run(context.Background(), e, params, func(evidence.Row) error { return stop }); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	// PID and list failures are structural, not a clean process scan.
	fault := psxviewFieldFault{flatMemory: mem, at: 0x410}
	e.Kernel = fault
	e.Objects = &object.Reader{Layer: fault, Symbols: e.Symbols}
	if _, err = runPebFixture(t, e, nil); err == nil {
		t.Fatal("PID read failure hidden")
	}
}

func TestPebStringPartialAndX86(t *testing.T) {
	e, mem := pebMasqueradeFixture(t)
	// Read across the end: retain the captured bytes without exposing partial text.
	binary.LittleEndian.PutUint16(mem[0x9600:], 8)
	putU64(mem, 0x9608, uint64(len(mem)-4))
	var issues int
	r := readPebString(context.Background(), mem, e.Objects, 0x9600, "_OBJECT_NAME_INFORMATION", "Name", true, func(string, error) { issues++ })
	if issues != 1 || r.text.Kind != "missing" || r.details["CapturedBytes"].String() != "4" || r.details["ReadComplete"].Data != false {
		t.Fatal(r, issues)
	}
	// The reader uses the symbol pointer width and Buffer field layout.
	table := e.Symbols.(*symbols.ISF)
	table.Bases["pointer"] = symbols.Type{Size: 4}
	u := table.Types["_UNICODE_STRING"]
	f := u.Fields["Buffer"]
	f.Offset = 4
	u.Fields["Buffer"] = f
	u.Size = 8
	table.Types["_UNICODE_STRING"] = u
	putU32(mem, 0x9604, 0x9700)
	binary.LittleEndian.PutUint16(mem[0x9600:], 2)
	binary.LittleEndian.PutUint16(mem[0x9602:], 4)
	copy(mem[0x9700:], []byte{'X', 0})
	r = readPebString(context.Background(), mem, e.Objects, 0x9600, "_OBJECT_NAME_INFORMATION", "Name", true, func(string, error) { t.Fatal("unexpected read failure") })
	if r.text.String() != "X" || r.mismatch.Data != false || r.details["Buffer"].String() != "0x0000000000009700" {
		t.Fatal(r)
	}
}

func TestPebMasqueradePerProcessStateAndBounds(t *testing.T) {
	e, mem := pebMasqueradeFixture(t)
	// Same PID, distinct object and unreadable second PEB: no first-process reuse.
	copy(mem[0xa000:0xa070], mem[0x400:0x470])
	putU64(mem, 0x400, 0xa000)
	putU64(mem, 0xa000, 0x80)
	putU64(mem, 0xa008, 0x400)
	putU64(mem, 0x88, 0xa000)
	putU64(mem, 0xa058, 0x900000)
	rows, err := runPebFixture(t, e, nil)
	if err != nil || len(rows) != 3 {
		t.Fatal(rows, err)
	}
	if rows[0].Cells["ProcessIdentity"].String() == rows[1].Cells["ProcessIdentity"].String() || rows[1].Cells["PEB_ImageFilePath"].Kind != "missing" || rows[1].Cells["ImagePathLengthMismatch"].Kind != "missing" || rows[1].Cells["Error"].Kind != "structure" {
		t.Fatal(rows)
	}
	if _, err = runPebFixture(t, e, map[string]string{"max-nodes": "1"}); err == nil {
		t.Fatal("traversal bound ignored")
	}
	// Broken layouts preserve per-field failure and continue to the other string.
	e, mem = pebMasqueradeFixture(t)
	table := e.Symbols.(*symbols.ISF)
	typ := table.Types["_RTL_USER_PROCESS_PARAMETERS"]
	delete(typ.Fields, "ImagePathName")
	table.Types["_RTL_USER_PROCESS_PARAMETERS"] = typ
	rows, err = runPebFixture(t, e, nil)
	if err != nil || len(rows) != 2 || rows[0].Cells["PEB_CommandLine"].Kind != "string" || rows[0].Cells["Error"].Kind != "structure" {
		t.Fatal(rows, err)
	}
}
