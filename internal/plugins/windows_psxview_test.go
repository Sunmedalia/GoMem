package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func psxviewFixture(t *testing.T) (plugin.Environment, flatMemory) {
	t.Helper()
	mem := make(flatMemory, 0xa000)
	table := processScanSymbols()
	threads := threadScanSymbols(false)
	for _, name := range []string{"_ETHREAD", "_KTHREAD", "_CLIENT_ID", "_UNICODE_STRING", "_OBJECT_TYPE"} {
		table.Types[name] = threads.Types[name]
	}
	process := table.Types["_EPROCESS"]
	process.Size = 96
	process.Fields["ActiveProcessLinks"] = symbols.Field{Offset: 64, Type: symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}}
	process.Fields["ObjectTable"] = symbols.Field{Offset: 80, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["_EPROCESS"] = process
	table.Types["_OBJECT_HEADER"].Fields["TypeIndex"] = symbols.Field{Offset: 24, Type: symbols.TypeRef{Kind: "base", Name: "unsigned char"}}
	handles := handleSymbols(true, 8)
	table.Types["_HANDLE_TABLE_ENTRY"] = handles.Types["_HANDLE_TABLE_ENTRY"]
	table.Types["_HANDLE_TABLE"].Fields["TableCode"] = symbols.Field{Offset: 8, Type: symbols.TypeRef{Kind: "base", Name: "unsigned long long"}}
	table.Types["_HANDLE_TABLE"] = symbols.Type{Kind: "struct", Size: 16, Fields: table.Types["_HANDLE_TABLE"].Fields}
	table.Symbols["PsActiveProcessHead"] = symbols.Symbol{Address: 0x80}
	putU64(mem, 0x28, 0x800)
	putU64(mem, 0x30, 0x900)
	putHandleUnicode(mem, 0x810, 0xa00, "Process")
	putHandleUnicode(mem, 0x910, 0xb00, "Thread")
	for i, name := range []string{"csrss.exe", "main.exe", "hidden.exe", "bad1.exe"} {
		header := uint64(0x1000 + i*0x1000)
		mem[header+2], mem[header+3] = 40, 2
		copy(mem[header+4:], "Proc")
		pid := uint64(100 + i*4)
		if i == 2 {
			pid = 104 // Same PID as main.exe, different object and creation time.
		}
		putProcess(mem, header+0x220, pid, name)
		mem[header+0x220-48+24] = 1
	}
	putU64(mem, 0x80, 0x1260)
	putU64(mem, 0x88, 0x2260)
	putU64(mem, 0x1260, 0x2260)
	putU64(mem, 0x1268, 0x80)
	putU64(mem, 0x2260, 0x80)
	putU64(mem, 0x2268, 0x1260)
	putU64(mem, 0x3240, 132539328000000000) // 2021 exit time.
	putProcess(mem, 0x4800, 112, "owner.exe")
	for i, header := range []uint64{0x5000, 0x6000} {
		mem[header+2], mem[header+3] = 40, 2
		copy(mem[header+4:], []byte{'T', 'h', 'r', 0xe5})
		address := header + 0x230
		putThread(mem, address, uint64(i*4), uint64(8+i*4), 132223104000000000)
		putU64(mem, address, 0x4800)
	}
	putU64(mem, 0x1270, 0x7000)
	putU64(mem, 0x7008, 0x8000)
	putHandle(mem, 0x8000, 0x3220-48, 0x1fffff)
	putHandle(mem, 0x8010, 0x2220-48, 0x1fffff)
	putHandle(mem, 0x8020, 0x2220-48, 0x1fffff)
	// No InfoMask/name-info symbol exists: raw process handles must not need it.
	return plugin.Environment{Physical: mem, Kernel: mem, Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}, OS: "windows", ImageHash: "image"}, mem
}

func runPsXViewFixture(t *testing.T, e plugin.Environment, p map[string]string) ([]evidence.Row, error) {
	t.Helper()
	b := windowsPsXViewPlugins()[0]
	parameters, err := plugin.Parameters(b.Spec(), p)
	if err != nil {
		return nil, err
	}
	var rows []evidence.Row
	err = b.Run(context.Background(), e, parameters, func(row evidence.Row) error { rows = append(rows, row); return nil })
	return rows, err
}

func TestPsXViewFourSourcesPIDReuseAndRawThreadOwners(t *testing.T) {
	e, _ := psxviewFixture(t)
	rows, err := runPsXViewFixture(t, e, nil)
	if err != nil || len(rows) != 5 {
		t.Fatal(len(rows), err, rows)
	}
	for i, want := range []struct {
		name string
		pid  string
		bits [4]bool
	}{{"csrss.exe", "100", [4]bool{true, true, false, false}}, {"main.exe", "104", [4]bool{true, true, false, true}}, {"hidden.exe", "104", [4]bool{false, true, false, true}}, {"owner.exe", "112", [4]bool{false, false, true, false}}} {
		row := rows[i]
		if row.Cells["Name"].String() != want.name || row.Cells["PID"].String() != want.pid || row.Cells["Identity"].Kind != "string" {
			t.Fatal(i, row)
		}
		for j, source := range psxviewSources {
			if row.Cells[source].Data != want.bits[j] {
				t.Fatal(i, source, row)
			}
		}
	}
	if rows[1].Cells["Identity"].String() == rows[2].Cells["Identity"].String() || rows[2].Cells["ExitTime"].String() != "2021-01-01 00:00:00+00:00" {
		t.Fatal(rows)
	}
	coverage := rows[4].Cells["Coverage"].Data.(map[string]any)
	for key, want := range map[string]string{"pslist": "2", "psscan": "3", "thrdscan": "1", "csrss": "2", "psscan_rejected": "1", "thrdscan_duplicates": "1", "csrss_duplicates": "1"} {
		if coverage[key] != want {
			t.Fatal(key, coverage)
		}
	}
	// Display-oriented thread gathering would remove PID 0. PsXView must still
	// see the owner through the raw thread scan (including when PID 4 is absent).
	e, mem := psxviewFixture(t)
	copy(mem[0x6004:], "none")
	rows, err = runPsXViewFixture(t, e, nil)
	if err != nil || len(rows) != 5 || rows[3].Cells["thrdscan"].Data != true {
		t.Fatal(rows, err)
	}
}

func TestPsXViewBoundsCancellationAndFailures(t *testing.T) {
	e, _ := psxviewFixture(t)
	for _, p := range []map[string]string{{"max-processes": "1"}, {"max-nodes": "1"}, {"physical-offsets": "invalid"}, {"pid": "104"}} {
		if _, err := runPsXViewFixture(t, e, p); err == nil {
			t.Fatal("accepted unsupported parameters or bound", p)
		}
	}
	b := windowsPsXViewPlugins()[0]
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
	for _, scenario := range []string{"list-cycle", "owner-read", "process-exit-read", "object-table-read", "physical-fallback"} {
		t.Run(scenario, func(t *testing.T) {
			e, mem := psxviewFixture(t)
			var fault uint64
			params := map[string]string{}
			switch scenario {
			case "list-cycle":
				putU64(mem, 0x2260, 0x1260)
			case "owner-read":
				fault = 0x5230
			case "process-exit-read":
				// System is exempt from the process validity time checks, so a
				// final exit read failure must still fail instead of looking empty.
				copy(mem[0x1220:0x1220+15], make([]byte, 15))
				copy(mem[0x1220:], "System")
				putU64(mem, 0x1230, 4)
				fault = 0x1240
			case "object-table-read":
				fault = 0x1270
			case "physical-fallback":
				params["physical-offsets"] = "true"
			}
			if fault != 0 {
				layer := psxviewFieldFault{flatMemory: mem, at: fault}
				e.Kernel, e.Physical = layer, layer
				e.Objects = &object.Reader{Layer: layer, Symbols: e.Symbols}
			}
			rows, err := runPsXViewFixture(t, e, params)
			if scenario == "object-table-read" {
				if err != nil || rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)["csrss_unreadable_object_tables"] != "1" {
					t.Fatal(rows, err)
				}
			} else if scenario == "physical-fallback" {
				if err != nil || rows[0].Cells["TranslationError"].Error == "" || rows[0].Cells["OffsetSpace"].String() != "kernel_virtual" {
					t.Fatal(rows, err)
				}
			} else if err == nil {
				t.Fatal("read/list failure became clean output", rows)
			}
		})
	}
}

func TestPsXViewRequiredSymbolsAndAbsentCsrss(t *testing.T) {
	for _, check := range []struct{ typ, field string }{{"_EPROCESS", "ExitTime"}, {"_EPROCESS", "Pcb"}, {"_ETHREAD", "Cid"}, {"_ETHREAD", "Tcb"}} {
		e, _ := psxviewFixture(t)
		delete(e.Symbols.(*symbols.ISF).Types[check.typ].Fields, check.field)
		if _, err := runPsXViewFixture(t, e, nil); err == nil {
			t.Fatal("missing validity/owner symbols became clean output", check)
		}
	}
	e, mem := psxviewFixture(t)
	clear(mem[0x1220 : 0x1220+15])
	copy(mem[0x1220:], "other.exe")
	rows, err := runPsXViewFixture(t, e, nil)
	if err != nil || len(rows) != 5 {
		t.Fatal(rows, err)
	}
	for _, row := range rows[:4] {
		if row.Cells["csrss"].Data != false {
			t.Fatal(row)
		}
	}
	if rows[4].Cells["Coverage"].Data.(map[string]any)["csrss_processes"] != "0" {
		t.Fatal(rows[4])
	}
}

type psxviewTranslator struct{ fail, mask bool }

type psxviewFieldFault struct {
	flatMemory
	at uint64
}

func (p psxviewFieldFault) ReadAt(ctx context.Context, dst []byte, address uint64) (int, error) {
	if address == p.at {
		return 0, errors.New("field page missing")
	}
	return p.flatMemory.ReadAt(ctx, dst, address)
}

func (p psxviewTranslator) Translate(_ context.Context, address uint64) (memory.Translation, error) {
	if p.fail {
		return memory.Translation{}, errors.New("page missing")
	}
	if p.mask {
		return memory.Translation{Physical: address & 0xfff}, nil
	}
	return memory.Translation{Physical: address + 0x10000}, nil
}

func TestPsXViewPinnedFilterAndMergeOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-psxview-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Names []struct {
			Name     string
			Expected bool
		}
		Merges []struct {
			Collision bool
			Processes []struct {
				ID, Name    string
				Offset, PID uint64
				Valid       bool
				Exited      bool
			}
			Inputs   [][]string
			Expected [][]json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil || len(fixture.Names) != 267 || len(fixture.Merges) != 30 {
		t.Fatal(err, len(fixture.Names), len(fixture.Merges))
	}
	for _, c := range fixture.Names {
		if got := psxviewNameValid(c.Name); got != c.Expected {
			t.Fatalf("name %q: got %v want %v", c.Name, got, c.Expected)
		}
	}
	for i, c := range fixture.Merges {
		e, mem := psxviewFixture(t)
		addresses := map[string]uint64{}
		for _, p := range c.Processes {
			clear(mem[p.Offset : p.Offset+96])
			putProcess(mem, p.Offset, p.PID, p.Name)
			if p.Exited {
				putU64(mem, p.Offset+32, 132539328000000000)
			}
			addresses[p.ID] = p.Offset
		}
		if c.Collision {
			e.Kernel = &memory.Virtual{ID: "kernel", Physical: mem, Translator: psxviewTranslator{mask: true}}
		}
		index := psxviewIndex{env: e, physical: c.Collision, limit: 100}
		for source, input := range c.Inputs {
			for _, id := range input {
				if _, err := index.add(context.Background(), source, e.Objects, addresses[id]); err != nil {
					t.Fatal(i, err)
				}
			}
		}
		var got [][]any
		err = index.emit(context.Background(), func(row evidence.Row) error {
			offset, _ := row.Cells["Offset"].Uint()
			pid, _ := row.Cells["PID"].Uint()
			got = append(got, []any{offset, row.Cells["Name"].String(), pid, row.Cells["pslist"].Data, row.Cells["psscan"].Data, row.Cells["thrdscan"].Data, row.Cells["csrss"].Data, row.Cells["ExitTime"].String()})
			return nil
		})
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(c.Expected)
		if err != nil || string(gotJSON) != string(wantJSON) {
			t.Fatalf("case %d got %s want %s: %v", i, gotJSON, wantJSON, err)
		}
	}
}

func TestPsXViewPhysicalCoordinatesAndMixedPoolSpace(t *testing.T) {
	e, mem := psxviewFixture(t)
	e.Kernel = &memory.Virtual{ID: "kernel", Physical: mem, Translator: psxviewTranslator{}}
	for _, c := range []struct {
		physical bool
		layer    string
		key      uint64
		space    string
	}{{false, "kernel", 0x1234, "kernel_virtual"}, {false, mem.Name(), 0x1234, "physical_pool"}, {true, "kernel", 0x11234, "physical"}, {true, mem.Name(), 0x11234, "physical"}} {
		key, space, err := psxviewOffset(context.Background(), e, 0x1234, c.layer, c.physical)
		if err != nil || key != c.key || space != c.space {
			t.Fatal(c, key, space, err)
		}
	}
	e.Kernel.(*memory.Virtual).Translator = psxviewTranslator{fail: true}
	key, space, err := psxviewOffset(context.Background(), e, 0x1234, mem.Name(), true)
	if err == nil || key != 0x1234 || space != "physical_pool" {
		t.Fatal(key, space, err)
	}
}
