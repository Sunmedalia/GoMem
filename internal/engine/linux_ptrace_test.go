package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type ptraceInput struct {
	Name              string
	PID, TGID, Ptrace uint64
	ParentTID         uint64 `json:"parent_tid"`
	Tracees           []uint64
	NextReadable      bool `json:"next_readable"`
}
type ptraceCase struct {
	Name  string
	Tasks []ptraceInput
	Rows  []struct {
		Depth          uint64
		Process        string
		PID, TID       uint64
		Tracer, Tracee *uint64
		Flags          *string
	}
	Error bool
}

func ptraceCases(t *testing.T) []ptraceCase {
	t.Helper()
	raw, err := os.ReadFile("../plugins/testdata/linux-ptrace-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct{ Cases []ptraceCase }
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Cases) != 12 {
		t.Fatal(err)
	}
	return oracle.Cases
}
func ptraceFixture(t *testing.T, tc ptraceCase, arch, fault string) testfixture.Fixture {
	t.Helper()
	f := linuxTasksFixture(t, "control")
	if fault == "signal" {
		f = linuxTasksFixture(t, "signal")
	}
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	if arch == "x86" || arch == "pae" {
		pointer := table.Bases["pointer"]
		pointer.Size = 4
		table.Bases["pointer"] = pointer
		list := table.Types["list_head"]
		list.Size = 8
		prev := list.Fields["prev"]
		prev.Offset = 4
		list.Fields["prev"] = prev
		table.Types["list_head"] = list
		clear(data[0x1000:0x4000])
		if arch == "x86" {
			binary.LittleEndian.PutUint32(data[0x1000:], 0x83)
		} else {
			binary.LittleEndian.PutUint64(data[0x1000:], 0x2001)
			binary.LittleEndian.PutUint64(data[0x2000:], 0x83)
		}
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	listref := symbols.TypeRef{Kind: "struct", Name: "list_head"}
	task := table.Types["task_struct"]
	task.Size = 192
	task.Fields["ptrace"] = symbols.Field{Offset: 144, Type: symbols.TypeRef{Kind: "base", Name: "u64"}}
	task.Fields["parent"] = symbols.Field{Offset: 152, Type: ptr}
	task.Fields["ptraced"] = symbols.Field{Offset: 160, Type: listref}
	task.Fields["ptrace_entry"] = symbols.Field{Offset: 176, Type: listref}
	table.Types["task_struct"] = task
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	putptr := func(a, v uint64) {
		if arch == "x86" || arch == "pae" {
			binary.LittleEndian.PutUint32(data[a:], uint32(v))
		} else {
			put(a, v)
		}
	}
	ptrSize := uint64(table.PointerSize())
	list := func(head uint64, nodes ...uint64) {
		putptr(head, head)
		putptr(head+ptrSize, head)
		if len(nodes) == 0 {
			return
		}
		putptr(head, nodes[0])
		putptr(head+ptrSize, nodes[len(nodes)-1])
		for i, a := range nodes {
			next, prev := head, head
			if i > 0 {
				prev = nodes[i-1]
			}
			if i+1 < len(nodes) {
				next = nodes[i+1]
			}
			putptr(a, next)
			putptr(a+ptrSize, prev)
		}
	}
	list(0x9000, 0xa000, 0xb000)
	list(0xa060, 0x1d060, 0x1d260)
	list(0xb060)
	if fault == "signal" {
		list(0x1e000, 0xa060, 0x1d060, 0x1d260)
		list(0x1e100, 0xb060)
	}
	addresses := map[uint64]uint64{100: 0xa000, 101: 0xb000, 200: 0x1d000, 201: 0x1d200}
	for _, a := range addresses {
		put(a+144, 0)
		list(a + 160)
		list(a + 176)
	}
	counter := 0
	for i, n := range tc.Tasks {
		a := addresses[n.PID]
		if a == 0 {
			t.Fatal(n)
		}
		clear(data[a+24 : a+40])
		copy(data[a+24:a+40], n.Name)
		binary.LittleEndian.PutUint32(data[a+16:], uint32(n.PID))
		binary.LittleEndian.PutUint32(data[a+20:], uint32(n.TGID))
		put(a+144, n.Ptrace)
		parent := uint64(0x1c400 + i*0x100)
		putptr(a+152, parent)
		binary.LittleEndian.PutUint32(data[parent+16:], uint32(n.ParentTID))
		var traceeNodes []uint64
		for _, pid := range n.Tracees {
			address := uint64(0x1e400 + counter*0x100)
			counter++
			binary.LittleEndian.PutUint32(data[address+16:], uint32(pid))
			put(address+48, uint64(counter)*1000000000)
			traceeNodes = append(traceeNodes, address+176)
		}
		list(a+160, traceeNodes...)
		if !n.NextReadable {
			putptr(a+160, 0x300000)
		}
	}
	switch fault {
	case "bad-parent-field":
		f := task.Fields["parent"]
		f.Offset = 0x300000
		task.Fields["parent"] = f
		task.Size = 0x300008
	case "bad-parent":
		putptr(0xa098, 0x300000)
	case "null-parent":
		putptr(0xa098, 0)
	case "bad-tail":
		putptr(0xa0a0+ptrSize, 0x300000)
	case "tracee-cycle":
		putptr(0x1e4b0, 0x1e4b0)
	case "tracee-partial":
		f := task.Fields["ptrace_entry"]
		f.Offset = 0
		task.Fields["ptrace_entry"] = f
		f = task.Fields["pid"]
		f.Type = symbols.TypeRef{Kind: "base", Name: "u64"}
		task.Fields["pid"] = f
		list(0xa0a0, 0x1ffec)
		binary.LittleEndian.PutUint32(data[0x1fffc:], 123)

	case "thread-owner":
		binary.LittleEndian.PutUint32(data[0x1d014:], 999)
	case "group-leader":
		putptr(0x1d058, 0xb000)
	case "null-next":
		putptr(0xa0a0, 0)
	case "thread-cycle":
		putptr(0x1d260, 0x1d060)
	case "bad-flags":
		f := task.Fields["ptrace"]
		f.Offset = 0x300000
		task.Fields["ptrace"] = f
		task.Size = 0x300008
	case "partial-flags":
		f := task.Fields["ptrace"]
		f.Offset = 0x15ffc
		task.Fields["ptrace"] = f
		task.Size = 0x30008
		copy(data[0x1fffc:], []byte{1, 2, 3, 4})
	case "missing-field":
		delete(task.Fields, "ptrace")
	case "name":
		copy(data[0xa018:], []byte{'a', 0xff, 'b', 0})
	}
	table.Types["task_struct"] = task
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
func TestLinuxPtracePinnedGenerator(t *testing.T) {
	for _, tc := range ptraceCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			e := openPsaux(t, ptraceFixture(t, tc, "x64", ""))
			var rows, relations []evidence.Row
			result, err := e.Run(context.Background(), "linux.ptrace", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
				rows = append(rows, r)
				if r.Cells["RecordType"].String() == "relationship" {
					relations = append(relations, r)
				}
				return nil
			}})
			bad := tc.Error || tc.Name == "unreadable-tracer-next"
			if (err != nil) != bad {
				t.Fatal(result, err)
			}
			if tc.Error {
				if len(relations) != 1 || relations[0].Cells["Flags"].Reason != "ptrace_flags_unknown" {
					t.Fatal(relations)
				}
				return
			}
			if len(relations) != len(tc.Rows) {
				t.Fatal(len(relations), tc.Rows, err)
			}
			for i, r := range relations {
				want := tc.Rows[i]
				c := r.Cells
				if c["Process"].String() != want.Process || c["PID"].String() != fmt.Sprint(want.PID) || c["TID"].String() != fmt.Sprint(want.TID) || c["Depth"].String() != fmt.Sprint(want.Depth) {
					t.Fatal(c, want)
				}
				for name, number := range map[string]*uint64{"Tracer TID": want.Tracer, "Tracee TID": want.Tracee} {
					if number == nil {
						if c[name].Reason != "not_available" {
							t.Fatal(c)
						}
					} else {
						got, err := c[name].Uint()
						if err != nil || got != *number {
							t.Fatal(c, number)
						}
					}
				}
				if want.Flags == nil {
					if c["Flags"].Reason != "not_available" {
						t.Fatal(c)
					}
				} else if c["Flags"].String() != *want.Flags {
					t.Fatal(c, want)
				}
				if want.Depth == 0 && r.ParentID != "" || want.Depth > 0 && r.ParentID != relations[i-1].ID {
					t.Fatal("renderer parent", r)
				}
			}

			native := filepath.Join(t.TempDir(), "native.jsonl")
			file, err := os.Create(native)
			if err != nil {
				t.Fatal(err)
			}
			encoder := json.NewEncoder(file)
			for _, r := range rows {
				if err = encoder.Encode(r); err != nil {
					t.Fatal(err)
				}
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			var referenceRows []any
			ancestors := map[uint64]map[string]any{}
			for _, w := range tc.Rows {
				node := map[string]any{"Process": w.Process, "PID": w.PID, "TID": w.TID, "Tracer TID": w.Tracer, "Tracee TID": w.Tracee, "Flags": w.Flags, "__children": []any{}}
				if w.Depth == 0 {
					referenceRows = append(referenceRows, node)
				} else {
					parent := ancestors[w.Depth-1]
					parent["__children"] = append(parent["__children"].([]any), node)
				}
				ancestors[w.Depth] = node
			}
			if referenceRows == nil {
				referenceRows = []any{}
			}
			reference := filepath.Join(t.TempDir(), "reference.json")
			encoded, err := json.Marshal(referenceRows)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(reference, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("python3", "../../tools/diff_results.py", "--native", native, "--reference", reference, "--mapping", "../../docs/diff/linux.ptrace.json").CombinedOutput()
			if err != nil {
				t.Fatal(string(output), err)
			}
			stored, err := e.Store.Query(context.Background(), evidence.Query{TaskID: result.Task.ID, Limit: 100})
			if err != nil || len(stored) != len(rows) {
				t.Fatal(err, len(stored), len(rows))
			}
			for _, r := range stored {
				if err = r.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			if !bad {
				again, err := e.Run(context.Background(), "linux.ptrace", nil, engine.RunOptions{})
				if err != nil || !again.Reused {
					t.Fatal(again, err)
				}
			}
			if tc.Name == "duplicate-tracee-tid" {
				a := relations[0].Cells["Tracee"].Data.(map[string]evidence.Value)
				b := relations[1].Cells["Tracee"].Data.(map[string]evidence.Value)
				if a["TaskIdentity"].String() == b["TaskIdentity"].String() {
					t.Fatal("same PID on distinct objects must not share identity")
				}
			}
		})
	}
}

func TestLinuxPtraceFaultsAndArchitectures(t *testing.T) {
	var control ptraceCase
	for _, tc := range ptraceCases(t) {
		if tc.Name == "both" {
			control = tc
		}
	}
	for _, arch := range []string{"x64", "x86", "pae"} {
		t.Run(arch, func(t *testing.T) {
			f := ptraceFixture(t, control, arch, "")
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			result, err := e.Run(context.Background(), "linux.ptrace", nil, engine.RunOptions{})
			if err != nil || result.Task.State != "completed" {
				t.Fatal(result, err)
			}
		})
	}
	for _, fault := range []string{"signal", "bad-parent-field", "bad-parent", "null-parent", "bad-tail", "tracee-cycle", "tracee-partial", "thread-cycle", "thread-owner", "group-leader", "null-next", "bad-flags", "partial-flags", "missing-field", "name"} {
		t.Run(fault, func(t *testing.T) {
			e := openPsaux(t, ptraceFixture(t, control, "x64", fault))
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.ptrace", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			bad := fault != "signal" && fault != "name"
			if (err != nil) != bad {
				t.Fatal(result, err)
			}
			if fault == "bad-parent-field" {
				tracer := rows[0].Cells["Tracer"].Data.(map[string]evidence.Value)
				if tracer["Offset"].Reason != "tracer_pointer_unreadable" {
					t.Fatal(tracer)
				}
			}
			if fault == "name" && rows[0].Cells["Process"].String() != "a" {
				t.Fatal(rows[0])
			}
			if fault == "partial-flags" {
				fields := rows[0].Cells["FieldEvidence"].Data.(map[string]evidence.Value)
				capture := fields["ptrace"].Data.(map[string]evidence.Value)
				raw := capture["Raw"].Data.([]byte)
				if len(raw) != 4 || raw[0] != 1 || raw[3] != 4 || capture["ReadComplete"].Data != false {
					t.Fatal(capture)
				}
			}
			if fault == "tracee-partial" {
				fields := rows[0].Cells["FieldEvidence"].Data.(map[string]evidence.Value)
				failed := fields["FailedTracee"].Data.(map[string]evidence.Value)
				capture := failed["PIDField"].Data.(map[string]evidence.Value)
				if len(capture["Raw"].Data.([]byte)) != 4 || capture["ReadComplete"].Data != false {
					t.Fatal(capture)
				}
			}
			if fault == "bad-tail" || fault == "tracee-cycle" {
				if result.Task.State != "failed" || len(rows) < 3 || rows[1].Cells["RecordType"].String() != "relationship" || rows[1].Cells["TraceesComplete"].Data != false {
					t.Fatal(rows, result)
				}
			}
		})
	}
	e := openPsaux(t, ptraceFixture(t, control, "x64", ""))
	for _, p := range []map[string]string{{"max-nodes": "0"}, {"max-tasks": "0"}, {"max-relations": "1000001"}, {"max-tasks": "2"}, {"max-relations": "1"}, {"max-nodes": "1"}} {
		if _, err := e.Run(context.Background(), "linux.ptrace", p, engine.RunOptions{}); err == nil {
			t.Fatal(p)
		}
	}
	stop := errors.New("stop")
	if _, err := e.Run(context.Background(), "linux.ptrace", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { return stop }}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Run(ctx, "linux.ptrace", nil, engine.RunOptions{Fresh: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
