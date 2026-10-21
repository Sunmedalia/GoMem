package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
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

type iomemNode struct {
	Raw            string
	Start, End     uint64
	Child, Sibling int
	Invalid        bool
	UnreadableName bool `json:"unreadable_name"`
}
type iomemCase struct {
	Name  string
	Nodes []iomemNode
	Rows  []struct {
		Depth      uint64
		Name       *string
		Start, End uint64
	}
}

func iomemCases(t *testing.T) []iomemCase {
	t.Helper()
	raw, err := os.ReadFile("../plugins/testdata/linux-iomem-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct{ Cases []iomemCase }
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Cases) != 17 {
		t.Fatal(err)
	}
	return oracle.Cases
}

func iomemFixture(t *testing.T, nodes []iomemNode, arch, fault string) testfixture.Fixture {
	t.Helper()
	var f testfixture.Fixture
	var err error
	if arch == "x86" || arch == "pae" {
		f = linuxCapabilityFixture(t, arch)
	} else {
		f, err = testfixture.Write(t.TempDir(), "linux")
		if err != nil {
			t.Fatal(err)
		}
	}
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	u64 := symbols.TypeRef{Kind: "base", Name: "u64"}
	// Deliberately non-C ordering and 64-bit extents with 32-bit pointers.
	table.Types["resource"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"name": {Offset: 24, Type: ptr}, "start": {Offset: 8, Type: u64}, "end": {Offset: 40, Type: u64}, "child": {Offset: 0, Type: ptr}, "sibling": {Offset: 56, Type: ptr}}}
	table.Symbols["iomem_resource"] = symbols.Symbol{Address: 0x1d000}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	pointer := func(a, v uint64) {
		if arch == "x86" || arch == "pae" {
			binary.LittleEndian.PutUint32(data[a:], uint32(v))
		} else {
			put(a, v)
		}
	}
	address := func(i int) uint64 {
		if i < 0 {
			return 0
		}
		if nodes[i].Invalid {
			return 0x300000 + uint64(i)*0x80
		}
		return 0x1d000 + uint64(i)*0x80
	}
	for i, n := range nodes {
		if n.Invalid {
			continue
		}
		a := address(i)
		name := uint64(0x1e000 + i*0x100)
		raw, err := hex.DecodeString(n.Raw)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[name:], raw)
		if n.UnreadableName {
			name = 0x300000
		}
		pointer(a+24, name)
		put(a+8, n.Start)
		put(a+40, n.End)
		pointer(a, address(n.Child))
		pointer(a+56, address(n.Sibling))
	}
	switch fault {
	case "partial-name":
		pointer(0x1d018, 0x1fffe)
		copy(data[0x1fffe:], "xy")
	case "partial-nul":
		pointer(0x1d018, 0x1fffc)
		copy(data[0x1fffc:], "x\x00yz")
	case "missing-symbol":
		delete(table.Symbols, "iomem_resource")
	case "missing-field":
		delete(table.Types["resource"].Fields, "child")
	case "bad-start":
		f := table.Types["resource"].Fields["start"]
		f.Offset = 0x20000
		table.Types["resource"].Fields["start"] = f
	case "partial-start":
		f := table.Types["resource"].Fields["start"]
		f.Offset = 0x2ffc
		table.Types["resource"].Fields["start"] = f
		copy(data[0x1fffc:], []byte{1, 2, 3, 4})
	case "bad-sibling":
		f := table.Types["resource"].Fields["sibling"]
		f.Offset = 0x20000
		table.Types["resource"].Fields["sibling"] = f
	case "bad-child":
		f := table.Types["resource"].Fields["child"]
		f.Offset = 0x20000
		table.Types["resource"].Fields["child"] = f
	}
	if fault == "bad-start" || fault == "bad-child" || fault == "bad-sibling" || fault == "partial-start" {
		typ := table.Types["resource"]
		typ.Size = 0x20040
		table.Types["resource"] = typ
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

func TestLinuxIOMemPinnedTraversal(t *testing.T) {
	for _, tc := range iomemCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			e := openPsaux(t, iomemFixture(t, tc.Nodes, "x64", ""))
			var rows, entities []evidence.Row
			result, runErr := e.Run(context.Background(), "linux.iomem", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
				rows = append(rows, r)
				if r.Cells["RecordType"].String() == "resource" {
					entities = append(entities, r)
				}
				return nil
			}})
			bad := tc.Name == "self-child" || tc.Name == "self-sibling" || tc.Name == "ancestor-loop" || tc.Name == "shared-node" || tc.Name == "unreadable-name" || tc.Name == "bad-child"
			if (runErr != nil) != bad {
				t.Fatal(result, runErr)
			}
			if len(entities) != len(tc.Rows) {
				t.Fatalf("got %d resources, want %d: %v", len(entities), len(tc.Rows), runErr)
			}
			parents := map[uint64]string{}
			for i, r := range entities {
				want := tc.Rows[i]
				c := r.Cells
				start, _ := c["Start"].Uint()
				end, _ := c["End"].Uint()
				if c["Depth"].String() != fmt.Sprint(want.Depth) || start != want.Start || end != want.End {
					t.Fatal(i, c, want)
				}
				if want.Name == nil {
					if c["Name"].Kind != "missing" {
						t.Fatal(c)
					}
				} else if c["Name"].String() != *want.Name {
					t.Fatal(c, want)
				}
				if want.Depth > 0 && r.ParentID != parents[want.Depth-1] || want.Depth == 0 && r.ParentID != "" {
					t.Fatal("parent", r)
				}
				parents[want.Depth] = r.ID
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
				again, err := e.Run(context.Background(), "linux.iomem", nil, engine.RunOptions{})
				if err != nil || !again.Reused {
					t.Fatal(again, err)
				}
			}
		})
	}
}

func TestLinuxIOMemFaultsBoundsAndArchitectures(t *testing.T) {
	cases := iomemCases(t)
	for _, arch := range []string{"x64", "x86", "pae"} {
		t.Run(arch, func(t *testing.T) {
			f := iomemFixture(t, cases[1].Nodes, arch, "")
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, OS: "linux", Arch: arch, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			r, err := e.Run(context.Background(), "linux.iomem", nil, engine.RunOptions{})
			if err != nil || r.Task.State != "completed" {
				t.Fatal(r, err)
			}
		})
	}
	for _, fault := range []string{"partial-name", "partial-nul", "missing-symbol", "missing-field", "bad-start", "bad-child", "bad-sibling", "partial-start"} {
		t.Run(fault, func(t *testing.T) {
			e := openPsaux(t, iomemFixture(t, cases[1].Nodes, "x64", fault))
			var rows []evidence.Row
			result, err := e.Run(context.Background(), "linux.iomem", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err)
			}
			if fault == "partial-name" || fault == "partial-nul" {
				want := "xy"
				got := uint64(2)
				if fault == "partial-nul" {
					want = "x"
					got = 4
				}
				if rows[0].Cells["Name"].String() != want {
					t.Fatal(rows[0])
				}
				d := rows[0].Cells["NameEvidence"].Data.(map[string]evidence.Value)
				n, _ := d["CapturedBytes"].Uint()
				if n != got || d["ReadComplete"].Data != false {
					t.Fatal(d)
				}
			}
			if fault == "partial-start" {
				if len(rows) != 2 || rows[0].Cells["RecordType"].String() != "diagnostic" || rows[0].Cells["Start"].Reason != "resource_extent_unreadable" || rows[0].Cells["End"].Kind != "address" {
					t.Fatal(rows)
				}
				fields := rows[0].Cells["FieldEvidence"].Data.(map[string]evidence.Value)
				capture := fields["start"].Data.(map[string]evidence.Value)
				raw := capture["Raw"].Data.([]byte)
				if len(raw) != 4 || raw[0] != 1 || raw[3] != 4 || capture["ReadComplete"].Data != false {
					t.Fatal(capture)
				}
			}
			if fault == "bad-sibling" && len(rows) != 4 {
				t.Fatal("readable child branch must survive sibling failure", rows)
			}
			if fault == "bad-child" && len(rows) != 2 {
				t.Fatal("unreadable child must preserve root and summary", rows)
			}
		})
	}
	e := openPsaux(t, iomemFixture(t, cases[1].Nodes, "x64", ""))
	for _, p := range []map[string]string{{"max-nodes": "0"}, {"max-depth": "0"}, {"max-depth": "1025"}, {"max-nodes": "1000001"}, {"max-nodes": "1"}, {"max-depth": "1"}} {
		if _, err := e.Run(context.Background(), "linux.iomem", p, engine.RunOptions{}); err == nil {
			t.Fatal(p)
		}
	}
	stop := errors.New("stop")
	if _, err := e.Run(context.Background(), "linux.iomem", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { return stop }}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Run(ctx, "linux.iomem", nil, engine.RunOptions{Fresh: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
