package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/wincallbacks"
)

type callbackObjectLayer struct {
	flatMemory
	holes [][2]uint64
}

func (l callbackObjectLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	for _, h := range l.holes {
		if at < h[0]+h[1] && h[0] < at+uint64(len(p)) {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return l.flatMemory.ReadAt(ctx, p, at)
}

type callbackObjectWrite struct {
	Offset int
	Data   string
}
type callbackObjectControl struct {
	Layout         int
	Type, Scenario string
	Size           int
	Allocation     []callbackObjectWrite `json:"allocation_writes"`
	Kernel         []callbackObjectWrite `json:"kernel_writes"`
	Holes          [][2]uint64
	Valid          bool
	Row            []json.RawMessage
	Error          *struct{ Type, Message string }
}
type callbackObjectLayout struct {
	Width      int
	HeaderMode string          `json:"header_mode"`
	Kernel     json.RawMessage `json:"kernel_isf"`
	Callback   json.RawMessage `json:"callback_isf"`
}

func callbackObjectControls(t testing.TB) ([]callbackObjectLayout, []callbackObjectControl) {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-callback-object-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit  string
		Layouts []callbackObjectLayout
		Cases   []callbackObjectControl
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Layouts) != 6 || len(f.Cases) != 360 {
		t.Fatal("callback object oracle drift")
	}
	return f.Layouts, f.Cases
}
func callbackObjectSetup(t testing.TB, l callbackObjectLayout, c callbackObjectControl) (plugin.Environment, *wincallbacks.Table, poolHit) {
	t.Helper()
	k, err := symbols.Parse(l.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	table, err := wincallbacks.Parse(l.Callback, k)
	if err != nil {
		t.Fatal(err)
	}
	makeLayer := func(writes []callbackObjectWrite, holes [][2]uint64) callbackObjectLayer {
		data := make(flatMemory, c.Size)
		for _, w := range writes {
			raw, err := hex.DecodeString(w.Data)
			if err != nil || w.Offset < 0 || w.Offset > len(data) || len(raw) > len(data)-w.Offset {
				t.Fatal("invalid callback oracle write")
			}
			copy(data[w.Offset:], raw)
		}
		return callbackObjectLayer{data, holes}
	}
	kernel := makeLayer(c.Kernel, nil)
	allocation := makeLayer(c.Allocation, c.Holes)
	env := plugin.Environment{Kernel: kernel, Symbols: k, Objects: &object.Reader{Layer: kernel, Symbols: k}}
	return env, table, poolHit{object: 0x1000, typ: c.Type, scan: &object.Reader{Layer: allocation, Symbols: table}, native: kernel}
}
func callbackOracleValue(t testing.TB, raw json.RawMessage) evidence.Value {
	t.Helper()
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return evidence.Text(text)
	}
	var missing struct{ Missing string }
	if err := json.Unmarshal(raw, &missing); err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{"NotApplicableValue": "not_applicable", "UnparsableValue": "unparsable", "UnreadableValue": "unreadable"}
	reason, ok := reasons[missing.Missing]
	if !ok {
		t.Fatalf("unknown oracle value %s", raw)
	}
	return evidence.Missing(reason, nil)
}
func TestCallbackObjectsActualProcessors(t *testing.T) {
	layouts, cases := callbackObjectControls(t)
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d/width%d/%s/%s/%s", i, layouts[c.Layout].Width, layouts[c.Layout].HeaderMode, c.Type, c.Scenario), func(t *testing.T) {
			env, table, hit := callbackObjectSetup(t, layouts[c.Layout], c)
			got, err := callbackPoolObject(context.Background(), env, table, hit, map[int]string{1: "Driver", 2: "Device", 3: "File"})
			if !c.Valid {
				if got.valid {
					t.Fatal("accepted object rejected by original validity check")
				}
				return
			}
			if c.Error != nil {
				if err == nil {
					t.Fatalf("original %s must retain an explicit error", c.Error.Type)
				}
				if c.Type == "_NOTIFY_ENTRY_HEADER" && c.Scenario == "no-name-info" {
					if !got.valid || got.address != 0x8800 || got.detail.Reason != "unreadable" {
						t.Fatal("lost callback when name-info unavailable", got)
					}
				} else if got.valid {
					t.Fatal("unreadable callback field emitted as valid")
				}
				return
			}
			if !got.valid || len(c.Row) != 3 {
				t.Fatal("lost original callback", got, err)
			}
			var address uint64
			if err := json.Unmarshal(c.Row[1], &address); err != nil {
				t.Fatal(err)
			}
			typ, detail := callbackOracleValue(t, c.Row[0]), callbackOracleValue(t, c.Row[2])
			if got.address != address || got.typ.String() != typ.String() || got.typ.Reason != typ.Reason || got.detail.String() != detail.String() && got.detail.Reason == "" || got.detail.Reason != detail.Reason {
				t.Fatalf("processor differs: got %#v want %s", got, c.Row)
			}
			// The baseline catches some read failures and substitutes an absent value.
			// Native rows preserve that value and also fail the enclosing task.
			failed := c.Type == "_SHUTDOWN_PACKET" && (c.Scenario == "bad-name" || c.Scenario == "bad-driver" || c.Scenario == "bad-field") || c.Type == "_NOTIFY_ENTRY_HEADER" && (c.Scenario == "bad-driver" || c.Scenario == "bad-name" && layouts[c.Layout].HeaderMode != "encoded-index")
			if (err != nil) != failed {
				t.Fatalf("read failure completeness: %v", err)
			}
		})
	}
}

var _ memory.MemoryLayer = callbackObjectLayer{}

func TestCallbackProjectionAliasesAndOverlappingModules(t *testing.T) {
	var rows []evidence.Row
	trace := &poolScannerAnalysis{ctx: context.Background(), maxRows: 100, out: func(r evidence.Row) error { rows = append(rows, r); return nil }}
	a := callbackAnalysis{trace: trace, modules: []kernelModule{{"first", 0x8000, 0x1000}, {"overlap", 0x8000, 0x2000}}, symbols: map[uint64][]string{0x800: {"alias1", "alias2"}}, layout: "fixed"}
	if err := a.emit(0x1000, "allocation", "pool", evidence.Text("test"), 0x8800, evidence.Missing("not_applicable", nil), nil); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || a.callbacks != 1 || a.rows != 4 {
		t.Fatal("lost projection multiplicity", rows)
	}
	for i, row := range rows {
		if row.Cells["Module"].String() != []string{"first", "first", "overlap", "overlap"}[i] || row.Cells["Symbol"].String() != []string{"alias1", "alias2", "alias1", "alias2"}[i] {
			t.Fatal("aliased output cells", rows)
		}
	}
	rows[0].Cells["Module"] = evidence.Text("modified")
	if rows[1].Cells["Module"].String() != "first" {
		t.Fatal("rows share mutable cells")
	}
	if err := a.emit(0, "kernel", "index", evidence.Text("outside"), 0, evidence.Text(""), nil); err != nil {
		t.Fatal(err)
	}
	if rows[4].Cells["Module"].Reason != "not_available" || rows[4].Cells["Symbol"].Reason != "not_available" {
		t.Fatal("outside address attribution")
	}
}

func TestCallbackProjectionTerminalErrors(t *testing.T) {
	sentinel := fmt.Errorf("output stopped")
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		if cancelled {
			cancel()
		}
		trace := &poolScannerAnalysis{ctx: ctx, maxRows: 100, out: func(evidence.Row) error { calls++; return sentinel }}
		a := callbackAnalysis{trace: trace, modules: []kernelModule{{"a", 0x8000, 0x1000}, {"b", 0x8000, 0x1000}}, symbols: map[uint64][]string{0: {"one", "two"}}}
		err := a.emit(0, "kernel", "index", evidence.Text("test"), 0x8000, evidence.Text(""), nil)
		cancel()
		if err == nil || cancelled && calls != 0 || !cancelled && calls != 1 {
			t.Fatal("emitter/cancellation was not terminal", calls, err)
		}
	}
}

func FuzzCallbackPoolObjects(f *testing.F) {
	layouts, cases := callbackObjectControls(f)
	for _, i := range []int{0, 48, 60, 108, 120, 168, 180, 228, 240, 288, 300, 348} {
		f.Add(uint16(i), uint16(0), []byte{0})
	}
	f.Fuzz(func(t *testing.T, which, offset uint16, mutation []byte) {
		c := cases[int(which)%len(cases)]
		env, table, hit := callbackObjectSetup(t, layouts[c.Layout], c)
		layer := hit.scan.Layer.(callbackObjectLayer)
		if len(mutation) > 256 {
			mutation = mutation[:256]
		}
		at := 0x1000 + int(offset)%256
		copy(layer.flatMemory[at:], mutation)
		hit.scan.Layer = layer
		// Verify malformed fields, pointer arithmetic and Unicode reads remain bounded
		// in the source/native layers. Errors and rejected candidates are legitimate.
		_, _ = callbackPoolObject(context.Background(), env, table, hit, map[int]string{1: "Driver", 2: "Device", 3: "File"})
	})
}
