package wincallbacks

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type control struct {
	Width         int
	Vista, Legacy bool
	Scenario      string
	Size          int
	KernelBase    uint64          `json:"kernel_base"`
	Kernel        json.RawMessage `json:"kernel_isf"`
	Layout        json.RawMessage `json:"callback_isf"`
	Writes        []struct {
		Offset int
		Data   string
	}
	Holes   [][2]uint64
	Results []struct {
		Method string
		Rows   [][]json.RawMessage
		Error  *struct{ Type, Message string }
	}
}
type original struct {
	data  []byte
	holes [][2]uint64
}

func (m original) Name() string { return "original" }
func (m original) Ranges() []memory.Range {
	return []memory.Range{{Start: 0, Length: uint64(len(m.data))}}
}
func (m original) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at > uint64(len(m.data)) || uint64(len(p)) > uint64(len(m.data))-at {
		return 0, io.ErrUnexpectedEOF
	}
	for _, h := range m.holes {
		if at < h[0]+h[1] && h[0] < at+uint64(len(p)) {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return copy(p, m.data[at:at+uint64(len(p))]), nil
}
func controls(t testing.TB) []control {
	t.Helper()
	raw, err := os.ReadFile("testdata/index-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []control
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 88 {
		t.Fatal("callback fixture drift")
	}
	return fixture.Cases
}
func setup(t testing.TB, c control) (*Index, original) {
	t.Helper()
	kernel, err := symbols.Parse(c.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	table, err := Parse(c.Layout, kernel)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, c.Size)
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(data) || len(raw) > len(data)-w.Offset {
			t.Fatal("invalid fixture write")
		}
		copy(data[w.Offset:], raw)
	}
	layer := original{data: data, holes: c.Holes}
	return &Index{Table: table, Layer: layer, KernelBase: c.KernelBase, Vista: c.Vista, MaxNodes: 10000}, layer
}

func TestActualCallbackIndexes(t *testing.T) {
	for i, c := range controls(t) {
		t.Run(fmt.Sprintf("%d/width%d/vista%t/legacy%t/%s", i, c.Width, c.Vista, c.Legacy, c.Scenario), func(t *testing.T) {
			x, _ := setup(t, c)
			var entries []Entry
			err := x.Walk(context.Background(), func(e Entry) error { entries = append(entries, e); return nil })
			bad := c.Scenario == "missing-callback" || c.Scenario == "missing-component" || c.Scenario == "missing-fastref" || c.Scenario == "bad-altitude" && !c.Legacy
			if (err != nil) != bad {
				t.Fatal("callback completeness", err)
			}
			var sourceLayout struct {
				Types map[string]struct {
					Fields map[string]struct{ Offset int } `json:"fields"`
				} `json:"user_types"`
			}
			if err := json.Unmarshal(c.Layout, &sourceLayout); err != nil {
				t.Fatal(err)
			}
			_, original := setup(t, c)
			for _, entry := range entries {
				typ, field := "_GENERIC_CALLBACK", "Callback"
				switch entry.Type {
				case "KeBugCheckCallbackListHead":
					typ, field = "_KBUGCHECK_CALLBACK_RECORD", "CallbackRoutine"
				case "KeBugCheckReasonCallbackListHead":
					typ, field = "_KBUGCHECK_REASON_CALLBACK_RECORD", "CallbackRoutine"
				case "CmRegisterCallback":
					typ, field = "_EX_CALLBACK_ROUTINE_BLOCK", "Function"
				case "CmRegisterCallbackEx":
					typ, field = "_CM_CALLBACK_ENTRY", "Function"
				}
				at := entry.Source + uint64(sourceLayout.Types[typ].Fields[field].Offset)
				if at > uint64(len(original.data)) || uint64(c.Width) > uint64(len(original.data))-at {
					t.Fatal("source outside fixture")
				}
				raw := original.data[at : at+uint64(c.Width)]
				var address uint64
				if c.Width == 4 {
					address = uint64(binary.LittleEndian.Uint32(raw))
				} else {
					address = binary.LittleEndian.Uint64(raw)
				}
				if address != entry.Callback {
					t.Fatal("callback does not match original source bytes")
				}
			}
			var got, want [][]any
			for _, e := range entries {
				var detail any
				if e.Detail.Kind == "missing" {
					if c.Scenario == "missing-component" && e.Type == "KeBugCheckReasonCallbackListHead" {
						detail = "unreadable"
					} else if c.Scenario == "bad-altitude" && !c.Legacy && e.Type == "CmRegisterCallbackEx" {
						detail = "Altitude: None"
					} else if e.Detail.Reason != "not_applicable" {
						t.Fatal("unexpected missing detail", e)
					}
				} else {
					detail = e.Detail.String()
				}
				got = append(got, []any{e.Type, e.Callback, detail})
			}
			for _, r := range c.Results {
				if r.Error != nil && (c.Scenario != "missing-callback" || r.Method != "list_notify_routines" || r.Error.Type != "InvalidAddressException") {
					t.Fatal("unexpected upstream exception", r.Error)
				}
				for _, row := range r.Rows {
					var name string
					var callback uint64
					var detail any
					if len(row) != 3 {
						t.Fatal("reference row shape")
					}
					json.Unmarshal(row[0], &name)
					json.Unmarshal(row[1], &callback)
					json.Unmarshal(row[2], &detail)
					if m, ok := detail.(map[string]any); ok {
						if m["missing"] != "UnreadableValue" {
							t.Fatal(detail)
						}
						detail = "unreadable"
					}
					want = append(want, []any{name, callback, detail})
				}
				if r.Error != nil {
					// Baseline aborts its notification method on the bad Callback
					// field. Native keeps the independent process-notify entry.
					want = append(want, []any{"PspCreateProcessNotifyRoutine", uint64(0x28200), nil})
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("actual callbacks differ\ngot %v\nwant %v", got, want)
			}
		})
	}
}

func TestCallbackIndexBoundsCancellationAndOutput(t *testing.T) {
	c := controls(t)[0]
	x, _ := setup(t, c)
	stop := errors.New("stop callback output")
	calls := 0
	if err := x.Walk(context.Background(), func(Entry) error { calls++; return stop }); !errors.Is(err, stop) || calls != 1 {
		t.Fatal(calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := x.Walk(ctx, func(Entry) error { t.Fatal("output after cancel"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	x.MaxNodes = 1
	if err := x.Walk(context.Background(), func(Entry) error { return nil }); err == nil {
		t.Fatal("node bound ignored")
	}
	x.MaxNodes = 0
	if err := x.Walk(context.Background(), func(Entry) error { return nil }); err == nil {
		t.Fatal("zero bound accepted")
	}
}

func TestCallbackNamespaceIsolation(t *testing.T) {
	c := controls(t)[0]
	var missing *symbols.ISF
	if _, err := Parse(c.Layout, missing); err == nil {
		t.Fatal("typed nil kernel accepted")
	}
	kernel, err := symbols.Parse(c.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	base := kernel.Bases["unsigned short"]
	base.Size = 4
	kernel.Bases["unsigned short"] = base
	table, err := Parse(c.Layout, kernel)
	if err != nil {
		t.Fatal(err)
	}
	k, err := table.Type("nt_symbols!_UNICODE_STRING")
	if err != nil {
		t.Fatal(err)
	}
	if k.Fields["Length"].Type.Name != "nt_symbols!unsigned short" {
		t.Fatal("kernel namespace lost")
	}
	local, err := table.Type("callbacks!unsigned short")
	if err != nil || local.Size != 2 {
		t.Fatal("local base shadowed", err)
	}
	remote, err := table.Type(k.Fields["Length"].Type.Name)
	if err != nil || remote.Size != 4 {
		t.Fatal("kernel base shadowed", err)
	}
	if _, err := table.Type("unknown!_LIST_ENTRY"); err == nil {
		t.Fatal("unknown namespace accepted")
	}
	other := controls(t)[44]
	if _, err := Parse(other.Layout, kernel); err == nil {
		t.Fatal("mixed pointer widths accepted")
	}
}

func TestCallbackIndexDamagedListAndSymbols(t *testing.T) {
	for _, mode := range []string{"cycle", "stride", "symbol-overflow", "missing-roots", "missing-count"} {
		t.Run(mode, func(t *testing.T) {
			x, data := setup(t, controls(t)[0])
			kernel := x.Table.kernel.(*symbols.ISF)
			switch mode {
			case "cycle":
				binary.LittleEndian.PutUint32(data.data[0x19000:], 0x19000)
			case "stride":
				typ := kernel.Types["_EX_FAST_REF"]
				typ.Size = 1 << 20
				kernel.Types["_EX_FAST_REF"] = typ
			case "symbol-overflow":
				kernel.Symbols["PspLoadImageNotifyRoutine"] = symbols.Symbol{Address: ^uint64(0)}
			case "missing-roots":
				kernel.Symbols = map[string]symbols.Symbol{}
			case "missing-count":
				kernel.Symbols = map[string]symbols.Symbol{"CallbackListHead": {Address: 0x2040}}
			}
			if err := x.Walk(context.Background(), func(Entry) error { return nil }); err == nil {
				t.Fatal("damaged callback index became complete")
			}
		})
	}
}

func FuzzCallbackIndexes(f *testing.F) {
	fixtures := controls(f)
	f.Add([]byte{0, 0, 0, 0}, uint8(0), uint8(0))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uint8(1), uint8(7))
	f.Fuzz(func(t *testing.T, payload []byte, region, variant uint8) {
		if len(payload) > 128 {
			return
		}
		c := fixtures[(int(variant)%8)*11]
		x, data := setup(t, c)
		at := []int{0x11000, 0x11100, 0x12000, 0x12040, 0x12080, 0x19000, 0x1a000, 0x18000}[int(region)%8]
		copy(data.data[at:], payload)
		x.MaxNodes = 512
		calls := 0
		_ = x.Walk(context.Background(), func(Entry) error {
			calls++
			if calls > 512 {
				t.Fatal("callback output bound bypassed")
			}
			return nil
		})
	})
}
