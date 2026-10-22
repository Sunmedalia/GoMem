package winconsole

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

type original struct {
	data  []byte
	holes [][2]uint64
}

func (m original) Name() string           { return "original" }
func (m original) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(m.data))}} }
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

type result struct {
	Value json.RawMessage
	Error string
}
type control struct {
	Layout, Scenario string
	Size             int
	Writes           []struct {
		Offset int
		Data   string
	}
	Holes   [][2]uint64
	Results map[string]result
}
type oracle struct {
	Commit  string
	Layouts map[string]struct{ ISF json.RawMessage }
	Cases   []control
}

func fixture(t testing.TB) oracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/history-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o oracle
	if err = json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	if o.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(o.Cases) != 385 || len(o.Layouts) != 11 {
		t.Fatal("oracle drift")
	}
	return o
}
func setup(t testing.TB, o oracle, c control) (Reader, original) {
	t.Helper()
	table, err := ParseHistoryLayout(o.Layouts[c.Layout].ISF)
	if err != nil {
		t.Fatal(err)
	}
	m := original{data: make([]byte, c.Size), holes: c.Holes}
	for _, w := range c.Writes {
		b, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(m.data) || len(b) > len(m.data)-w.Offset {
			t.Fatal("invalid fixture write")
		}
		copy(m.data[w.Offset:], b)
	}
	return Reader{Objects: &object.Reader{Symbols: table, Layer: m}}, m
}
func compare(t *testing.T, c control, name string, value any, err error) {
	t.Helper()
	want := c.Results[name]
	if want.Error != "" {
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%s: expected read failure, got %v", name, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var a, b any
	json.Unmarshal(raw, &a)
	json.Unmarshal(want.Value, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%s got %s want %s", name, raw, want.Value)
	}
}
func TestOriginalCommandHistoryMethods(t *testing.T) {
	o := fixture(t)
	for _, c := range o.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := setup(t, o, c)
			ctx := context.Background()
			valid, err := r.ValidCommand(ctx, 0x1000)
			compare(t, c, "valid", valid, err)
			cmd, _ := r.Command(ctx, 0x1000)
			s, raw, err := r.Text(ctx, 0x1000)
			compare(t, c, "text", s, err)
			if err == nil && len(raw) > 0 { // Retained bytes must be independently readable at their source.
				at := uint64(0x1000)
				if cmd.Length >= 8 {
					at, e := r.Objects.Uint(ctx, 0x1000, "_COMMAND", "Pointer")
					if e != nil {
						t.Fatal(e)
					}
					b, e := memory.Read(ctx, m, at, len(raw))
					if e != nil || !reflect.DeepEqual(raw, b) {
						t.Fatal("pointer capture mismatch")
					}
				} else {
					b, e := memory.Read(ctx, m, at, len(raw))
					if e != nil || !reflect.DeepEqual(raw, b) {
						t.Fatal("inline capture mismatch")
					}
				}
			}
			h, _ := r.History(ctx, 0x2000)
			count, err := r.CommandCount(ctx, 0x2000)
			compare(t, c, "count", count, err)
			hv, err := r.ValidHistory(ctx, 0x2000, 50)
			compare(t, c, "history_valid", hv, err)
			s, _, err = r.Application(ctx, 0x2000)
			compare(t, c, "application", s, err)
			for _, active := range []bool{true, false} {
				var end *uint64
				name := "scan"
				if active {
					end = &h.End
					name = "active"
				}
				rows := []map[string]any{}
				err := r.WalkBucket(ctx, h, end, 100, func(i uint64, c Command) error {
					s, _, e := r.Text(ctx, c.Address)
					if e != nil {
						return e
					}
					rows = append(rows, map[string]any{"index": i, "address": c.Address, "valid": c.Valid(), "text": s})
					return nil
				})
				compare(t, c, name, rows, err)
			}
		})
	}
}
func TestHistoryBoundsAndTermination(t *testing.T) {
	o := fixture(t)
	r, _ := setup(t, o, o.Cases[0])
	ctx := context.Background()
	h, err := r.History(ctx, 0x2000)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("emitter")
	if err := r.WalkBucket(ctx, h, nil, 100, func(uint64, Command) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	stop := h.Begin + 1000
	if err := r.WalkBucket(ctx, h, &stop, 1, func(uint64, Command) error { return nil }); err == nil {
		t.Fatal("slot limit ignored")
	}
	h.Maximum = ^uint64(0)
	if err := r.WalkBucket(ctx, h, nil, 100, func(uint64, Command) error { return nil }); err == nil {
		t.Fatal("capacity overflow ignored")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := r.Text(canceled, 0x1000); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := r.WalkBucket(canceled, h, nil, 100, func(uint64, Command) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	h.Maximum = 1
	canceled, cancel = context.WithCancel(ctx)
	if err := r.WalkBucket(canceled, h, nil, 100, func(uint64, Command) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, limit := range []uint64{0, 1000001} {
		if err := r.WalkBucket(ctx, h, nil, limit, func(uint64, Command) error { return nil }); err == nil {
			t.Fatal("invalid limit")
		}
	}
}
func FuzzHistoryBucket(f *testing.F) {
	o := fixture(f)
	r, m := setup(f, o, o.Cases[0])
	h, err := r.History(context.Background(), 0x2000)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint64(0x3000), uint64(0x3040), uint64(1), []byte("command"))
	f.Add(^uint64(0)-10, ^uint64(0), ^uint64(0), []byte{})
	f.Fuzz(func(t *testing.T, begin, end, maximum uint64, data []byte) {
		local := append([]byte(nil), m.data...)
		copy(local[0x3000:], data)
		reader := Reader{Objects: &object.Reader{Layer: original{data: local}, Symbols: r.Objects.Symbols}}
		h := h
		h.Begin, h.Capacity, h.Maximum = begin, end, maximum
		emitted := 0
		_ = reader.WalkBucket(context.Background(), h, nil, 32, func(i uint64, c Command) error {
			emitted++
			if emitted > 32 || i >= 32 || !c.Valid() {
				t.Fatal("invalid output")
			}
			_, raw, _ := reader.Text(context.Background(), c.Address)
			if len(raw) > 2046 {
				t.Fatal("unbounded text")
			}
			return nil
		})
		if emitted > 32 {
			t.Fatal("unbounded walk")
		}
	})
}

func TestHistoryLayoutRejectsMalformedTypes(t *testing.T) {
	o := fixture(t)
	for _, scenario := range []string{"missing-command", "negative-command-offset", "zero-command-size", "pointer-width"} {
		t.Run(scenario, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(o.Layouts[o.Cases[0].Layout].ISF, &document); err != nil {
				t.Fatal(err)
			}
			types := document["user_types"].(map[string]any)
			command := types["_COMMAND"].(map[string]any)
			switch scenario {
			case "missing-command":
				delete(types, "_COMMAND")
			case "negative-command-offset":
				command["fields"].(map[string]any)["Length"].(map[string]any)["offset"] = -1
			case "zero-command-size":
				command["size"] = 0
			case "pointer-width":
				document["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			table, err := ParseHistoryLayout(raw)
			if err != nil {
				return
			}
			reader := Reader{Objects: &object.Reader{Symbols: table, Layer: originalLayerForMalformed()}}
			if _, err := reader.CommandCount(context.Background(), 0); err == nil {
				t.Fatal("malformed layout accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte("{"), make([]byte, 4<<20+1)} {
		if _, err := ParseHistoryLayout(raw); err == nil {
			t.Fatal("invalid JSON bounds accepted")
		}
	}
}

func originalLayerForMalformed() memory.MemoryLayer { return original{data: make([]byte, 256)} }
