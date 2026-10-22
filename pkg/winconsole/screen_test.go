package winconsole

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
)

type screenControl struct {
	Layout, Scenario string
	Size             int
	Row, Screen      uint64
	Writes           []struct {
		Offset int
		Data   string
	}
	Holes   [][2]uint64
	Results map[string]result
}
type screenOracle struct {
	Commit  string
	Layouts map[string]struct {
		Source string
		SHA256 string
	}
	Cases []screenControl
}

func screenFixture(t testing.TB) screenOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/screen-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o screenOracle
	if err = json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	if o.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(o.Cases) != 209 || len(o.Layouts) != 11 {
		t.Fatal("screen oracle drift")
	}
	return o
}
func screenSetup(t testing.TB, o screenOracle, c screenControl) (ScreenReader, original) {
	t.Helper()
	layout, err := ParseScreenLayout([]byte(o.Layouts[c.Layout].Source))
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the exact pinned file bytes, including formatting.
	hash := sha256.Sum256([]byte(o.Layouts[c.Layout].Source))
	if layout.SHA256 != hex.EncodeToString(hash[:]) || layout.SHA256 != o.Layouts[c.Layout].SHA256 || layout.SHA256 != catalogPins[c.Layout].sha256 {
		t.Fatal("wrong source digest")
	}
	m := original{data: make([]byte, c.Size), holes: c.Holes}
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(m.data) || len(raw) > len(m.data)-w.Offset {
			t.Fatal("invalid screen oracle write")
		}
		copy(m.data[w.Offset:], raw)
	}
	return ScreenReader{Layer: m, Layout: layout}, m
}
func screenCompare(t *testing.T, c screenControl, name string, got any) {
	t.Helper()
	var want any
	if err := json.Unmarshal(c.Results[name].Value, &want); err != nil {
		t.Fatal(err)
	}
	if c.Scenario == "negative-length" && (name == "buffer_0_0" || name == "buffer_0_1") {
		// BufferDataLayer slices a negative length to empty bytes; the original
		// appends an invented empty row. Native stops with the acquired prefix.
		rows := want.([]any)
		if len(rows) != 3 || rows[2] != "" {
			t.Fatal("original negative-length behavior drift", rows)
		}
		want = rows[:2]
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("%s got %s want %s", name, raw, c.Results[name].Value)
	}
}
func verifyScreenRaw(t testing.TB, m original, row ScreenRow) {
	t.Helper()
	if row.Length < 0 || len(row.Raw) != int(row.Length)*3 {
		t.Fatal("invalid captured row length", row.Length, len(row.Raw))
	}
	raw := make([]byte, len(row.Raw))
	n, err := m.ReadAt(context.Background(), raw, row.CellsAddress)
	if err != nil || n != len(raw) || !bytes.Equal(raw, row.Raw) {
		t.Fatal("false screen cell capture", n, err)
	}
}
func TestOriginalConsoleScreenMethods(t *testing.T) {
	o := screenFixture(t)
	limits := ScreenLimits{MaxRows: 32767, MaxCells: 32767, MaxTextBytes: 1 << 20}
	for _, c := range o.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := screenSetup(t, o, c)
			for _, trim := range []bool{false, true} {
				name := "row"
				if trim {
					name = "row_trimmed"
				}
				row, err := r.Row(context.Background(), c.Row, 32767, trim)
				if (err != nil) != (c.Results[name].Error != "" || c.Scenario == "negative-length") {
					t.Fatal(name, err, c.Results[name].Error)
				}
				if c.Results[name].Error == "InvalidAddressException" && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("row read failure lost its cause", err)
				}
				if err == nil {
					screenCompare(t, c, name, row.Text)
					verifyScreenRaw(t, m, row)
				}
			}
			x, y, err := r.Dimensions(context.Background(), c.Screen)
			if (err != nil) != (c.Results["x"].Error != "" || c.Results["y"].Error != "") {
				t.Fatal("dimensions", err)
			}
			if err == nil {
				screenCompare(t, c, "x", x)
				screenCompare(t, c, "y", y)
			}
			for _, trimRows := range []bool{false, true} {
				for _, trimLines := range []bool{false, true} {
					name := fmt.Sprintf("buffer_%d_%d", boolInt(trimRows), boolInt(trimLines))
					buffer, err := r.Buffer(context.Background(), c.Screen, limits, trimRows, trimLines)
					// The original silently stops on row faults and treats a negative capacity
					// as an empty range. Native retains an explicit error with its partial rows.
					failed := c.Scenario == "negative-capacity" || c.Scenario == "negative-length" || c.Scenario == "unreadable-cells" || c.Scenario == "unreadable-row-length" || c.Scenario == "unreadable-pointer" || c.Scenario == "unreadable-second-row" || c.Scenario == "capacity-hole" || c.Scenario == "start-hole"
					if failed != (err != nil) {
						t.Fatal(name, "failure mismatch", err)
					}
					text := []string{}
					for _, row := range buffer.AcquiredRows {
						verifyScreenRaw(t, m, row)
					}
					for _, row := range buffer.Rows {
						text = append(text, row.Text)
						verifyScreenRaw(t, m, row)
					}
					if c.Results[name].Error == "" {
						screenCompare(t, c, name, text)
					} else if err == nil {
						t.Fatal("original failure lost", name)
					}
				}
			}
		})
	}
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type screenCancelLayer struct {
	original
	cancel context.CancelFunc
}

type screenPartialLayer struct{ original }

func (m screenPartialLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == 0x8000 && len(p) > 3 {
		n, _ := m.original.ReadAt(ctx, p[:3], at)
		return n, io.ErrUnexpectedEOF
	}
	return m.original.ReadAt(ctx, p, at)
}

func (m screenCancelLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	n, err := m.original.ReadAt(ctx, p, at)
	if at == 0x8000 {
		m.cancel()
	}
	return n, err
}

func TestScreenBoundsAndCancellation(t *testing.T) {
	o := screenFixture(t)
	c := o.Cases[0]
	r, _ := screenSetup(t, o, c)
	for _, limits := range []ScreenLimits{{}, {2, 32767, 1 << 20}, {32767, 1, 1 << 20}, {32767, 32767, 1}, {32768, 32767, 1 << 20}, {32767, 32768, 1 << 20}, {32767, 32767, 17 << 20}} {
		if _, err := r.Buffer(context.Background(), c.Screen, limits, true, true); err == nil {
			t.Fatal("screen bound ignored", limits)
		}
	}
	for _, cells := range []uint64{0, 1, 32768, ^uint64(0)} {
		if _, err := r.Row(context.Background(), c.Row, cells, true); err == nil {
			t.Fatal("cell bound ignored", cells)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Row(ctx, c.Row, 32767, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.Buffer(ctx, c.Screen, ScreenLimits{32767, 32767, 1 << 20}, true, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := r.Dimensions(ctx, c.Screen); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := screenOffset(0, -18); err == nil {
		t.Fatal("signed underflow")
	}
	if _, err := screenOffset(^uint64(0), 1); err == nil {
		t.Fatal("signed overflow")
	}
	if _, err := screenOffset(0, -1<<63); err == nil {
		t.Fatal("minimum signed offset")
	}
	r, m := screenSetup(t, o, c)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	r.Layer = screenCancelLayer{m, cancel}
	b, err := r.Buffer(ctx, c.Screen, ScreenLimits{3, 7, 39}, false, false)
	if !errors.Is(err, context.Canceled) || len(b.AcquiredRows) != 2 || b.AcquiredRows[0].Text != "middle " || b.FailedRow == nil || len(b.FailedRow.Raw) != 18 {
		t.Fatal("cancellation lost acquired prefix", err, b)
	}
	r.Layer = screenPartialLayer{m}
	partial, err := r.Row(context.Background(), c.Row, 32767, false)
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(partial.Raw) != 3 || partial.CellsAddress != 0x8000 || partial.Text != "" {
		t.Fatal("partial cell bytes lost", err, partial)
	}
	b, err = r.Buffer(context.Background(), c.Screen, ScreenLimits{3, 7, 39}, false, false)
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(b.AcquiredRows) != 2 || b.FailedRow == nil || !bytes.Equal(b.FailedRow.Raw, partial.Raw) {
		t.Fatal("failed buffer row bytes lost", err, b)
	}
	// Exact budgets allow the trailing zero-length row; one byte less fails
	// before its nonempty predecessor and preserves the acquired prefix.
	for _, c := range o.Cases {
		if c.Scenario != "normal" && c.Scenario != "trailing-empty" {
			continue
		}
		r, _ := screenSetup(t, o, c)
		b, err := r.Buffer(context.Background(), c.Screen, ScreenLimits{3, 7, 39}, false, false)
		if err != nil || len(b.Rows) != 3 || len(b.AcquiredRows) != 3 {
			t.Fatal("exact byte budget", c.Layout, c.Scenario, err)
		}
		b, err = r.Buffer(context.Background(), c.Screen, ScreenLimits{3, 7, 38}, false, false)
		if err == nil || len(b.Rows) == 0 || len(b.Rows) == 3 {
			t.Fatal("lost bounded prefix", err, b)
		}
	}
}
func TestScreenLayoutRejectsMalformedFields(t *testing.T) {
	o := screenFixture(t)
	raw := []byte(o.Layouts[o.Cases[0].Layout].Source)
	for _, bad := range [][]byte{nil, []byte("{}"), []byte("{"), bytes.Repeat([]byte("x"), 4<<20+1)} {
		if _, err := ParseScreenLayout(bad); err == nil {
			t.Fatal("accepted invalid layout")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4 },
		func(d map[string]any) { delete(d["user_types"].(map[string]any), "_ROW") },
		func(d map[string]any) {
			d["user_types"].(map[string]any)["_CHAR_ROW_CELL"].(map[string]any)["size"] = 4
		},
		func(d map[string]any) { d["base_types"].(map[string]any)["pointer"].(map[string]any)["kind"] = "float" },
		func(d map[string]any) {
			d["user_types"].(map[string]any)["_ROW"].(map[string]any)["fields"].(map[string]any)["CharRow"].(map[string]any)["offset"] = -2000000
		},
	} {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		bad, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseScreenLayout(bad); err == nil {
			t.Fatal("malformed field accepted")
		}
	}
}
func FuzzConsoleScreen(f *testing.F) {
	o := screenFixture(f)
	for _, index := range []uint8{0, 1, 7, 18, 19, 57, 133, 190, 208} {
		f.Add([]byte{}, index, uint16(0))
	}
	f.Fuzz(func(t *testing.T, payload []byte, index uint8, offset uint16) {
		if len(payload) > 256 {
			return
		}
		c := o.Cases[int(index)%len(o.Cases)]
		r, m := screenSetup(t, o, c)
		at := int(offset) % len(m.data)
		copy(m.data[at:], payload)
		r.Layer = m
		b, _ := r.Buffer(context.Background(), c.Screen, ScreenLimits{8, 256, 4096}, true, true)
		total := 0
		if len(b.Rows) > 8 {
			t.Fatal("unbounded rows")
		}
		for _, row := range b.AcquiredRows {
			total += len(row.Raw)
			verifyScreenRaw(t, m, row)
		}
		if total > 4096 {
			t.Fatal("unbounded text bytes")
		}
	})
}

func FuzzConsoleScreenLayout(f *testing.F) {
	o := screenFixture(f)
	f.Add([]byte(o.Layouts["consoles-win10-22000-x64"].Source))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4<<20+1 {
			return
		}
		layout, err := ParseScreenLayout(raw)
		if err != nil {
			return
		}
		r := ScreenReader{Layer: original{data: make([]byte, 128)}, Layout: layout}
		_, _ = r.Row(context.Background(), 0, 32, false)
		_, _, _ = r.Dimensions(context.Background(), 0)
		_, _ = r.Buffer(context.Background(), 0, ScreenLimits{8, 32, 1024}, false, false)
	})
}
