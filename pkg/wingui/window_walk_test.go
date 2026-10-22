package wingui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
)

type windowWalkRow struct {
	Offset, Address uint64
	Name            *string
}
type windowWalkCase struct {
	guiObjectCase
	MaxWindows   uint64 `json:"max_windows"`
	Rows, Prefix []windowWalkRow
	Error        string
}
type windowWalkFixture struct {
	Commit  string
	Kernel  json.RawMessage
	Layouts map[string]string
	Cases   []windowWalkCase
}

func windowWalkOracle(t testing.TB) windowWalkFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/window-walk-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f windowWalkFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 168 {
		t.Fatal("window walk fixture drift")
	}
	return f
}

func TestGUIWindowWalkOriginalMixedOffsets(t *testing.T) {
	f := windowWalkOracle(t)
	layouts := map[string]*Layout{}
	for name, digest := range f.Layouts {
		l, err := ParseWindowLayout(guiSource(t, name))
		if err != nil || l.SHA256 != digest {
			t.Fatal(err)
		}
		layouts[name] = l
	}
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := guiObjectSetup(t, guiObjectFixture{Kernel: f.Kernel}, c.guiObjectCase, layouts[c.Layout])
			var got []windowWalkRow
			err := r.Windows(context.Background(), c.Desktop, WindowWalkOptions{MaxWindows: c.MaxWindows, MaxSteps: 10000, MaxDepth: 32}, func(w WindowRef) error {
				got = append(got, windowWalkRow{w.Offset, w.Address, w.Name.Text})
				return nil
			})
			if err == nil {
				t.Fatal("missing explicit bound/read/cycle failure")
			}
			if len(got) < len(c.Prefix) || !reflect.DeepEqual(got[:len(c.Prefix)], c.Prefix) {
				t.Fatalf("adjacent prefix got %v want %v", got, c.Prefix)
			}
			slices.SortFunc(got, func(a, b windowWalkRow) int {
				if a.Offset < b.Offset {
					return -1
				}
				if a.Offset > b.Offset {
					return 1
				}
				if a.Address < b.Address {
					return -1
				}
				if a.Address > b.Address {
					return 1
				}
				return 0
			})
			if !reflect.DeepEqual(got, c.Rows) {
				actual, _ := json.Marshal(got)
				expected, _ := json.Marshal(c.Rows)
				t.Fatalf("entities got %s want %s; native error %v", actual, expected, err)
			}
			if len(m.reads) > 10000 {
				t.Fatal("unbounded reads")
			}
			for _, read := range m.reads {
				if read.At > uint64(len(m.data)) || uint64(len(read.Data)) > uint64(len(m.data))-read.At {
					t.Fatal("capture outside source")
				}
				if !bytes.Equal(read.Data, m.data[read.At:read.At+uint64(len(read.Data))]) {
					t.Fatal("capture differs from source")
				}
			}
		})
	}
}

func FuzzGUIWindowTraversal(f *testing.F) {
	fixture := windowWalkOracle(f)
	c := fixture.Cases[0]
	l, err := ParseWindowLayout(guiSource(f, c.Layout))
	if err != nil {
		f.Fatal(err)
	}
	r, seed := guiObjectSetup(f, guiObjectFixture{Kernel: fixture.Kernel}, c.guiObjectCase, l)
	f.Add(c.Desktop, uint64(0x10000), []byte{}, uint8(0))
	f.Add(c.Desktop, uint64(0x10000), bytes.Repeat([]byte{0xff}, 128), uint8(1))
	f.Fuzz(func(t *testing.T, desktop, patchAt uint64, patch []byte, hole uint8) {
		if len(patch) > 128 {
			patch = patch[:128]
		}
		m := &guiMemory{data: append([]byte(nil), seed.data...), holes: append([][2]uint64(nil), seed.holes...)}
		if patchAt < uint64(len(m.data)) {
			copy(m.data[patchAt:], patch)
			if hole != 0 {
				m.holes = append(m.holes, [2]uint64{patchAt, uint64(hole)})
			}
		}
		r.Layer = m
		count := 0
		_ = r.Windows(context.Background(), desktop, WindowWalkOptions{MaxWindows: 16, MaxSteps: 512, MaxDepth: 16}, func(w WindowRef) error {
			count++
			if len(w.Name.Raw) > 65535 {
				t.Fatal("name allocation bound")
			}
			return nil
		})
		if count > 16 || len(m.reads) > 4096 {
			t.Fatal("unbounded window traversal", count, len(m.reads))
		}
	})
}

func TestGUIWindowWalkCancelEmitterAndBounds(t *testing.T) {
	f := windowWalkOracle(t)
	c := f.Cases[0]
	l, err := ParseWindowLayout(guiSource(t, c.Layout))
	if err != nil {
		t.Fatal(err)
	}
	r, m := guiObjectSetup(t, guiObjectFixture{Kernel: f.Kernel}, c.guiObjectCase, l)
	opts := WindowWalkOptions{MaxWindows: 16, MaxSteps: 10000, MaxDepth: 32}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Windows(ctx, c.Desktop, opts, func(WindowRef) error { t.Fatal("emitted after cancel"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(m.reads) != 0 {
		t.Fatal("read after cancel")
	}
	ctx, cancel = context.WithCancel(context.Background())
	countAfterCancel := 0
	if err := r.Windows(ctx, c.Desktop, opts, func(WindowRef) error { countAfterCancel++; cancel(); return nil }); !errors.Is(err, context.Canceled) || countAfterCancel != 1 {
		t.Fatal("mid-stream cancellation", countAfterCancel, err)
	}
	sentinel := fmt.Errorf("emitter sentinel")
	count := 0
	if err := r.Windows(context.Background(), c.Desktop, opts, func(WindowRef) error { count++; return sentinel }); !errors.Is(err, sentinel) || count != 1 {
		t.Fatal(count, err)
	}
	for _, bad := range []WindowWalkOptions{{}, {MaxWindows: 1000001, MaxSteps: 1, MaxDepth: 1}, {MaxWindows: 1, MaxSteps: 10000001, MaxDepth: 1}, {MaxWindows: 1, MaxSteps: 1, MaxDepth: 257}} {
		n := len(m.reads)
		if err := r.Windows(context.Background(), c.Desktop, bad, func(WindowRef) error { t.Fatal("bad bound emitted"); return nil }); err == nil {
			t.Fatal("accepted bad bounds")
		}
		if len(m.reads) != n {
			t.Fatal("read with bad bound")
		}
	}
	opts.MaxSteps = 1
	if err := r.Windows(context.Background(), c.Desktop, opts, func(WindowRef) error { t.Fatal("emitted beyond step bound"); return nil }); err == nil {
		t.Fatal("missing step bound")
	}
	for _, childCase := range f.Cases {
		if childCase.Layout != c.Layout || childCase.Scenario != "child" {
			continue
		}
		reader, _ := guiObjectSetup(t, guiObjectFixture{Kernel: f.Kernel}, childCase.guiObjectCase, l)
		count := 0
		err := reader.Windows(context.Background(), childCase.Desktop, WindowWalkOptions{MaxWindows: 16, MaxSteps: 10000, MaxDepth: 1}, func(WindowRef) error { count++; return nil })
		if err == nil || count != 1 {
			t.Fatal("depth bound", count, err)
		}
	}
}
