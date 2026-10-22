package winconsole

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/object"
)

type relationControl struct {
	Layout, Scenario string
	Size             int
	Root, Exe, Alias uint64
	Holes            [][2]uint64
	Writes           []struct {
		Offset int
		Data   string
	}
	Results map[string]struct {
		Value json.RawMessage
		Error *string
	}
}
type relationOracle struct {
	Commit  string
	Layouts map[string]struct{ Source, SHA256 string }
	Cases   []relationControl
}

func relationFixture(t testing.TB) relationOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/relations-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o relationOracle
	if err = json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	if o.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(o.Cases) != 264 || len(o.Layouts) != 11 {
		t.Fatal("relation oracle drift")
	}
	return o
}
func relationSetup(t testing.TB, o relationOracle, c relationControl) (ConsoleReader, *ScreenLayout, original) {
	t.Helper()
	l, err := ParseConsoleLayout([]byte(o.Layouts[c.Layout].Source))
	if err != nil {
		t.Fatal(err)
	}
	screen, err := ParseScreenLayout([]byte(o.Layouts[c.Layout].Source))
	if err != nil {
		t.Fatal(err)
	}
	if l.SHA256 != screen.SHA256 || l.SHA256 != o.Layouts[c.Layout].SHA256 || l.SHA256 != catalogPins[c.Layout].sha256 {
		t.Fatal("wrong relation source digest")
	}
	m := original{data: make([]byte, c.Size), holes: c.Holes}
	for _, w := range c.Writes {
		raw, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(m.data) || len(raw) > len(m.data)-w.Offset {
			t.Fatal("bad relation source bytes")
		}
		copy(m.data[w.Offset:], raw)
	}
	return ConsoleReader{Layer: m, Layout: l}, screen, m
}
func relationCompare(t *testing.T, want json.RawMessage, got any) {
	t.Helper()
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err = json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("got %s want %s", raw, want)
	}
}
func TestOriginalConsoleRelationMethods(t *testing.T) {
	o := relationFixture(t)
	for _, c := range o.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, screen, m := relationSetup(t, o, c)
			links := []map[string]uint64{}
			err := r.WalkScreens(context.Background(), c.Root, screen, 16, func(link ScreenLink) error {
				raw := make([]byte, 8)
				n, err := m.ReadAt(context.Background(), raw, link.Address)
				if err != nil || n != 8 || binary.LittleEndian.Uint64(raw) != link.Target {
					t.Fatal("bad pointer source", link, err)
				}
				value, err := consoleRead(context.Background(), m, link.Address, 8)
				if err != nil || !reflect.DeepEqual(raw, value) {
					t.Fatal("pointer bytes mismatch")
				}
				links = append(links, map[string]uint64{"address": link.Address, "target": link.Target})
				return nil
			})
			expectedFailure := c.Results["screens"].Error != nil || c.Scenario == "screen-cycle" || c.Scenario == "alternate-cycle" || c.Scenario == "negative-capacity"
			if expectedFailure != (err != nil) {
				t.Fatal("screen failure mismatch", err)
			}
			want := c.Results["screens"].Value
			if c.Scenario == "negative-capacity" && c.Layout != "consoles-win10-17763-x64" {
				// Native rejects malformed capacity before emitting the second link.
				if len(links) != 1 || links[0]["target"] != 0x6000 {
					t.Fatal("negative capacity prefix", links)
				}
			} else {
				relationCompare(t, want, links)
			}
			for _, name := range []string{"source", "target", "exe"} {
				var address uint64
				var text *string
				var raw []byte
				var err error
				if name == "exe" {
					address, text, raw, err = r.ExeName(context.Background(), c.Exe)
				} else {
					field := "_ALIAS.Source"
					if name == "target" {
						field = "_ALIAS.Target"
					}
					address, text, raw, err = r.CommandText(context.Background(), c.Alias, field)
				}
				expected := c.Results[name]
				if (expected.Error != nil) != (err != nil) {
					t.Fatal(name, "error mismatch", err, expected.Error)
				}
				if expected.Error != nil {
					if *expected.Error == "AttributeError" && !errors.Is(err, ErrLegacyExeName) {
						t.Fatal("legacy exe error hidden", err)
					}
					if *expected.Error == "InvalidAddressException" && !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatal("alias read error cause lost", err)
					}
					continue
				}
				relationCompare(t, expected.Value, text)
				if len(raw) > 0 {
					at := address
					command := Reader{Objects: &object.Reader{Layer: r.Layer, Symbols: r.Layout.History}}
					length, err := command.Objects.Uint(context.Background(), address, "_COMMAND", "Length")
					if err != nil {
						t.Fatal(err)
					}
					if length >= 8 {
						at, err = command.Objects.Uint(context.Background(), address, "_COMMAND", "Pointer")
						if err != nil {
							t.Fatal(err)
						}
					}
					consoleCapture(t, m, at, raw)
				}
			}
		})
	}
}

func TestConsoleRelationBoundsCancellationAndFailures(t *testing.T) {
	o := relationFixture(t)
	c := o.Cases[0]
	r, screen, m := relationSetup(t, o, c)
	for _, bound := range []uint64{0, 1, 1000001} {
		count := 0
		err := r.WalkScreens(context.Background(), c.Root, screen, bound, func(ScreenLink) error { count++; return nil })
		if err == nil || count > 1 {
			t.Fatal("screen limit ignored", bound, count, err)
		}
	}
	sentinel := errors.New("emitter stopped")
	count := 0
	err := r.WalkScreens(context.Background(), c.Root, screen, 16, func(ScreenLink) error { count++; return sentinel })
	if !errors.Is(err, sentinel) || count != 1 {
		t.Fatal("emitter not terminal", err, count)
	}
	ctx, cancel := context.WithCancel(context.Background())
	count = 0
	err = r.WalkScreens(ctx, c.Root, screen, 16, func(ScreenLink) error { count++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || count != 1 {
		t.Fatal("cancellation not terminal", err, count)
	}
	if _, _, _, err := r.ExeName(ctx, c.Exe); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, _, err := r.CommandText(ctx, c.Alias, "_ALIAS.Source"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, _, err := r.CommandText(context.Background(), c.Root, "_CONSOLE_INFORMATION.Title"); err == nil {
		t.Fatal("pointer accepted as embedded command")
	}
	if err := r.WalkScreens(context.Background(), c.Root, nil, 16, func(ScreenLink) error { return nil }); err == nil {
		t.Fatal("nil screen layout accepted")
	}
	if err := r.WalkScreens(context.Background(), c.Root, screen, 16, nil); err == nil {
		t.Fatal("nil screen emitter accepted")
	}
	mismatch := *screen
	mismatch.SHA256 = "different-source"
	if err := r.WalkScreens(context.Background(), c.Root, &mismatch, 16, func(ScreenLink) error { return nil }); err == nil {
		t.Fatal("mixed layout sources accepted")
	}
	empty := ConsoleReader{}
	if _, _, _, err := empty.CommandText(context.Background(), 0, "_ALIAS.Source"); err == nil {
		t.Fatal("missing text environment accepted")
	}
	r.Layer = relationPartialLayer{m}
	address, text, raw, err := r.CommandText(context.Background(), c.Alias, "_ALIAS.Target")
	if !errors.Is(err, io.ErrUnexpectedEOF) || text != nil || len(raw) != 4 || address != c.Alias+48 || !reflect.DeepEqual(raw, m.data[0x13000:0x13004]) {
		t.Fatal("partial alias capture lost", address, text, raw, err)
	}
	// Prior cycle diagnostics must survive a later independent chain's read fault.
	for _, candidate := range o.Cases {
		if candidate.Layout == c.Layout && candidate.Scenario == "screen-cycle" {
			r, screen, m = relationSetup(t, o, candidate)
			field, err := screenOffset(0x6200, screen.fields["_SCREEN_INFORMATION.TextBufferInfo"])
			if err != nil {
				t.Fatal(err)
			}
			m.holes = append(m.holes, [2]uint64{field, 8})
			r.Layer = m
			err = r.WalkScreens(context.Background(), candidate.Root, screen, 16, func(ScreenLink) error { return nil })
			if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "cycle") {
				t.Fatal("prior failure discarded", err)
			}
			break
		}
	}
}

type relationPartialLayer struct{ original }

func (m relationPartialLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == 0x13000 && len(p) > 4 {
		n, _ := m.original.ReadAt(ctx, p[:4], at)
		return n, io.ErrUnexpectedEOF
	}
	return m.original.ReadAt(ctx, p, at)
}
func FuzzConsoleRelations(f *testing.F) {
	o := relationFixture(f)
	for _, index := range []uint8{0, 5, 6, 7, 21, 22, 100, 180, 241} {
		f.Add([]byte{}, index, uint32(0))
	}
	f.Fuzz(func(t *testing.T, payload []byte, index uint8, offset uint32) {
		if len(payload) > 256 {
			return
		}
		c := o.Cases[int(index)%len(o.Cases)]
		r, screen, m := relationSetup(t, o, c)
		copy(m.data[int(offset)%len(m.data):], payload)
		r.Layer = m
		count := 0
		_ = r.WalkScreens(context.Background(), c.Root, screen, 8, func(link ScreenLink) error { count++; return nil })
		if count > 8 {
			t.Fatal("unbounded screen chain")
		}
		_, _, raw, _ := r.ExeName(context.Background(), c.Exe)
		if len(raw) > 2046 {
			t.Fatal("unbounded exe bytes")
		}
		_, _, raw, _ = r.CommandText(context.Background(), c.Alias, "_ALIAS.Target")
		if len(raw) > 2046 {
			t.Fatal("unbounded alias bytes")
		}
	})
}
