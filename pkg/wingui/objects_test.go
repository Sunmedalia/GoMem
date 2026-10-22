package wingui

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type guiObjectCase struct {
	Layout, Scenario string
	Root, Desktop    uint64
	Size             int
	Holes            [][2]uint64
	Writes           []struct {
		Offset int
		Data   string
	}
	Results map[string]struct {
		Value json.RawMessage
		Error string
	}
}
type guiObjectFixture struct {
	Commit  string
	Kernel  json.RawMessage
	Layouts map[string]string
	Cases   []guiObjectCase
}

func guiObjectOracle(t testing.TB) guiObjectFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/object-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f guiObjectFixture
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 384 || len(f.Layouts) != 12 {
		t.Fatal("GUI object fixture drift")
	}
	return f
}

type guiRead struct {
	At   uint64
	Data []byte
	Err  error
}
type guiMemory struct {
	data  []byte
	holes [][2]uint64
	reads []guiRead
}

func (m *guiMemory) Name() string           { return "gui-byte-control" }
func (m *guiMemory) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(m.data))}} }
func (m *guiMemory) ReadAt(ctx context.Context, p []byte, at uint64) (n int, err error) {
	defer func() { m.reads = append(m.reads, guiRead{at, append([]byte(nil), p[:n]...), err}) }()
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if at > uint64(len(m.data)) || uint64(len(p)) > uint64(len(m.data))-at {
		return 0, io.ErrUnexpectedEOF
	}
	for _, h := range m.holes {
		if at < h[0]+h[1] && h[0] < at+uint64(len(p)) {
			return 0, memory.ErrUnmapped
		}
	}
	return copy(p, m.data[at:at+uint64(len(p))]), nil
}
func guiObjectSetup(t testing.TB, f guiObjectFixture, c guiObjectCase, l *Layout) (Reader, *guiMemory) {
	t.Helper()
	k, err := symbols.Parse(f.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	m := &guiMemory{data: make([]byte, c.Size), holes: c.Holes}
	for _, w := range c.Writes {
		data, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(m.data) || len(data) > len(m.data)-w.Offset {
			t.Fatal("invalid GUI object write")
		}
		copy(m.data[w.Offset:], data)
	}
	return Reader{Layer: m, Layout: l, KernelSymbols: k}, m
}
func guiEqual(t *testing.T, c guiObjectCase, key string, got any) {
	t.Helper()
	expected := c.Results[key]
	if expected.Error != "" {
		t.Fatal("unexpected original exception", key, expected.Error)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err = json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(expected.Value, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%s got %s want %s", key, data, expected.Value)
	}
}
func TestGUIObjectsOriginalByteBacked(t *testing.T) {
	f := guiObjectOracle(t)
	layouts := map[string]*Layout{}
	for name, digest := range f.Layouts {
		l, err := ParseLayout(guiSource(t, name))
		if err != nil || l.SHA256 != digest {
			t.Fatal("GUI original layout mismatch", err)
		}
		layouts[name] = l
	}
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := guiObjectSetup(t, f, c, layouts[c.Layout])
			ctx := context.Background()
			for _, item := range []struct {
				key  string
				call func(context.Context, uint64) (*uint64, error)
				at   uint64
			}{
				{"station_session", r.StationSession, c.Root}, {"desktop_session", r.DesktopSession, c.Desktop}, {"desktop_station", r.DesktopStation, c.Desktop},
			} {
				value, err := item.call(ctx, item.at)
				guiEqual(t, c, item.key, value)
				if (err != nil) != bytes.Equal(c.Results[item.key].Value, []byte("null")) {
					t.Fatal(item.key, "lost missing-read distinction", err)
				}
			}
			stationValid, stationErr := r.StationValid(ctx, c.Root)
			guiEqual(t, c, "station_valid", stationValid)
			if (stationErr != nil) != (c.Scenario == "session-hole" || c.Scenario == "parent-session-hole") {
				t.Fatal(stationErr)
			}
			desktopValid, desktopErr := r.DesktopValid(ctx, c.Desktop)
			guiEqual(t, c, "desktop_valid", desktopValid)
			if (desktopErr != nil) != (stationErr != nil || c.Scenario == "parent-hole") {
				t.Fatal(desktopErr)
			}
			for key, limit := range map[string]uint64{"traverse": 15, "traverse_one": 1, "traverse_zero": 0} {
				stations := []uint64{}
				err := r.TraverseStations(ctx, c.Root, limit, func(at uint64) error { stations = append(stations, at); return nil })
				guiEqual(t, c, key, stations)
				if (err != nil) != (c.Scenario == "next-hole" && limit > 0) {
					t.Fatal(key, err)
				}
			}
			threads := []ThreadOwner{}
			err := r.Threads(ctx, c.Desktop, 100, func(owner ThreadOwner) error { threads = append(threads, owner); return nil })
			guiEqual(t, c, "threads", threads)
			damaged := strings.Contains(c.Scenario, "hole") && c.Scenario != "session-hole" && c.Scenario != "next-hole" && c.Scenario != "parent-hole" && c.Scenario != "parent-session-hole" || (c.Scenario == "thread-cycle" || c.Scenario == "null-thread-head")
			if (err != nil) != damaged {
				t.Fatal("thread failure visibility", err)
			}
			for _, read := range m.reads {
				if read.Err == nil && (read.At > uint64(len(m.data)) || uint64(len(read.Data)) > uint64(len(m.data))-read.At || !bytes.Equal(read.Data, m.data[read.At:read.At+uint64(len(read.Data))])) {
					t.Fatal("original read mismatch")
				}
			}
		})
	}
}
func TestGUIObjectsBoundsCancellationAndEmitter(t *testing.T) {
	f := guiObjectOracle(t)
	c := f.Cases[0]
	l, err := ParseLayout(guiSource(t, c.Layout))
	if err != nil {
		t.Fatal(err)
	}
	r, m := guiObjectSetup(t, f, c, l)
	ctx := context.Background()
	emitted := 0
	err = r.Threads(ctx, c.Desktop, 1, func(ThreadOwner) error { emitted++; return nil })
	if err == nil || emitted != 1 {
		t.Fatal("thread bound lost prefix", emitted, err)
	}
	stop := errors.New("emitter stopped")
	for _, kind := range []string{"station", "thread"} {
		m.reads = nil
		emitted = 0
		emit := func() error { emitted++; return stop }
		if kind == "station" {
			err = r.TraverseStations(ctx, c.Root, 15, func(uint64) error { return emit() })
		} else {
			err = r.Threads(ctx, c.Desktop, 100, func(ThreadOwner) error { return emit() })
		}
		if !errors.Is(err, stop) || emitted != 1 {
			t.Fatal(kind, emitted, err)
		}
		if kind == "station" && len(m.reads) != 0 {
			t.Fatal("read after failed root emitter")
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		m.reads = nil
		emitted = 0
		if kind == "station" {
			err = r.TraverseStations(cancelled, c.Root, 15, func(uint64) error { emitted++; return nil })
		} else {
			err = r.Threads(cancelled, c.Desktop, 100, func(ThreadOwner) error { emitted++; return nil })
		}
		if !errors.Is(err, context.Canceled) || emitted != 0 {
			t.Fatal(kind, emitted, err)
		}
	}
	for _, kind := range []string{"station", "thread"} {
		cancelled, cancel := context.WithCancel(ctx)
		emitted = 0
		if kind == "station" {
			err = r.TraverseStations(cancelled, c.Root, 15, func(uint64) error { emitted++; cancel(); return nil })
		} else {
			err = r.Threads(cancelled, c.Desktop, 100, func(ThreadOwner) error { emitted++; cancel(); return nil })
		}
		cancel()
		if !errors.Is(err, context.Canceled) || emitted != 1 {
			t.Fatal("mid-stream cancellation", kind, emitted, err)
		}
	}
	for _, bound := range []uint64{0, 1000001} {
		if err = r.Threads(ctx, c.Desktop, bound, func(ThreadOwner) error { return nil }); err == nil {
			t.Fatal("invalid bound accepted")
		}
	}
	if err = r.TraverseStations(ctx, c.Root, 1000001, func(uint64) error { return nil }); err == nil {
		t.Fatal("invalid station bound accepted")
	}
	if err = r.Threads(ctx, c.Desktop, 1, nil); err == nil {
		t.Fatal("nil emitter accepted")
	}
	if err = r.TraverseStations(ctx, c.Root, 1, nil); err == nil {
		t.Fatal("nil emitter accepted")
	}
	if _, err = r.StationSession(ctx, math.MaxUint64); err == nil {
		t.Fatal("overflow accepted")
	}
	if err = (Reader{}).Threads(ctx, 0, 1, func(ThreadOwner) error { return nil }); err == nil {
		t.Fatal("empty reader accepted")
	}
	r.KernelSymbols = nil
	if err = r.Threads(ctx, c.Desktop, 1, func(ThreadOwner) error { return nil }); err == nil {
		t.Fatal("missing kernel accepted")
	}
}
func FuzzGUIObjects(f *testing.F) {
	fixture := guiObjectOracle(f)
	c := fixture.Cases[0]
	layout, err := ParseLayout(guiSource(f, c.Layout))
	if err != nil {
		f.Fatal(err)
	}
	r, source := guiObjectSetup(f, fixture, c, layout)
	f.Add(uint64(0x4000), uint64(0x8000), uint64(0), uint64(0), []byte{})
	f.Add(uint64(0), uint64(0x8000), uint64(0xa000), uint64(1), []byte{0xff})
	f.Fuzz(func(t *testing.T, station, desktop, hole, width uint64, patch []byte) {
		m := &guiMemory{data: append([]byte(nil), source.data...)}
		if len(patch) > 256 {
			patch = patch[:256]
		}
		if hole < uint64(len(m.data)) {
			copy(m.data[hole:], patch)
			if width > 0 {
				m.holes = [][2]uint64{{hole, 1 + width%32}}
			}
		}
		r.Layer = m
		_, _ = r.StationValid(context.Background(), station)
		_, _ = r.DesktopValid(context.Background(), desktop)
		count := 0
		_ = r.TraverseStations(context.Background(), station, 4, func(uint64) error {
			count++
			if count > 5 {
				return fmt.Errorf("station budget")
			}
			return nil
		})
		if count > 5 {
			t.Fatal("station bound exceeded")
		}
		count = 0
		_ = r.Threads(context.Background(), desktop, 4, func(owner ThreadOwner) error {
			count++
			if len(owner.RawName) > 256 {
				t.Fatal("name bound")
			}
			return nil
		})
		if count > 4 || len(m.reads) > 128 {
			t.Fatal("GUI read/node bound exceeded", count, len(m.reads))
		}
	})
}

func TestGUIThreadsRejectInvalidKernelTypes(t *testing.T) {
	f := guiObjectOracle(t)
	c := f.Cases[0]
	layout, err := ParseLayout(guiSource(t, c.Layout))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"width", "list-size", "name-scalar", "name-empty", "name-wide", "name-large"} {
		t.Run(mode, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(f.Kernel, &doc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			fields := types["_EPROCESS"].(map[string]any)["fields"].(map[string]any)
			ref := fields["ImageFileName"].(map[string]any)["type"].(map[string]any)
			switch mode {
			case "width":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["size"] = 4
			case "list-size":
				types["_LIST_ENTRY"].(map[string]any)["size"] = 8
			case "name-scalar":
				fields["ImageFileName"].(map[string]any)["type"] = map[string]any{"kind": "base", "name": "u8"}
			case "name-empty":
				ref["count"] = 0
			case "name-wide":
				ref["subtype"] = map[string]any{"kind": "base", "name": "u64"}
				ref["count"] = 2
			case "name-large":
				ref["count"] = 257
				types["_EPROCESS"].(map[string]any)["size"] = 1024
			}
			encoded, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			f.Kernel = encoded
			r, _ := guiObjectSetup(t, f, c, layout)
			emitted := 0
			err = r.Threads(context.Background(), c.Desktop, 10, func(ThreadOwner) error { emitted++; return nil })
			if err == nil || emitted != 0 {
				t.Fatal("invalid kernel accepted", err, emitted)
			}
		})
		// Each malformed control starts from the unchanged original kernel.
		f = guiObjectOracle(t)
	}
}
