package wingui

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestGUIWindowOriginalByteBacked(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit  string
		Kernel  json.RawMessage
		Layouts map[string]string
		Cases   []struct {
			guiObjectCase
			Window uint64
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 312 {
		t.Fatal("window oracle drift")
	}
	base := guiObjectFixture{Kernel: fixture.Kernel}
	layouts := map[string]*Layout{}
	for name, digest := range fixture.Layouts {
		l, err := ParseWindowLayout(guiSource(t, name))
		if err != nil || l.SHA256 != digest {
			t.Fatal("window layout mismatch", err)
		}
		layouts[name] = l
	}
	for _, c := range fixture.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := guiObjectSetup(t, base, c.guiObjectCase, layouts[c.Layout])
			ctx := context.Background()
			check := func(key string, got any, nativeErr error) {
				t.Helper()
				want := c.Results[key]
				if want.Error != "" {
					if nativeErr == nil {
						t.Fatalf("%s: lost original exception %s", key, want.Error)
					}
					return
				}
				if string(want.Value) == "null" && nativeErr != nil {
					return
				}
				if nativeErr != nil && !(key == "name" && (c.Scenario == "direct-pointer-hole" || c.Scenario == "direct-buffer-hole")) {
					t.Fatalf("%s: unexpected native error: %v", key, nativeErr)
				}
				encoded, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				decode := func(b []byte) any {
					d := json.NewDecoder(bytes.NewReader(b))
					d.UseNumber()
					var v any
					if err := d.Decode(&v); err != nil {
						t.Fatal(err)
					}
					return v
				}
				if !reflect.DeepEqual(decode(encoded), decode(want.Value)) {
					t.Fatalf("%s got %s want %s (error %v)", key, encoded, want.Value, nativeErr)
				}
			}
			name, err := r.WindowName(ctx, c.Window)
			check("name", name.Text, err)
			desktop, err := r.WindowDesktop(ctx, c.Window)
			check("desktop", desktop, err)
			sid, err := r.WindowSession(ctx, c.Window)
			check("session", sid, err)
			proc, err := r.WindowProcedure(ctx, c.Window)
			check("procedure", proc, err)
			owner, err := r.WindowOwner(ctx, c.Window)
			check("owner", map[string]any{"process": owner.Process, "name": owner.Name, "pid": owner.PID}, err)
			top, err := r.DesktopWindow(ctx, c.Desktop)
			check("top", top, err)
			// Independently verify every successfully captured byte against the
			// original fixture, including failed operations' readable prefixes.
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

func TestGUIWindowPointersAllLayouts(t *testing.T) {
	fixture := guiObjectOracle(t)
	for name, digest := range fixture.Layouts {
		t.Run(name, func(t *testing.T) {
			l, err := ParseWindowLayout(guiSource(t, name))
			if err != nil {
				t.Fatal(err)
			}
			if l.SHA256 != digest {
				t.Fatal("layout digest changed")
			}
			m := &guiMemory{data: make([]byte, 0x10000)}
			r := Reader{Layout: l, Layer: m}
			o := &object.Reader{Symbols: l.Types}
			put := func(at uint64, typ, member string, value uint64) uint64 {
				t.Helper()
				f, err := o.Field(typ, member)
				if err != nil {
					t.Fatal(err)
				}
				size, err := o.Size(f.Type)
				if err != nil {
					t.Fatal(err)
				}
				if size == 4 {
					binary.LittleEndian.PutUint32(m.data[at+f.Offset:], uint32(value))
				} else {
					binary.LittleEndian.PutUint64(m.data[at+f.Offset:], value)
				}
				return at + f.Offset
			}
			const desktop, info, window, sub, station = uint64(0x1000), uint64(0x2000), uint64(0x3000), uint64(0x4000), uint64(0x5000)
			put(desktop, "tagDESKTOP", "pDeskInfo", info)
			put(info, "tagDESKTOPINFO", "spwnd", window)
			put(window, "tagWND", "head.rpdesk", desktop)
			put(desktop, "tagDESKTOP", "rpwinstaParent", station)
			put(station, "tagWINDOWSTATION", "dwSessionId", 7)
			procAt := put(window, "tagWND", "lpfnWndProc", 0xdeadbeef)
			if _, ok := l.Types.Types["tagWND"].Fields["subPointer"]; ok {
				put(window, "tagWND", "subPointer", sub)
				procAt = put(sub, "subTagWNDType", "lpfnWndProc", 0x123456789abcdef0)
			}
			got, err := r.DesktopWindow(context.Background(), desktop)
			if err != nil || got != window {
				t.Fatal(got, err)
			}
			sid, err := r.WindowSession(context.Background(), window)
			if err != nil || sid == nil || *sid != 7 {
				t.Fatal(sid, err)
			}
			want := binary.LittleEndian.Uint64(m.data[procAt:])
			got, err = r.WindowProcedure(context.Background(), window)
			if err != nil || got != want {
				t.Fatalf("procedure %x want %x: %v", got, want, err)
			}
			binary.LittleEndian.PutUint64(m.data[procAt:], 0)
			got, err = r.WindowProcedure(context.Background(), window)
			if err != nil || got != 0 {
				t.Fatal("readable zero", got, err)
			}
			m.holes = [][2]uint64{{procAt, 8}}
			if _, err := r.WindowProcedure(context.Background(), window); !errors.Is(err, memory.ErrUnmapped) {
				t.Fatal("lost procedure fault", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := r.DesktopWindow(ctx, desktop); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func TestGUIWindowLayoutRejectsMalformedFields(t *testing.T) {
	raw := guiSource(t, "gui-win10-19041-x64")
	for _, scenario := range []string{"missing", "overrun", "target", "embedded", "length"} {
		t.Run(scenario, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			fields := types["tagWND"].(map[string]any)["fields"].(map[string]any)
			switch scenario {
			case "missing":
				delete(fields, "head")
			case "overrun":
				fields["spwndNext"].(map[string]any)["offset"] = 1 << 20
			case "target":
				fields["spwndNext"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "tagDESKTOP"}}
			case "embedded":
				fields["head"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "_THRDESKHEAD"}}
			case "length":
				types["_LARGE_UNICODE_STRING"].(map[string]any)["fields"].(map[string]any)["Length"].(map[string]any)["type"] = map[string]any{"kind": "base", "name": "unsigned char"}
			}
			bad, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ParseWindowLayout(bad); err == nil {
				t.Fatal("accepted malformed window layout")
			}
		})
	}
}

func TestGUIWindowNameBoundsAndCancellation(t *testing.T) {
	l, err := ParseWindowLayout(guiSource(t, "gui-win7sp1-x64"))
	if err != nil {
		t.Fatal(err)
	}
	m := &guiMemory{data: make([]byte, 0x10000)}
	r := Reader{Layer: m, Layout: l}
	o := &object.Reader{Symbols: l.Types}
	f, err := o.Field("tagWND", "strName.Length")
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(m.data[0x1000+f.Offset:], 0xffffffff)
	if name, err := r.WindowName(context.Background(), 0x1000); err == nil || name.Text != nil {
		t.Fatal("oversized name accepted", name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := len(m.reads)
	if _, err := r.WindowName(ctx, 0x1000); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(m.reads) != n+1 {
		t.Fatal("continued reading after cancellation")
	}
}

func FuzzGUIWindowFields(f *testing.F) {
	fixture := guiObjectOracle(f)
	k, err := symbols.Parse(fixture.Kernel)
	if err != nil {
		f.Fatal(err)
	}
	var layouts []*Layout
	for _, name := range []string{"gui-win7sp1-x64", "gui-win10-19041-x64"} {
		l, err := ParseWindowLayout(guiSource(f, name))
		if err != nil {
			f.Fatal(err)
		}
		layouts = append(layouts, l)
	}
	f.Add([]byte{}, uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 512), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, which uint8) {
		if len(data) > 0x10000 {
			t.Skip()
		}
		m := &guiMemory{data: make([]byte, 0x20000)}
		copy(m.data[0x1000:], data)
		r := Reader{Layer: m, Layout: layouts[which%2], KernelSymbols: k}
		ctx := context.Background()
		_, _ = r.WindowName(ctx, 0x1000)
		_, _ = r.WindowProcedure(ctx, 0x1000)
		_, _ = r.WindowSession(ctx, 0x1000)
		_, _ = r.WindowOwner(ctx, 0x1000)
		_, _ = r.DesktopWindow(ctx, 0x1000)
		if len(m.reads) > 32 {
			t.Fatal("unbounded window field reads")
		}
	})
}
