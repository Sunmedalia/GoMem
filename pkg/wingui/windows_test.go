package wingui

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

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
