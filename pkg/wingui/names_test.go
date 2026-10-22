package wingui

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type guiNameCase struct {
	Layout, Scenario string
	HeaderKind       string `json:"header_kind"`
	Kernel           json.RawMessage
	KernelBase       uint64 `json:"kernel_base"`
	Size             int
	Root, Desktop    uint64
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
type guiNameFixture struct {
	Commit string
	Cases  []guiNameCase
	Codec  []struct{ Raw, Text string }
}

func guiNameOracle(t testing.TB) guiNameFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/names-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f guiNameFixture
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 768 || len(f.Codec) != 512 {
		t.Fatal("GUI name fixture drift")
	}
	return f
}
func guiNameSetup(t testing.TB, c guiNameCase, l *Layout) (Reader, *guiMemory) {
	t.Helper()
	r, m := guiObjectSetup(t, guiObjectFixture{Kernel: c.Kernel}, guiObjectCase{Size: c.Size, Holes: c.Holes, Writes: c.Writes}, l)
	r.KernelBase = c.KernelBase
	return r, m
}
func TestGUINamesOriginalExecutiveAndDesktopMethods(t *testing.T) {
	f := guiNameOracle(t)
	layouts := map[string]*Layout{}
	for _, c := range f.Cases {
		if layouts[c.Layout] == nil {
			l, err := ParseLayout(guiSource(t, c.Layout))
			if err != nil {
				t.Fatal(err)
			}
			layouts[c.Layout] = l
		}
	}
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.HeaderKind+"/"+c.Scenario, func(t *testing.T) {
			r, m := guiNameSetup(t, c, layouts[c.Layout])
			compare := guiObjectCase{Layout: c.Layout, Scenario: c.Scenario, Results: c.Results}
			ctx := context.Background()
			name, err := r.ObjectName(ctx, c.Root)
			guiEqual(t, compare, "name", name.Text)
			nameFault := c.Scenario == "header-hole" || c.Scenario == "maximum-hole" || c.Scenario == "buffer-hole" || c.Scenario == "name-hole" || c.Scenario == "name-tail-hole" || c.HeaderKind == "infomask" && (c.Scenario == "table-hole" || c.Scenario == "mask-hole")
			if (err != nil) != nameFault {
				t.Fatal("GUI name read failure visibility", err)
			}
			if len(name.Raw) > 0 {
				if name.Buffer > uint64(len(m.data)) || uint64(len(name.Raw)) > uint64(len(m.data))-name.Buffer || !bytes.Equal(name.Raw, m.data[name.Buffer:name.Buffer+uint64(len(name.Raw))]) {
					t.Fatal("GUI raw name lost original bytes")
				}
			}
			info, err := r.StationInfo(ctx, c.Root)
			guiEqual(t, compare, "info", []any{info.Name, info.Session})
			if (err != nil) != (nameFault || c.Scenario == "station-session-hole") {
				t.Fatal("station info failure visibility", err)
			}
			for key, limit := range map[string]uint64{"desktops": 12, "desktops_one": 1, "desktops_zero": 0} {
				rows := []map[string]any{}
				err := r.Desktops(ctx, c.Root, limit, func(at uint64, name Name) error {
					rows = append(rows, map[string]any{"address": at, "name": name.Text})
					return nil
				})
				guiEqual(t, compare, key, rows)
				desktopFault := limit > 0 && (c.Scenario == "desktop-pointer-hole" || c.Scenario == "desktop-name-hole" || c.Scenario == "desktop-null" || c.HeaderKind == "infomask" && c.Scenario == "table-hole")
				if (err != nil) != desktopFault {
					t.Fatal(key, "desktop failure visibility", err)
				}
			}
			for _, read := range m.reads {
				if read.Err == nil && (read.At > uint64(len(m.data)) || uint64(len(read.Data)) > uint64(len(m.data))-read.At || !bytes.Equal(read.Data, m.data[read.At:read.At+uint64(len(read.Data))])) {
					t.Fatal("GUI name read does not match source")
				}
			}
		})
	}
}
func TestGUINamePythonUTF16Codec(t *testing.T) {
	for _, c := range guiNameOracle(t).Codec {
		raw, err := hex.DecodeString(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeName(raw); got != c.Text {
			t.Fatalf("UTF16 %x got %q want %q", raw, got, c.Text)
		}
	}
}

type guiShortNameLayer struct {
	memory.MemoryLayer
	mode string
}

func (l guiShortNameLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at != 0x11000 {
		return l.MemoryLayer.ReadAt(ctx, p, at)
	}
	if l.mode == "invalid-count" {
		return len(p) + 1, nil
	}
	n, err := l.MemoryLayer.ReadAt(ctx, p[:min(3, len(p))], at)
	if err != nil {
		return n, err
	}
	if l.mode == "short" {
		return n, nil
	}
	return n, io.ErrUnexpectedEOF
}
func TestGUINamesPartialReadsCancellationAndEmitter(t *testing.T) {
	c := guiNameOracle(t).Cases[0]
	l, err := ParseLayout(guiSource(t, c.Layout))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"short", "error", "invalid-count"} {
		r, m := guiNameSetup(t, c, l)
		r.Layer = guiShortNameLayer{MemoryLayer: m, mode: mode}
		name, err := r.ObjectName(context.Background(), c.Root)
		if err == nil || name.Text != nil {
			t.Fatal("GUI short read fabricated name", name, err)
		}
		if mode != "invalid-count" && (!bytes.Equal(name.Raw, m.data[0x11000:0x11003]) || !errors.Is(err, io.ErrUnexpectedEOF)) {
			t.Fatal("GUI partial raw bytes or cause lost", name, err)
		}
	}
	ctx := context.Background()
	for _, mid := range []bool{false, true} {
		r, m := guiNameSetup(t, c, l)
		cancelled, cancel := context.WithCancel(ctx)
		if !mid {
			cancel()
		}
		count := 0
		err := r.Desktops(cancelled, c.Root, 12, func(uint64, Name) error { count++; cancel(); return nil })
		cancel()
		expected := 0
		if mid {
			expected = 1
		}
		if !errors.Is(err, context.Canceled) || count != expected {
			t.Fatal("GUI desktop cancellation", count, err)
		}
		if !mid && len(m.reads) != 0 {
			t.Fatal("GUI read after cancellation")
		}
		if !mid {
			name, err := r.ObjectName(cancelled, c.Root)
			if !errors.Is(err, context.Canceled) || name.Text != nil || len(m.reads) != 0 {
				t.Fatal("cancelled name read", err)
			}
		}
	}
	r, _ := guiNameSetup(t, c, l)
	count := 0
	stop := errors.New("GUI name output failed")
	err = r.Desktops(ctx, c.Root, 12, func(uint64, Name) error { count++; return stop })
	if !errors.Is(err, stop) || count != 1 {
		t.Fatal("GUI desktop emitter failure", count, err)
	}
	if err = r.Desktops(ctx, c.Root, 1000001, func(uint64, Name) error { return nil }); err == nil {
		t.Fatal("GUI desktop bound accepted")
	}
	if err = r.Desktops(ctx, c.Root, 1, nil); err == nil {
		t.Fatal("nil desktop emitter accepted")
	}
	if _, err = (Reader{}).ObjectName(ctx, c.Root); err == nil {
		t.Fatal("missing name reader accepted")
	}
	table, err := symbols.Parse(c.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	delete(table.Types, "_OBJECT_HEADER_NAME_INFO")
	r.KernelSymbols = table
	count = 0
	err = r.Desktops(ctx, c.Root, 12, func(uint64, Name) error { count++; return nil })
	var schema nameSchemaError
	if !errors.As(err, &schema) || count != 0 {
		t.Fatal("GUI name schema failure swallowed", count, err)
	}
}
func FuzzGUINames(f *testing.F) {
	c := guiNameOracle(f).Cases[0]
	layout, err := ParseLayout(guiSource(f, c.Layout))
	if err != nil {
		f.Fatal(err)
	}
	seed, memorySeed := guiNameSetup(f, c, layout)
	f.Add(uint64(0x4000), uint64(0x3fb8), uint64(0), []byte{})
	f.Add(uint64(0x4000), uint64(0x3fb8), uint64(1), []byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, at, patchAt, holeWidth uint64, patch []byte) {
		m := &guiMemory{data: append([]byte(nil), memorySeed.data...)}
		if len(patch) > 32 {
			patch = patch[:32]
		}
		if patchAt < uint64(len(m.data)) {
			copy(m.data[patchAt:], patch)
			if holeWidth > 0 {
				m.holes = [][2]uint64{{patchAt, 1 + holeWidth%8}}
			}
		}
		r := seed
		r.Layer = m
		name, _ := r.ObjectName(context.Background(), at)
		if len(name.Raw) > 65535 || name.Text != nil && !utf8.ValidString(*name.Text) {
			t.Fatal("GUI name bound/encoding")
		}
		_, _ = r.StationInfo(context.Background(), at)
		count := 0
		_ = r.Desktops(context.Background(), at, 4, func(uint64, Name) error { count++; return nil })
		if count > 4 || len(m.reads) > 128 {
			t.Fatal("GUI name traversal exceeded bounds", count, len(m.reads))
		}
	})
}
