package plugins

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/wingui"
)

type guiPoolCase struct {
	Layout, Tag, Scenario string
	TopDown               bool `json:"top_down"`
	Header                uint64
	BlockBytes            uint64 `json:"block_bytes"`
	Accepted              bool
	Objects               []uint64
	Holes                 [][2]uint64
	Writes                []struct {
		Offset int
		Data   string
	}
}
type guiPoolFixture struct {
	Commit      string
	Kernel      json.RawMessage
	Size        int
	Constraints []struct {
		Tag        string
		TypeName   string `json:"type_name"`
		ObjectType string `json:"object_type"`
		PageType   int    `json:"page_type"`
		Size       []*uint64
		SkipType   bool `json:"skip_type"`
	}
	Cases []guiPoolCase
}

func guiPoolOracle(t testing.TB) guiPoolFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-gui-pool-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture guiPoolFixture
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 480 || len(fixture.Constraints) != 2 {
		t.Fatal("GUI pool oracle drift")
	}
	return fixture
}
func guiPoolLayouts(t testing.TB) map[string]*wingui.Layout {
	t.Helper()
	raw, err := os.ReadFile("../../pkg/wingui/testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Catalog map[string]struct {
			SHA256 string
			Source string `json:"source_gzip_base64"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	result := map[string]*wingui.Layout{}
	for name, c := range fixture.Catalog {
		data, err := base64.StdEncoding.DecodeString(c.Source)
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		data, err = io.ReadAll(io.LimitReader(z, 4<<20+1))
		_ = z.Close()
		if err != nil || len(data) > 4<<20 {
			t.Fatal("invalid GUI catalog fixture", err)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != c.SHA256 {
			t.Fatal("GUI catalog digest mismatch")
		}
		result[name], err = wingui.ParseLayout(data)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(result) != 12 {
		t.Fatal("GUI catalog count differs")
	}
	return result
}

type guiPoolMemory struct {
	flatMemory
	holes    [][2]uint64
	reads    int
	failures int
}

func (l *guiPoolMemory) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.reads++
	for _, h := range l.holes {
		if at < h[0]+h[1] && h[0] < at+uint64(len(p)) {
			l.failures++
			return 0, io.ErrUnexpectedEOF
		}
	}
	n, err := l.flatMemory.ReadAt(ctx, p, at)
	if n > 0 && !bytes.Equal(p[:n], l.flatMemory[at:at+uint64(n)]) {
		panic("GUI pool source capture differs")
	}
	return n, err
}
func guiPoolSetup(t testing.TB, f guiPoolFixture, c guiPoolCase) (plugin.Environment, *guiPoolMemory) {
	t.Helper()
	table, err := symbols.Parse(f.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	version := `{"pe":{"major":6,"minor":1,"revision":7601}}`
	if c.TopDown {
		version = `{"pe":{"major":10,"minor":0,"revision":19041}}`
	}
	table.Meta["windows"] = json.RawMessage(version)
	data := make(flatMemory, f.Size)
	for _, w := range c.Writes {
		p, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(data)-len(p) {
			t.Fatal("invalid GUI writes", err)
		}
		copy(data[w.Offset:], p)
	}
	layer := &guiPoolMemory{flatMemory: data, holes: c.Holes}
	return plugin.Environment{OS: "windows", Architecture: "x64", Symbols: table, Kernel: layer, Physical: layer, Objects: &object.Reader{Layer: layer, Symbols: table}}, layer
}
func TestGUIPoolOriginalHeadersAndCarving(t *testing.T) {
	f := guiPoolOracle(t)
	layouts := guiPoolLayouts(t)
	for _, c := range f.Cases {
		t.Run(fmt.Sprintf("%s/%t/%s/%s", c.Layout, c.TopDown, c.Tag, c.Scenario), func(t *testing.T) {
			constraints, err := guiPoolConstraints(layouts[c.Layout])
			if err != nil {
				t.Fatal(err)
			}
			var constraint poolConstraint
			for i, w := range f.Constraints {
				got := constraints[i]
				if w.Size == nil {
					w.Size = []*uint64{nil, nil}
				}
				if hex.EncodeToString(got.tag) != w.Tag || got.typeName != w.TypeName || got.objectType != w.ObjectType || got.pageType != w.PageType || got.skipType != w.SkipType || len(w.Size) != 2 || got.hasMin != (w.Size[0] != nil) || got.hasMax != (w.Size[1] != nil) || got.hasMin && got.minSize != *w.Size[0] {
					t.Fatal("GUI constraint differs", got, w)
				}
				if w.Tag == c.Tag {
					constraint = got
				}
			}
			e, layer := guiPoolSetup(t, f, c)
			layout, err := poolScanLayout(e, []poolConstraint{constraint})
			if err != nil || layout.topDown != c.TopDown {
				t.Fatal("GUI pool layout", err)
			}
			block, err := e.Objects.Uint(context.Background(), c.Header, "_POOL_HEADER", "BlockSize")
			if err != nil || block*layout.alignment != c.BlockBytes {
				t.Fatal("GUI block bytes", err)
			}
			p, err := e.Objects.Uint(context.Background(), c.Header, "_POOL_HEADER", "PoolType")
			if err != nil {
				t.Fatal(err)
			}
			accepted := poolPageOK(p, constraint.pageType, layout.vista) && (!constraint.hasMin || c.BlockBytes >= constraint.minSize)
			if accepted != c.Accepted {
				t.Fatal("GUI pool-header filter differs")
			}
			got := []uint64{}
			if accepted {
				carved, err := carvePoolObjects(context.Background(), layout, constraint, c.Header, c.BlockBytes, e.Objects, e.Kernel)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, carved...)
			}
			if !reflect.DeepEqual(got, c.Objects) {
				t.Fatal("GUI carved addresses differ", got, c.Objects)
			}
			// Exercise the shared scanner as well; GUI body types are intentionally
			// absent from the kernel table, so using the wrong table fails bottom-up.
			hits := []uint64{}
			err = scanPoolObjects(context.Background(), e, []poolConstraint{constraint}, "gui", poolScannerRow, func(evidence.Row) error { return nil }, func(_ context.Context, hit poolHit) (evidence.Row, bool, error) {
				hits = append(hits, hit.object)
				return evidence.Row{}, false, nil
			})
			if (err != nil) != (len(c.Holes) > 0) || err != nil && !errors.Is(err, io.ErrUnexpectedEOF) || !reflect.DeepEqual(hits, c.Objects) {
				t.Fatal("GUI scanner differs", hits, c.Objects, err)
			}
			if accepted && c.Scenario == "sid-hole" && layer.failures == 0 {
				t.Fatal("GUI invalid-address validity control did not read hole")
			}
		})
	}
}
func TestGUIPoolBoundsAndTerminalErrors(t *testing.T) {
	f := guiPoolOracle(t)
	layouts := guiPoolLayouts(t)
	c := f.Cases[0]
	if _, err := guiPoolConstraints(nil); err == nil {
		t.Fatal("nil GUI layout accepted")
	}
	if _, err := guiPoolConstraints(layouts[c.Layout], "File"); err == nil {
		t.Fatal("kernel tag accepted as GUI")
	}
	cs, err := guiPoolConstraints(layouts[c.Layout], "Wind")
	if err != nil || len(cs) != 1 {
		t.Fatal(err)
	}
	e, _ := guiPoolSetup(t, f, c)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := poolObjectValid(cancelled, cs[0], 0, e.Objects, e.Kernel); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled GUI validity", err)
	}
	sentinel := errors.New("GUI emitter stopped")
	err = scanPoolObjects(context.Background(), e, cs, "gui", poolScannerRow, func(evidence.Row) error { return sentinel }, func(context.Context, poolHit) (evidence.Row, bool, error) { return evidence.Row{}, true, nil })
	if !errors.Is(err, sentinel) {
		t.Fatal("GUI output failure lost", err)
	}
	e.Symbols.(*symbols.ISF).Bases["pointer"] = symbols.Type{Kind: "int", Size: 4, Endian: "little"}
	if _, err := poolScanLayout(e, cs); err == nil {
		t.Fatal("GUI/kernel pointer width mismatch accepted")
	}
}

func FuzzGUIPoolCarving(f *testing.F) {
	fixture := guiPoolOracle(f)
	layouts := guiPoolLayouts(f)
	f.Add([]byte{0, 1, 2, 3}, uint16(0), uint8(0))
	f.Add([]byte{255, 255, 255, 255}, uint16(0xffff), uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, index uint16, region uint8) {
		if len(payload) > 128 {
			return
		}
		c := fixture.Cases[int(index)%len(fixture.Cases)]
		e, layer := guiPoolSetup(t, fixture, c)
		at := []uint64{c.Header, c.Header + 16, c.Header + 64, 0x9000, 0xa000}[int(region)%5]
		copy(layer.flatMemory[at:], payload)
		tag, err := hex.DecodeString(c.Tag)
		if err != nil {
			t.Fatal(err)
		}
		constraints, err := guiPoolConstraints(layouts[c.Layout], string(tag))
		if err != nil {
			t.Fatal(err)
		}
		layout, err := poolScanLayout(e, constraints)
		if err != nil {
			t.Fatal(err)
		}
		block, err := e.Objects.Uint(context.Background(), c.Header, "_POOL_HEADER", "BlockSize")
		if err != nil {
			return
		}
		objects, err := carvePoolObjects(context.Background(), layout, constraints[0], c.Header, block*layout.alignment, e.Objects, e.Kernel)
		if err != nil {
			t.Fatal(err)
		}
		if len(objects) > 2 || layer.reads > 128 {
			t.Fatal("GUI pool carving exceeded bounded work", len(objects), layer.reads)
		}
		for _, at := range objects {
			if at > uint64(len(layer.flatMemory)) {
				t.Fatal("GUI object outside source", at)
			}
		}
	})
}
