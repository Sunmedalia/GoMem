package winshimcache

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type avlCase struct {
	Layout, Scenario string
	Width, At        uint64
	PageStart        uint64 `json:"page_start"`
	PageEnd          uint64 `json:"page_end"`
	Size             int
	Holes            [][2]uint64
	Valid            bool
	Reads            [][2]uint64
	Writes           []struct {
		Offset int
		Data   string
	}
}
type avlFixture struct {
	Commit  string
	Layouts map[string]struct {
		SHA256 string
		Source string `json:"source_base64"`
	}
	Cases []avlCase
}

func avlOracle(t testing.TB) avlFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/avl-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f avlFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Layouts) != 12 || len(f.Cases) != 264 {
		t.Fatal("Shimcache AVL oracle drift")
	}
	return f
}
func avlSource(t testing.TB, f avlFixture, name string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(f.Layouts[name].Source)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > 4<<20 {
		t.Fatal("source bound")
	}
	return raw
}

type avlMemory struct {
	data     []byte
	holes    [][2]uint64
	reads    [][2]uint64
	captures [][]byte
	faults   uint64
}

func (m *avlMemory) Name() string           { return "shimcache-avl-control" }
func (m *avlMemory) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(m.data))}} }
func (m *avlMemory) ReadAt(ctx context.Context, p []byte, at uint64) (n int, err error) {
	defer func() {
		m.reads = append(m.reads, [2]uint64{at, uint64(len(p))})
		m.captures = append(m.captures, append([]byte(nil), p[:n]...))
		if err != nil {
			m.faults++
		}
	}()
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
func avlSetup(t testing.TB, c avlCase, l *Layout) (Reader, *avlMemory) {
	t.Helper()
	m := &avlMemory{data: make([]byte, c.Size), holes: c.Holes}
	for _, w := range c.Writes {
		b, err := hex.DecodeString(w.Data)
		if err != nil || w.Offset < 0 || w.Offset > len(m.data)-len(b) {
			t.Fatal("invalid AVL writes", err)
		}
		copy(m.data[w.Offset:], b)
	}
	return Reader{Layer: m, Layout: l}, m
}
func TestShimcacheAVLOriginalAllLayouts(t *testing.T) {
	f := avlOracle(t)
	layouts := map[string]*Layout{}
	for name, source := range f.Layouts {
		l, err := ParseAVLLayout(avlSource(t, f, name))
		if err != nil || l.SHA256 != source.SHA256 {
			t.Fatal("layout mismatch", name, err)
		}
		layouts[name] = l
	}
	for _, c := range f.Cases {
		t.Run(c.Layout+"/"+c.Scenario, func(t *testing.T) {
			r, m := avlSetup(t, c, layouts[c.Layout])
			valid, err := r.AVLValid(context.Background(), c.At, c.PageStart, c.PageEnd)
			if valid != c.Valid {
				t.Fatal("validity differs", valid, c.Valid, err)
			}
			if !reflect.DeepEqual(m.reads, c.Reads) {
				t.Fatal("original/native read sequence differs", m.reads, c.Reads)
			}
			if (err != nil) != (m.faults > 0) {
				t.Fatal("read failure hidden or rejection fabricated", err, m.faults)
			}
			for i, read := range m.reads {
				raw := m.captures[i]
				if read[0] > uint64(len(m.data)) || uint64(len(raw)) > uint64(len(m.data))-read[0] || !bytes.Equal(raw, m.data[read[0]:read[0]+uint64(len(raw))]) {
					t.Fatal("source capture differs")
				}
			}
		})
	}
}
func TestShimcacheAVLCancelAndOverflow(t *testing.T) {
	f := avlOracle(t)
	c := f.Cases[0]
	l, err := ParseAVLLayout(avlSource(t, f, c.Layout))
	if err != nil {
		t.Fatal(err)
	}
	r, m := avlSetup(t, c, l)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if valid, err := r.AVLValid(ctx, c.At, c.PageStart, c.PageEnd); valid || !errors.Is(err, context.Canceled) || len(m.reads) != 0 {
		t.Fatal("cancel", valid, err, m.reads)
	}
	if valid, err := r.AVLValid(context.Background(), math.MaxUint64, c.PageStart, c.PageEnd); valid || err == nil {
		t.Fatal("overflow", valid, err)
	}
	if valid, err := (Reader{}).AVLValid(context.Background(), 0, 0, 0); valid || err == nil {
		t.Fatal("missing environment")
	}
}

func TestShimcacheAVLRejectsMalformedLayouts(t *testing.T) {
	f := avlOracle(t)
	raw := avlSource(t, f, "shimcache-win10-x64")
	for _, scenario := range []string{"missing-root", "root-target", "parent-target", "routine-scalar", "overrun", "oversized", "pointer-endian", "pointer-signed"} {
		t.Run(scenario, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			types := doc["user_types"].(map[string]any)
			table := types["_RTL_AVL_TABLE"].(map[string]any)
			fields := table["fields"].(map[string]any)
			switch scenario {
			case "missing-root":
				delete(fields, "BalancedRoot")
			case "root-target":
				fields["BalancedRoot"].(map[string]any)["type"] = map[string]any{"kind": "struct", "name": "_RTL_AVL_TABLE"}
			case "parent-target":
				types["_RTL_BALANCED_LINKS"].(map[string]any)["fields"].(map[string]any)["Parent"].(map[string]any)["type"] = map[string]any{"kind": "pointer", "subtype": map[string]any{"kind": "struct", "name": "_RTL_AVL_TABLE"}}
			case "routine-scalar":
				fields["AllocateRoutine"].(map[string]any)["type"] = map[string]any{"kind": "base", "name": "unsigned long long"}
			case "overrun":
				fields["FreeRoutine"].(map[string]any)["offset"] = 1 << 20
			case "oversized":
				table["size"] = 1 << 21
			case "pointer-endian":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["endian"] = "big"
			case "pointer-signed":
				doc["base_types"].(map[string]any)["pointer"].(map[string]any)["signed"] = true
			}
			bad, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseAVLLayout(bad); err == nil {
				t.Fatal("accepted malformed layout")
			}
		})
	}
}

func TestShimcacheAVLStorageAliasShortCircuitsFreeRead(t *testing.T) {
	f := avlOracle(t)
	c := f.Cases[0]
	l, err := ParseAVLLayout(avlSource(t, f, c.Layout))
	if err != nil {
		t.Fatal(err)
	}
	typ := l.Types.Types["_RTL_AVL_TABLE"]
	field := typ.Fields["CompareRoutine"]
	field.Offset = typ.Fields["AllocateRoutine"].Offset
	typ.Fields["CompareRoutine"] = field
	l.Types.Types["_RTL_AVL_TABLE"] = typ
	r, m := avlSetup(t, c, l)
	m.holes = append(m.holes, [2]uint64{c.At + typ.Fields["FreeRoutine"].Offset, c.Width})
	valid, err := r.AVLValid(context.Background(), c.At, c.PageStart, c.PageEnd)
	if valid || err != nil || len(m.reads) != 3 {
		t.Fatal("routine alias short circuit", valid, err, m.reads)
	}
}

func FuzzShimcacheAVL(f *testing.F) {
	fixture := avlOracle(f)
	var readers []Reader
	var seeds []*avlMemory
	for _, name := range []string{"shimcache-win10-x86", "shimcache-win10-x64"} {
		l, err := ParseAVLLayout(avlSource(f, fixture, name))
		if err != nil {
			f.Fatal(err)
		}
		for _, c := range fixture.Cases {
			if c.Layout == name && c.Scenario == "normal" {
				r, m := avlSetup(f, c, l)
				readers = append(readers, r)
				seeds = append(seeds, m)
				break
			}
		}
	}
	f.Add(uint64(0x1000), uint64(0x3000), uint64(0x4000), []byte{}, uint8(0))
	f.Add(uint64(math.MaxUint64), uint64(0), uint64(math.MaxUint64), bytes.Repeat([]byte{255}, 128), uint8(1))
	f.Fuzz(func(t *testing.T, at, start, end uint64, patch []byte, which uint8) {
		i := which % 2
		m := &avlMemory{data: append([]byte(nil), seeds[i].data...)}
		if len(patch) > 128 {
			patch = patch[:128]
		}
		copy(m.data[0x1000:], patch)
		r := readers[i]
		r.Layer = m
		_, _ = r.AVLValid(context.Background(), at, start, end)
		if len(m.reads) > 4 {
			t.Fatal("unbounded AVL scalar reads")
		}
	})
}

func FuzzShimcacheAVLLayout(f *testing.F) {
	fixture := avlOracle(f)
	f.Add(avlSource(f, fixture, "shimcache-win10-x64"))
	f.Add(avlSource(f, fixture, "shimcache-xp-sp2-x86"))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4<<20 {
			t.Skip()
		}
		if l, err := ParseAVLLayout(raw); err == nil {
			m := &avlMemory{data: make([]byte, 0x10000)}
			_, _ = (Reader{Layer: m, Layout: l}).AVLValid(context.Background(), 0x1000, 0x3000, 0x4000)
			if len(m.reads) > 4 {
				t.Fatal("unbounded projected AVL reads")
			}
		}
	})
}
