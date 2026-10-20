package linuxcache

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type bytesLayer []byte

func (b bytesLayer) Name() string           { return "synthetic" }
func (b bytesLayer) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(b))}} }
func (b bytesLayer) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a >= uint64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[a:])
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func fixture(width int, xa bool, heightField string) (*object.Reader, bytesLayer, func(uint64, uint64)) {
	data := make(bytesLayer, 8192)
	ptr := symbols.TypeRef{Kind: "pointer"}
	base := symbols.TypeRef{Kind: "base", Name: "word"}
	field := func(off uint64, ref symbols.TypeRef) symbols.Field { return symbols.Field{Offset: off, Type: ref} }
	root, node, head := "radix_tree_root", "radix_tree_node", "rnode"
	if xa {
		root, node, head = "xarray", "xa_node", "xa_head"
		heightField = "shift"
	}
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: uint64(width), Endian: "little"}, "word": {Kind: "int", Size: uint64(width), Endian: "little"}}, Types: map[string]symbols.Type{
		"address_space": {Kind: "struct", Size: 32, Fields: map[string]symbols.Field{"i_pages": field(0, symbols.TypeRef{Kind: "struct", Name: root})}},
		root:            {Kind: "struct", Size: 32, Fields: map[string]symbols.Field{head: field(8, ptr)}},
		node:            {Kind: "struct", Size: 64, Fields: map[string]symbols.Field{heightField: field(0, base), "slots": field(16, symbols.TypeRef{Kind: "array", Count: 4, Subtype: &ptr})}},
	}}
	put := func(a, v uint64) {
		if width == 4 {
			binary.LittleEndian.PutUint32(data[a:], uint32(v))
		} else {
			binary.LittleEndian.PutUint64(data[a:], v)
		}
	}
	return &object.Reader{Layer: data, Symbols: table}, data, put
}
func TestTreesAndTaggedValues(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, layout := range []string{"height", "path", "shift", "xarray"} {
			t.Run(layout+string(rune('0'+width)), func(t *testing.T) {
				xa := layout == "xarray"
				r, _, put := fixture(width, xa, layout)
				tag := uint64(1)
				if xa {
					tag = 2
				}
				put(0x108, 0x1200|tag)
				h := uint64(2)
				if layout == "path" {
					if width == 8 {
						h |= 1 << 40
					} else {
						h |= 1 << 20
					}
				}
				if layout == "shift" || xa {
					h = 2
				}
				put(0x1200, h)
				put(0x1210, 0x1300|tag)
				h = 1
				if layout == "shift" || xa {
					h = 0
				}
				put(0x1300, h)
				put(0x1310, 0x1000)
				put(0x1310+uint64(width)*3, 0x1800)
				if xa {
					put(0x1210+uint64(width), 0x12000)
				} else {
					put(0x1210+uint64(width), 0x402)
				}
				var got []Entry
				stats, err := Walk(context.Background(), r, 0x100, Limits{8, 8}, func(e Entry) error { got = append(got, e); return nil })
				if err != nil || stats.Nodes != 2 || len(got) != 3 || got[0].Index != 0 || got[1].Index != 3 || got[2].Index != 4 || got[2].Span != 4 {
					t.Fatal(stats, got, err)
				}
				if xa && got[2].Kind != "page" || !xa && got[2].Kind != "exceptional" {
					t.Fatal(got)
				}
			})
		}
	}
}
func TestTreeFailuresAndPrefix(t *testing.T) {
	for _, scenario := range []string{"cycle", "height", "bound", "entries", "read", "callback", "cancel", "overflow", "badtag", "badslots", "rootheight"} {
		t.Run(scenario, func(t *testing.T) {
			r, data, put := fixture(8, false, "height")
			put(0x108, 0x1201)
			put(0x1200, 1)
			put(0x1210, 0x1000)
			put(0x1218, 0x1800)
			limits := Limits{8, 8}
			want := ""
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("consumer failed")
			switch scenario {
			case "cycle":
				put(0x1200, 2)
				put(0x1210, 0x1201)
				want = "repeated"
			case "height":
				put(0x1200, 0)
				want = "height"
			case "bound":
				put(0x1200, 2)
				put(0x1210, 0x1301)
				put(0x1300, 1)
				limits.Nodes = 1
				want = "limit"
			case "entries":
				limits.Entries = 1
				want = "limit"
			case "read":
				r.Layer = data[:0x1218]
				want = "slot"
			case "callback":
				want = "consumer"
			case "cancel":
				want = "canceled"
			case "overflow":
				put(0x1200, 32)
				put(0x1228, 0x1000)
				want = "overflow" // shift=62, slot3 fits; need child bad height below
			case "badtag":
				put(0x1210, 0x1003)
				want = "tag"
			case "badslots":
				table := r.Symbols.(*symbols.ISF)
				node := table.Types["radix_tree_node"]
				f := node.Fields["slots"]
				f.Type.Count = 3
				node.Fields["slots"] = f
				want = "slots"
			case "rootheight":
				table := r.Symbols.(*symbols.ISF)
				root := table.Types["radix_tree_root"]
				root.Fields["height"] = symbols.Field{Type: symbols.TypeRef{Kind: "base", Name: "word"}}
				put(0x100, 2)
				want = "mismatch"
			}
			if scenario == "overflow" { // 64 bits/2 permits height32; tagged child cannot match expected height31.
				put(0x1210, 0)
				put(0x1218, 0)
				put(0x1228, 0x1301)
				put(0x1300, 32)
				want = "height"
			}
			n := 0
			_, err := Walk(ctx, r, 0x100, limits, func(Entry) error {
				n++
				if scenario == "callback" {
					return sentinel
				}
				if scenario == "cancel" {
					cancel()
				}
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal(n, err, want)
			}
			if scenario == "read" && n != 1 {
				t.Fatal("lost valid prefix", n)
			}
			if scenario == "callback" && !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
		})
	}
}
func TestXArraySpecialEntriesAndDirectPage(t *testing.T) {
	r, _, put := fixture(8, true, "")
	put(0x108, 0x1202)
	put(0x1200, 0)
	for i, v := range []uint64{0x1000, 2, 257, 1030} {
		put(0x1210+uint64(i)*8, v)
	}
	var kinds []string
	_, err := Walk(context.Background(), r, 0x100, Limits{8, 8}, func(e Entry) error { kinds = append(kinds, e.Kind); return nil })
	if err != nil || strings.Join(kinds, ",") != "page,sibling,value,internal_value" {
		t.Fatal(kinds, err)
	}
	put(0x108, 0x1000)
	_, err = Walk(context.Background(), r, 0x100, Limits{1, 1}, func(e Entry) error {
		if e.Index != 0 || e.Span != 1 || e.Slot != 0x108 {
			t.Fatal(e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	put(0x108, 0)
	stats, err := Walk(context.Background(), r, 0x100, Limits{1, 1}, func(Entry) error { t.Fatal("empty tree"); return nil })
	if err != nil || stats.Entries != 0 {
		t.Fatal(stats, err)
	}
}
func FuzzPageCacheTree(f *testing.F) {
	f.Add([]byte{1, 2, 3}, true, uint8(8))
	f.Add([]byte{0, 1, 0, 0, 0, 0, 0, 0, 1, 2}, false, uint8(4))
	f.Fuzz(func(t *testing.T, b []byte, xa bool, widthByte uint8) {
		width := 4
		if widthByte&1 == 0 {
			width = 8
		}
		r, data, put := fixture(width, xa, "height")
		copy(data[0x1200:], b)
		tag := uint64(1)
		if xa {
			tag = 2
		}
		put(0x108, 0x1200|tag)
		height := uint64(1)
		if len(b) > 0 {
			height = uint64(b[0])
		}
		if xa {
			height = (height % 33) * 2
		}
		put(0x1200, height)
		calls := 0
		_, _ = Walk(context.Background(), r, 0x100, Limits{16, 32}, func(Entry) error {
			calls++
			if calls > 32 {
				t.Fatal("unbounded output")
			}
			return nil
		})
	})
}

func TestTreeIndexOverflow(t *testing.T) {
	r, _, put := fixture(8, false, "height")
	table := r.Symbols.(*symbols.ISF)
	node := table.Types["radix_tree_node"]
	node.Size = 528
	slots := node.Fields["slots"]
	slots.Type.Count = 64
	node.Fields["slots"] = slots
	table.Types["radix_tree_node"] = node
	put(0x108, 0x1201)
	put(0x1200, 11)
	put(0x1210+16*8, 0x1800)
	_, err := Walk(context.Background(), r, 0x100, Limits{16, 16}, func(Entry) error { t.Fatal("overflow emitted an entry"); return nil })
	if err == nil || !strings.Contains(err.Error(), "index overflow") {
		t.Fatal(err)
	}
}
