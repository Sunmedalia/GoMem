package object_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type latchCase struct {
	Width      int
	Nested     bool
	Sequence   uint64
	NodeOffset uint64 `json:"node_offset"`
	Shape      string
	ISF        json.RawMessage
	Writes     [][]json.RawMessage
	Expected   []struct {
		Key       uint64
		Inclusive bool
		Node      *uint64
		Visited   []uint64
	}
}

func latchCases(t testing.TB) []latchCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/latch-tree-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []latchCase
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 96 {
		t.Fatal("latch oracle provenance/count")
	}
	return v.Cases
}
func latchReader(t testing.TB, c latchCase) (*object.Reader, listBytes) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := make(listBytes, 0x5000)
	for _, w := range c.Writes {
		var at int
		var value string
		if err := json.Unmarshal(w[0], &at); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(w[1], &value); err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], raw)
	}
	return &object.Reader{Layer: data, Symbols: table}, data
}
func latchCompare(r *object.Reader, inclusive bool, visit func(uint64)) func(context.Context, uint64, uint64) (int, error) {
	return func(ctx context.Context, key, node uint64) (int, error) {
		if visit != nil {
			visit(node)
		}
		start, err := r.Uint(ctx, node, "latch_tree_node", "start")
		if err != nil {
			return 0, err
		}
		end, err := r.Uint(ctx, node, "latch_tree_node", "end")
		if err != nil {
			return 0, err
		}
		if key < start {
			return -1, nil
		}
		if key > end || key == end && !inclusive {
			return 1, nil
		}
		return 0, nil
	}
}

type latchRead struct {
	at  uint64
	raw []byte
}
type latchObserved struct {
	listBytes
	reads []latchRead
}

func (l *latchObserved) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	n, err := l.listBytes.ReadAt(ctx, p, at)
	l.reads = append(l.reads, latchRead{at, append([]byte(nil), p[:n]...)})
	return n, err
}
func TestPinnedLatchTree(t *testing.T) {
	for _, c := range latchCases(t) {
		t.Run(fmt.Sprintf("%d/%t/%d/%d/%s", c.Width, c.Nested, c.Sequence, c.NodeOffset, c.Shape), func(t *testing.T) {
			r, data := latchReader(t, c)
			trace := &latchObserved{listBytes: data}
			r.Layer = trace
			for i, want := range c.Expected {
				visited := []uint64{}
				trace.reads = nil
				got, err := r.FindLatchTree(context.Background(), 0x1000, want.Key, 64, latchCompare(r, want.Inclusive, func(node uint64) { visited = append(visited, node) }))
				if err != nil {
					t.Fatal(i, err)
				}
				if !reflect.DeepEqual(visited, want.Visited) || got.Visited != uint64(len(want.Visited)) || got.Sequence != c.Sequence || got.Index != c.Sequence&1 {
					t.Fatal(i, got, visited, want.Visited)
				}
				if got.Found != (want.Node != nil) || want.Node != nil && got.Node != *want.Node {
					t.Fatal(i, got, want.Node)
				}
				if got.Found && got.RBNode != got.Node+c.NodeOffset+got.Index*uint64(c.Width) {
					t.Fatal("pinned coordinate quirk lost", got)
				}
				selectedSlot := uint64(0x1020) + got.Index*uint64(c.Width)
				otherSlot := uint64(0x1020) + (got.Index^1)*uint64(c.Width)
				selectedRead := false
				for _, read := range trace.reads {
					actual, err := memory.Read(context.Background(), data, read.at, len(read.raw))
					if err != nil || !bytes.Equal(actual, read.raw) {
						t.Fatal("independent acquisition reread", err)
					}
					if read.at == selectedSlot {
						selectedRead = true
					}
					if read.at == otherSlot {
						t.Fatal("unselected tree read")
					}
				}
				if !selectedRead {
					t.Fatal("selected root not acquired")
				}
			}
		})
	}
}
func latchFaultCase(t testing.TB) latchCase {
	t.Helper()
	for _, c := range latchCases(t) {
		if c.Width == 8 && c.Nested && c.Sequence == 1 && c.NodeOffset == 16 && c.Shape == "normal" {
			return c
		}
	}
	t.Fatal("fixture missing")
	return latchCase{}
}
func TestLatchTreeFailures(t *testing.T) {
	c := latchFaultCase(t)
	for _, fault := range []string{"cycle", "bound", "unaligned", "underflow", "node-hole", "seq-hole", "tree-layout", "node-layout", "pointer-layout", "pointer-width", "sequence-layout", "overflow", "callback", "cancel-callback", "cancel-before", "nil-callback", "zero-bound", "huge-bound"} {
		t.Run(fault, func(t *testing.T) {
			r, data := latchReader(t, c)
			table := r.Symbols.(*symbols.ISF)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			max := 64
			root := uint64(0x1000)
			compare := latchCompare(r, false, nil)
			stop := errors.New("comparison stopped")
			mutate := func(typ, name string, ref symbols.TypeRef) {
				v := table.Types[typ]
				f := v.Fields[name]
				f.Type = ref
				v.Fields[name] = f
				table.Types[typ] = v
			}
			switch fault {
			case "cycle":
				binary.LittleEndian.PutUint64(data[0x3030:], 0x3028)
			case "bound":
				max = 1
			case "unaligned":
				binary.LittleEndian.PutUint64(data[0x1028:], 0x3029)
			case "underflow":
				binary.LittleEndian.PutUint64(data[0x1028:], 8)
			case "node-hole":
				r.Layer = data[:0x3028+23]
			case "seq-hole":
				r.Layer = data[:0x100f]
			case "tree-layout":
				mutate("latch_tree_root", "tree", symbols.TypeRef{Kind: "pointer"})
			case "node-layout":
				mutate("latch_tree_node", "node", symbols.TypeRef{Kind: "pointer"})
			case "pointer-layout":
				mutate("rb_node", "rb_left", symbols.TypeRef{Kind: "base", Name: "word"})
			case "pointer-width":
				table.Bases["narrow"] = symbols.Type{Kind: "int", Size: 4, Endian: "little"}
				mutate("rb_node", "rb_left", symbols.TypeRef{Kind: "pointer", Base: "narrow"})
			case "sequence-layout":
				mutate("seqcount_latch", "seqcount", symbols.TypeRef{Kind: "base", Name: "word"})
			case "overflow":
				root = ^uint64(0) - 2
			case "callback":
				compare = func(context.Context, uint64, uint64) (int, error) { return 0, stop }
			case "cancel-callback":
				compare = func(context.Context, uint64, uint64) (int, error) { cancel(); return 0, nil }
			case "cancel-before":
				cancel()
			case "nil-callback":
				compare = nil
			case "zero-bound":
				max = 0
			case "huge-bound":
				max = 1000001
			}
			key := uint64(0x1100)
			if fault == "cycle" {
				key = 0xffff
			}
			got, err := r.FindLatchTree(ctx, root, key, max, compare)
			if err == nil || got.Found {
				t.Fatal("failure became absence/match", got, err)
			}
			if fault == "callback" && !errors.Is(err, stop) {
				t.Fatal(err)
			}
			if (fault == "cancel-before" || fault == "cancel-callback") && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
	var r *object.Reader
	if _, err := r.FindLatchTree(context.Background(), 0, 0, 1, func(context.Context, uint64, uint64) (int, error) { return 0, nil }); err == nil {
		t.Fatal("nil reader")
	}
}
func FuzzLatchTree(f *testing.F) {
	c := latchFaultCase(f)
	_, original := latchReader(f, c)
	f.Add([]byte{0xff}, uint8(0), uint64(0x1120))
	f.Add([]byte{0x28, 0x30, 0, 0, 0, 0, 0, 0}, uint8(1), uint64(0xffff))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8, key uint64) {
		if len(payload) > 128 {
			return
		}
		r, _ := latchReader(t, c)
		data := append(listBytes(nil), original...)
		at := []int{0x1000, 0x1020, 0x3028, 0x3228, 0x3428, 0x3090}[int(region)%6]
		copy(data[at:], payload)
		r.Layer = data
		calls := 0
		compare := latchCompare(r, false, func(uint64) {
			calls++
			if calls > 16 {
				t.Fatal("unbounded comparisons")
			}
		})
		got, err := r.FindLatchTree(context.Background(), 0x1000, key, 16, compare)
		if err != nil && got.Found {
			t.Fatal("failed match")
		}
		if got.Visited > 16 {
			t.Fatal("unbounded search")
		}
	})
}

func TestLatchTreeEveryComparisonBoundary(t *testing.T) {
	c := latchFaultCase(t)
	for boundary := 1; boundary <= 2; boundary++ {
		for _, cancelInside := range []bool{false, true} {
			r, _ := latchReader(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			stop := errors.New("stop at comparison")
			calls := 0
			base := latchCompare(r, false, nil)
			got, err := r.FindLatchTree(ctx, 0x1000, 0x1100, 64, func(ctx context.Context, key, node uint64) (int, error) {
				calls++
				if calls == boundary {
					if cancelInside {
						cancel()
						return 0, nil
					}
					return 0, stop
				}
				return base(ctx, key, node)
			})
			cancel()
			expected := stop
			if cancelInside {
				expected = context.Canceled
			}
			if !errors.Is(err, expected) || calls != boundary || got.Found || got.Visited != uint64(boundary) {
				t.Fatal(boundary, cancelInside, got, calls, err)
			}
		}
	}
}

func TestLatchTreeZeroContainer(t *testing.T) {
	c := latchFaultCase(t)
	c.Sequence = 0
	r, data := latchReader(t, c)
	binary.LittleEndian.PutUint32(data[0x100c:], 0)
	binary.LittleEndian.PutUint64(data[0x1020:], 16)
	binary.LittleEndian.PutUint64(data[128:], 0x100)
	binary.LittleEndian.PutUint64(data[136:], 0x110)
	got, err := r.FindLatchTree(context.Background(), 0x1000, 0x100, 4, latchCompare(r, false, nil))
	if err != nil || !got.Found || got.Node != 0 || got.RBNode != 16 {
		t.Fatal(got, err)
	}
}
func TestLatchTreeBigEndian(t *testing.T) {
	c := latchFaultCase(t)
	r, data := latchReader(t, c)
	swap := func(at uint64, size int) {
		p := data[at : at+uint64(size)]
		for a, b := 0, len(p)-1; a < b; a, b = a+1, b-1 {
			p[a], p[b] = p[b], p[a]
		}
	}
	swap(0x100c, 4)
	for index := uint64(0); index < 2; index++ {
		swap(0x1020+index*8, 8)
		for i := uint64(0); i < 3; i++ {
			container := uint64(0x2000) + index*0x1000 + i*0x200
			rb := container + 16 + index*24
			for word := uint64(0); word < 3; word++ {
				swap(rb+word*8, 8)
			}
			node := rb - 16 - index*8
			swap(node+128, 8)
			swap(node+136, 8)
		}
	}
	table := r.Symbols.(*symbols.ISF)
	for name, base := range table.Bases {
		base.Endian = "big"
		table.Bases[name] = base
	}
	for _, want := range c.Expected {
		got, err := r.FindLatchTree(context.Background(), 0x1000, want.Key, 64, latchCompare(r, want.Inclusive, nil))
		if err != nil || got.Found != (want.Node != nil) || want.Node != nil && got.Node != *want.Node {
			t.Fatal(got, want.Node, err)
		}
	}
}
