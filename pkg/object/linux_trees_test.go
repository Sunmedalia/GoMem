package object_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type listBytes []byte

func (b listBytes) Name() string           { return "test-lists" }
func (b listBytes) Ranges() []memory.Range { return nil }
func (b listBytes) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a >= uint64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[a:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func linuxTreeReader(width int) (*object.Reader, listBytes, func(uint64, uint64)) {
	b := make(listBytes, 4096)
	ptr := symbols.TypeRef{Kind: "pointer"}
	f := func(o uint64) symbols.Field { return symbols.Field{Offset: o, Type: ptr} }
	s := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: uint64(width), Endian: "little"}}, Types: map[string]symbols.Type{
		"hlist_head": {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"first": f(0)}}, "hlist_node": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"next": f(0), "pprev": f(8)}},
		"rb_root": {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"rb_node": f(0)}}, "rb_node": {Kind: "struct", Size: 24, Fields: map[string]symbols.Field{"__rb_parent_color": f(0), "rb_left": f(8), "rb_right": f(16)}},
	}}
	put := func(a, v uint64) {
		if width == 4 {
			binary.LittleEndian.PutUint32(b[a:], uint32(v))
		} else {
			binary.LittleEndian.PutUint64(b[a:], v)
		}
	}
	return &object.Reader{Layer: b, Symbols: s}, b, put
}
func TestLinuxIntrusiveListsAndTrees(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, kind := range []string{"hlist", "rb"} {
			for _, fault := range []string{"normal", "empty", "parent", "cycle", "bound", "read", "consumer", "cancel"} {
				t.Run(kind+string(rune('0'+width))+fault, func(t *testing.T) {
					r, b, put := linuxTreeReader(width)
					if kind == "hlist" {
						put(0x10, 0x108)
						put(0x108, 0x208)
						put(0x110, 0x10)
						put(0x208, 0x308)
						put(0x210, 0x108)
						put(0x310, 0x208)
					} else {
						put(0x10, 0x208)
						put(0x208, 1)
						put(0x210, 0x108)
						put(0x218, 0x308)
						put(0x108, 0x209)
						put(0x308, 0x209)
					}
					limit := 100
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					sentinel := errors.New("output closed")
					switch fault {
					case "empty":
						put(0x10, 0)
					case "parent":
						if kind == "hlist" {
							put(0x210, 0)
						} else {
							put(0x108, 0)
						}
					case "cycle":
						if kind == "hlist" {
							put(0x308, 0x108)
						} else {
							put(0x110, 0x208)
						}
					case "bound":
						limit = 1
					case "read":
						r.Layer = b[:0x20]
					}
					var got []uint64
					emit := func(a uint64) error {
						got = append(got, a)
						if fault == "consumer" {
							return sentinel
						}
						if fault == "cancel" {
							cancel()
						}
						return nil
					}
					var err error
					if kind == "hlist" {
						err = r.WalkHList(ctx, 0x10, 8, limit, emit)
					} else {
						err = r.WalkRBTree(ctx, 0x10, 8, limit, emit)
					}
					switch fault {
					case "normal":
						if err != nil || !reflect.DeepEqual(got, []uint64{0x100, 0x200, 0x300}) {
							t.Fatal(got, err)
						}
					case "empty":
						if err != nil || len(got) != 0 {
							t.Fatal(got, err)
						}
					case "consumer":
						if !errors.Is(err, sentinel) {
							t.Fatal(err)
						}
					case "cancel":
						if !errors.Is(err, context.Canceled) {
							t.Fatal(err)
						}
					default:
						if err == nil {
							t.Fatal("silently accepted damaged traversal", got)
						}
					}
				})
			}
		}
	}
}
func FuzzLinuxIntrusiveTrees(f *testing.F) {
	f.Add([]byte{0x08, 0x01}, false)
	f.Add([]byte{0x08, 0x01, 0x00, 0x00}, true)
	hseed := make([]byte, 0x120)
	binary.LittleEndian.PutUint64(hseed[8:], 0x208)
	binary.LittleEndian.PutUint64(hseed[16:], 0x10)
	binary.LittleEndian.PutUint64(hseed[0x110:], 0x108)
	f.Add(hseed, true)
	rseed := make([]byte, 0x220)
	binary.LittleEndian.PutUint64(rseed[8:], 1)
	binary.LittleEndian.PutUint64(rseed[16:], 0x208)
	binary.LittleEndian.PutUint64(rseed[24:], 0x308)
	binary.LittleEndian.PutUint64(rseed[0x108:], 0x109)
	binary.LittleEndian.PutUint64(rseed[0x208:], 0x109)
	f.Add(rseed, false)
	f.Fuzz(func(t *testing.T, data []byte, hlist bool) {
		r, b, put := linuxTreeReader(8)
		copy(b[0x100:], data)
		put(0x10, 0x108)
		calls := 0
		emit := func(uint64) error {
			calls++
			if calls > 16 {
				t.Fatal("unbounded traversal")
			}
			return nil
		}
		if hlist {
			_ = r.WalkHList(context.Background(), 0x10, 8, 16, emit)
		} else {
			_ = r.WalkRBTree(context.Background(), 0x10, 8, 16, emit)
		}
	})
}
