package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type vmaFuzzLayer []byte

func (v vmaFuzzLayer) Name() string           { return "synthetic-vma-fuzz" }
func (v vmaFuzzLayer) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(v))}} }
func (v vmaFuzzLayer) ReadAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > memory.MaxRead {
		return 0, fmt.Errorf("oversized read")
	}
	if offset > uint64(len(v)) || uint64(len(p)) > uint64(len(v))-offset {
		return 0, io.EOF
	}
	return copy(p, v[offset:]), nil
}

func FuzzLinuxVMAMetadata(f *testing.F) {
	fixture, err := testfixture.Write(f.TempDir(), "linux")
	if err != nil {
		f.Fatal(err)
	}
	base, err := os.ReadFile(fixture.Image)
	if err != nil {
		f.Fatal(err)
	}
	list, err := symbols.Load(fixture.Symbols)
	if err != nil {
		f.Fatal(err)
	}
	maple, err := symbols.Load(fixture.Symbols)
	if err != nil {
		f.Fatal(err)
	}
	ptr := symbols.TypeRef{Kind: "pointer"}
	slots := symbols.TypeRef{Kind: "array", Count: 4, Subtype: &ptr}
	maple.Types["mm_struct"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"mm_mt": {Offset: 8, Type: symbols.TypeRef{Kind: "struct", Name: "maple_tree"}}}}
	maple.Types["maple_tree"] = symbols.Type{Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"ma_root": {Type: ptr}, "ma_flags": {Offset: 8, Type: symbols.TypeRef{Kind: "base", Name: "u32"}}}}
	maple.Types["maple_range"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"slot": {Offset: 32, Type: slots}}}
	maple.Types["maple_node"] = symbols.Type{Kind: "struct", Size: 64, Fields: map[string]symbols.Field{"parent": {Type: ptr}, "slot": {Offset: 8, Type: slots}, "mr64": {Type: symbols.TypeRef{Kind: "struct", Name: "maple_range"}}, "ma64": {Type: symbols.TypeRef{Kind: "struct", Name: "maple_range"}}}}
	for mode := byte(0); mode < 3; mode++ {
		f.Add([]byte{}, mode)
	}
	f.Fuzz(func(t *testing.T, state []byte, mode byte) {
		if len(state) > 65536 {
			return
		}
		data := append(vmaFuzzLayer(nil), base...)
		table := list
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		if mode%3 != 0 {
			table = maple
			put(0xe008, 0x1c00a)
			put(0xe010, 1<<2)
			put(0x1c000, 0xe009)
			for i, a := range []uint64{0x10000, 0x11000, 0x12000, 0x12100} {
				put(0x1c020+uint64(i)*8, a)
			}
			if mode%3 == 2 {
				put(0xe008, 0x1d012)
				put(0xe010, 2<<2)
				put(0x1d000, 0xe009)
				put(0x1d020, 0x1c00a)
				put(0x1c000, 0x1d006)
			}
		}
		copy(data[0xe000:], state)
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		env := plugin.Environment{Physical: data, Kernel: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}, OS: "linux", ImageHash: "synthetic-fuzz"}
		rows := 0
		_ = linuxMaps(ctx, env, map[string]string{"pid": "100", "max-nodes": "64", "max-regions": "64", "include-past-eof": "true"}, func(row evidence.Row) error {
			rows++
			if rows > 64 {
				t.Fatal("VMA output bound exceeded")
			}
			start, err := row.Cells["Start"].Uint()
			if err != nil {
				t.Fatal(err)
			}
			end, err := row.Cells["End"].Uint()
			if err != nil || start >= end || start&4095 != 0 || end&4095 != 0 {
				t.Fatal("invalid VMA interval emitted", start, end, err)
			}
			return nil
		})
	})
}
