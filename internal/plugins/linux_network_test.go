package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestUnixAbstractDisplayRetainsEveryByte(t *testing.T) {
	for _, raw := range [][]byte{{0}, {0, 0, 1, 0xff, '\\', '@'}, {'/', 't', 0, 'x'}} {
		display, encoding := linuxUnixDisplay(raw)
		if raw[0] == 0 {
			if encoding != "abstract" || !strings.HasPrefix(display, "@") {
				t.Fatal(display, encoding)
			}
			var recovered []byte
			for i := 1; i < len(display); {
				if display[i] == '\\' {
					if i+4 > len(display) || display[i+1] != 'x' {
						t.Fatal(display)
					}
					v, err := strconv.ParseUint(display[i+2:i+4], 16, 8)
					if err != nil {
						t.Fatal(err)
					}
					recovered = append(recovered, byte(v))
					i += 4
				} else {
					recovered = append(recovered, display[i])
					i++
				}
			}
			if !bytes.Equal(recovered, raw[1:]) {
				t.Fatal(raw, display, recovered)
			}
		} else if display != "/t" || encoding != "pathname" {
			t.Fatal(display, encoding)
		}
	}
}

func FuzzLinuxUnixEndpoint(f *testing.F) {
	f.Add([]byte("/tmp/a\x00"), uint32(9), false)
	f.Add([]byte{0, 'x', 0, 0xff}, uint32(6), false)
	f.Add([]byte("bad"), uint32(999), true)
	f.Fuzz(func(t *testing.T, payload []byte, length uint32, badPointer bool) {
		if len(payload) > 128 {
			return
		}
		data := make(inodeTimeLayer, 42+len(payload))
		binary.LittleEndian.PutUint64(data[8:], 32)
		binary.LittleEndian.PutUint32(data[32:], length)
		copy(data[42:], payload)
		if badPointer {
			binary.LittleEndian.PutUint64(data[8:], ^uint64(0)-4)
		}
		base := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: n} }
		char := base("char")
		name := symbols.TypeRef{Kind: "struct", Name: "sockaddr_un"}
		table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Size: 8, Endian: "little"}, "u32": {Size: 4, Endian: "little"}, "char": {Size: 1, Endian: "little"}}, Types: map[string]symbols.Type{
			"sock":         {Kind: "struct", Size: 8},
			"unix_sock":    {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{"sk": {Type: symbols.TypeRef{Kind: "struct", Name: "sock"}}, "addr": {Offset: 8, Type: symbols.TypeRef{Kind: "pointer"}}}},
			"unix_address": {Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"len": {Type: base("u32")}, "name": {Offset: 8, Type: symbols.TypeRef{Kind: "array", Count: 0, Subtype: &name}}}},
			"sockaddr_un":  {Kind: "struct", Size: 110, Fields: map[string]symbols.Field{"sun_path": {Offset: 2, Type: symbols.TypeRef{Kind: "array", Count: 108, Subtype: &char}}}},
		}}
		env := plugin.Environment{Kernel: data, Symbols: table, Objects: &object.Reader{Layer: data, Symbols: table}}
		n := linuxNetReader{ctx: context.Background(), e: env, cells: map[string]evidence.Value{}, proof: map[string]any{}}
		linuxUnixName(&n, 0, "Source")
		if n.cells["Source"].Kind == "string" {
			if badPointer || length < 2 || length > 110 || int(length-2) > len(payload) || n.failures.count != 0 {
				t.Fatal(length, len(payload), n.cells)
			}
			raw := n.cells["SourceRaw"].Data.([]byte)
			if !bytes.Equal(raw, payload[:length-2]) || len(n.cells["Source"].String()) > 4*108+1 {
				t.Fatal(n.cells)
			}
		} else if n.failures.count == 0 || n.cells["Source"].Kind != "missing" || n.cells["Source"].Error == "" {
			t.Fatal(n.cells, n.failures)
		}
	})
}
