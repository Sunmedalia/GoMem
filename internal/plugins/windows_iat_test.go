package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestIATParameterBounds(t *testing.T) {
	b := windowsIATPlugins()[0]
	for _, key := range []string{"pid", "max-nodes", "max-descriptors", "max-imports", "max-thunks", "max-read-bytes"} {
		for _, v := range []string{"-1", "no", "18446744073709551615"} {
			p, err := plugin.Parameters(b.Spec(), map[string]string{key: v})
			if err == nil {
				err = b.Run(context.Background(), plugin.Environment{}, p, func(evidence.Row) error { return nil })
			}
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal(key, v, err)
			}
		}
	}
}

type iatFuzzPhysical struct {
	memory.MemoryLayer
	hole  bool
	calls *int
}

func (l iatFuzzPhysical) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	*l.calls++
	if l.hole && at == 0x101f00 {
		return 0, memory.ErrUnmapped
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func FuzzIATPipeline(f *testing.F) {
	raw, err := os.ReadFile("../engine/testdata/windows-iat-oracle.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Width  int
			Name   string
			Size   int
			ISF    json.RawMessage
			Writes []struct {
				Offset int
				Data   string
			}
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		f.Fatal(err)
	}
	var data []byte
	var table *symbols.ISF
	for _, c := range fixture.Cases {
		if c.Width == 8 && c.Name == "normal" {
			data = make([]byte, c.Size)
			for _, w := range c.Writes {
				part, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset+len(part) > len(data) {
					f.Fatal("bad fixture")
				}
				copy(data[w.Offset:], part)
			}
			table, err = symbols.Parse(c.ISF)
			if err != nil {
				f.Fatal(err)
			}
		}
	}
	if table == nil {
		f.Fatal("missing normal fixture")
	}
	f.Add(uint32(0x1c00), uint64(0x1f00), false, false, false)
	f.Add(uint32(0xffffffff), uint64(0xffffffffffffffff), true, true, true)
	f.Fuzz(func(t *testing.T, directory uint32, thunk uint64, hole, cycle, stop bool) {
		mem := flatMemory(append([]byte(nil), data...))
		binary.LittleEndian.PutUint32(mem[0x100110:], directory)
		binary.LittleEndian.PutUint64(mem[0x101d00:], thunk)
		if cycle {
			putU64(mem, 0x400, 0x400)
		}
		calls, atStop := 0, -1
		physical := iatFuzzPhysical{mem, hole, &calls}
		env := plugin.Environment{OS: "windows", Architecture: "x64", KernelBase: 0x10000, Kernel: mem, Physical: physical, Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}}
		b := windowsIATPlugins()[0]
		p, err := plugin.Parameters(b.Spec(), map[string]string{"max-nodes": "16", "max-descriptors": "8", "max-imports": "16", "max-thunks": "128", "max-read-bytes": "4096"})
		if err != nil {
			t.Fatal(err)
		}
		emitted, found := 0, 0
		sentinel := errors.New("IAT fuzz output stop")
		err = b.Run(context.Background(), env, p, func(row evidence.Row) error {
			emitted++
			if emitted > 8192 {
				t.Fatal("unbounded IAT output")
			}
			if row.Cells["RecordType"].String() == "import" {
				found++
			}
			if stop {
				atStop = calls
				return sentinel
			}
			return nil
		})
		if stop && (!errors.Is(err, sentinel) || emitted != 1 || calls != atStop) {
			t.Fatal("lost output stop", emitted, err)
		}
		if !stop && !cycle && directory == 0x1c00 && thunk == 0x1f00 {
			want := 2
			if hole {
				want = 0
			}
			if found != want {
				t.Fatal("normal/damaged descriptor selection", found, want, err)
			}
		}
	})
}
