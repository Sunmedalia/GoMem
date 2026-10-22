package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsMalfindParameterBounds(t *testing.T) {
	b := windowsMalfindPlugins()[0]
	for _, key := range []string{"pid", "max-nodes", "max-regions", "max-pages", "max-read-bytes", "maxsize", "dump"} {
		for _, v := range []string{"-1", "no"} {
			p, err := plugin.Parameters(b.Spec(), map[string]string{key: v})
			if err == nil {
				err = b.Run(context.Background(), plugin.Environment{}, p, func(evidence.Row) error { return nil })
			}
			if err == nil {
				t.Fatal(key, v, "invalid parameter accepted")
			}
		}
	}
}
func FuzzWindowsMalfindPipeline(f *testing.F) {
	raw, err := os.ReadFile("../engine/testdata/windows-malfind-oracle.json")
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
		if c.Width == 8 && c.Name == "rwx-private-short" {
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
		f.Fatal("missing fixture")
	}
	f.Add(uint32(0x40), true, true, true, false, false)
	f.Add(uint32(0x20), false, false, false, true, true)
	f.Fuzz(func(t *testing.T, protection uint32, private, nonzero, dirty, hole, stop bool) {
		mem := flatMemory(append([]byte(nil), data...))
		binary.LittleEndian.PutUint32(mem[0x19004:], protection)
		flags := uint32(1 | 3<<16)
		if private {
			flags |= 0x100
		}
		binary.LittleEndian.PutUint32(mem[0x1030:], flags)
		if !nonzero {
			clear(mem[0x100000:0x104000])
		}
		entry := uint64(0x100003)
		if dirty {
			entry |= 0x40
		}
		if hole {
			entry = 0
		}
		putU64(mem, 0xb000+0x100*8, entry)
		env := plugin.Environment{OS: "windows", Architecture: "x64", KernelBase: 0x10000, Kernel: mem, Physical: mem, Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}}
		b := windowsMalfindPlugins()[0]
		p, err := plugin.Parameters(b.Spec(), map[string]string{"max-nodes": "16", "max-regions": "8", "max-pages": "16", "max-read-bytes": "131072"})
		if err != nil {
			t.Fatal(err)
		}
		emitted, found := 0, 0
		sentinel := errors.New("malfind fuzz output stopped")
		err = b.Run(context.Background(), env, p, func(row evidence.Row) error {
			emitted++
			if emitted > 4096 {
				t.Fatal("unbounded malfind output")
			}
			if row.Cells["RecordType"].String() == "finding" {
				found++
			}
			if stop {
				return sentinel
			}
			return nil
		})
		if stop && (!errors.Is(err, sentinel) || emitted != 1) {
			t.Fatal("lost output stop", err, emitted)
		}
		if !stop && (protection == 0x40 || protection == 0x20) {
			want := 0
			if nonzero && !hole && (protection == 0x40 || dirty) {
				want = 1
			}
			if found != want {
				t.Fatal("selection differs", found, want, err)
			}
		}
	})
}

// Exhausting the acquisition budget stops before touching the source.
func TestMalfindReadBudgetStopPrecedesSource(t *testing.T) {
	calls := 0
	source := malfindCountingLayer{&calls}
	a := &windowsSymbolAnalysis{ctx: context.Background(), out: func(evidence.Row) error { return nil }, maxBytes: 1}
	layer := windowsMalfindRead{source, a, "nonzero_page"}
	_, err := layer.ReadAt(context.Background(), make([]byte, 2), 0)
	if err == nil || calls != 0 || a.stop == nil {
		t.Fatal(err, calls)
	}
}

type malfindCountingLayer struct{ calls *int }

func (l malfindCountingLayer) Name() string           { return "counted" }
func (l malfindCountingLayer) Ranges() []memory.Range { return nil }
func (l malfindCountingLayer) ReadAt(_ context.Context, p []byte, _ uint64) (int, error) {
	*l.calls++
	clear(p)
	return len(p), nil
}
