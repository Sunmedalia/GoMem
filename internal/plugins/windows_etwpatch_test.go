package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestETWPatchParameterBounds(t *testing.T) {
	b := windowsETWPatchPlugins()[0]
	for _, key := range []string{"max-nodes", "max-regions", "max-modules", "max-read-bytes", "max-symbols", "max-probes", "pid"} {
		for _, value := range []string{"-1", "no", "18446744073709551615"} {
			p, err := plugin.Parameters(b.Spec(), map[string]string{key: value})
			if err == nil {
				err = b.Run(context.Background(), plugin.Environment{}, p, func(evidence.Row) error { return nil })
			}
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal(key, value, err)
			}
		}
	}
}

type etwFuzzLayer struct {
	memory.MemoryLayer
	hole bool
}

func (l etwFuzzLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if l.hole && len(p) == 1 && at == 0x101200 {
		return 0, memory.ErrUnmapped
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func FuzzETWPatchPipeline(f *testing.F) {
	raw, err := os.ReadFile("../engine/testdata/windows-etwpatch-oracle.json")
	if err != nil {
		f.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Width    int
			Name     string
			ISF, PDB json.RawMessage
			Size     int
			Writes   []struct {
				Offset int
				Data   string
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		f.Fatal(err)
	}
	var data []byte
	var kernel *symbols.ISF
	var pdbJSON json.RawMessage
	for _, c := range oracle.Cases {
		if c.Width == 8 && c.Name == "normal" {
			data = make([]byte, c.Size)
			for _, w := range c.Writes {
				bytes, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset+len(bytes) > len(data) {
					f.Fatal("bad fixture")
				}
				copy(data[w.Offset:], bytes)
			}
			kernel, err = symbols.Parse(c.ISF)
			if err != nil {
				f.Fatal(err)
			}
			pdbJSON = c.PDB
		}
	}
	if kernel == nil {
		f.Fatal("missing normal fixture")
	}
	var metadata struct {
		PDB symbols.PDBIdentity `json:"pdb"`
	}
	original, err := symbols.Parse(pdbJSON)
	if err != nil {
		f.Fatal(err)
	}
	if err = json.Unmarshal(original.Metadata()["windows"], &metadata); err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0xc3), uint64(0x1200), false, false, false)
	f.Add(uint8(0x90), uint64(0x1200), true, false, false)
	f.Add(uint8(0xe9), uint64(0xffffffffffffffff), false, true, true)
	f.Fuzz(func(t *testing.T, opcode uint8, rva uint64, hole, cycle, stop bool) {
		mem := flatMemory(append([]byte(nil), data...))
		mem[0x101200] = opcode
		if cycle {
			putU64(mem, 0x1000, 0x1000)
		}
		var doc map[string]any
		if err := json.Unmarshal(pdbJSON, &doc); err != nil {
			t.Fatal(err)
		}
		doc["symbols"].(map[string]any)["EtwEventWrite"] = map[string]any{"address": rva}
		encoded, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		table, err := symbols.Parse(encoded)
		if err != nil {
			t.Fatal(err)
		}
		env := plugin.Environment{OS: "windows", Architecture: "x64", KernelBase: 0x10000, Kernel: mem, Physical: etwFuzzLayer{mem, hole}, Symbols: kernel, Objects: &object.Reader{Layer: mem, Symbols: kernel}}
		env.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) {
			return pesymbols.PDB{Table: table, Identity: metadata.PDB}, nil
		}
		b := windowsETWPatchPlugins()[0]
		p, err := plugin.Parameters(b.Spec(), map[string]string{"max-nodes": "16", "max-regions": "16", "max-modules": "8", "max-read-bytes": "65536", "max-symbols": "8", "max-probes": "16"})
		if err != nil {
			t.Fatal(err)
		}
		emitted, found := 0, 0
		sentinel := errors.New("fuzz output stopped")
		err = b.Run(context.Background(), env, p, func(row evidence.Row) error {
			emitted++
			if emitted > 2048 {
				t.Fatal("unbounded ETW output")
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
			t.Fatal("output stop lost", err, emitted)
		}
		if !stop && !cycle && rva == 0x1200 {
			want := 6
			if !hole && (opcode == 0xc3 || opcode == 0xe9) {
				want++
			}
			if found != want {
				t.Fatal("first-byte selection or independent probes", found, want, err)
			}
		}
	})
}
