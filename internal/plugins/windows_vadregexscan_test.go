package plugins

import (
	"bytes"
	"context"
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

func FuzzWindowsVADRegexPipeline(f *testing.F) {
	raw, err := os.ReadFile("../engine/testdata/windows-regex-oracle.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Arch string
			Size       int
			ISF        json.RawMessage
			Writes     []struct {
				Offset int
				Data   string
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		f.Fatal(err)
	}
	var original flatMemory
	var table *symbols.ISF
	for _, c := range fixture.Cases {
		if c.Name != "literal" || c.Arch != "x64" {
			continue
		}
		original = make(flatMemory, c.Size)
		for _, w := range c.Writes {
			b, err := hex.DecodeString(w.Data)
			if err != nil || w.Offset < 0 || w.Offset+len(b) > len(original) {
				f.Fatal("invalid fixture")
			}
			copy(original[w.Offset:], b)
		}
		table, err = symbols.Parse(c.ISF)
		if err != nil {
			f.Fatal(err)
		}
	}
	if table == nil {
		f.Fatal("missing fixture")
	}
	f.Add("MATCH", []byte("MATCH"), uint8(0))
	f.Add("", []byte{0xff, 0}, uint8(1))
	f.Add("(AB)\\1", []byte("ABAB"), uint8(2))
	f.Fuzz(func(t *testing.T, pattern string, payload []byte, region uint8) {
		if len(pattern) > 64 || len(payload) > 256 {
			return
		}
		data := append(flatMemory(nil), original...)
		at := []int{0x100000, 0x1000, 0xb800, 0x430, 0x450, 0x418}[int(region)%6]
		copy(data[at:], payload)
		intel, err := memory.NewIntelForOS(data, 0x8000, "x64", "windows", 16)
		if err != nil {
			t.Fatal(err)
		}
		kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
		e := plugin.Environment{OS: "windows", Architecture: "x64", Physical: data, Kernel: kernel, Symbols: table, Objects: &object.Reader{Layer: kernel, Symbols: table}, KernelBase: 0x10000, ImageHash: "fixture"}
		b := windowsVADRegexPlugins()[0]
		p, err := plugin.Parameters(b.spec, map[string]string{"pattern": pattern, "max-nodes": "8", "max-regions": "8", "max-map-tables": "32", "max-map-entries": "8192", "max-mappings": "32", "max-chunks": "32", "max-matches": "16", "max-diagnostics": "16", "max-proof-pages": "32", "max-read-bytes": "262144", "regex-steps": "4096"})
		if err != nil {
			t.Fatal(err)
		}
		calls, matches := 0, 0
		stopped := false
		_ = b.run(context.Background(), e, p, func(row evidence.Row) error {
			if stopped {
				t.Fatal("output after stop")
			}
			calls++
			if calls > 3000 {
				stopped = true
				return errors.New("output stopped")
			}
			if row.Cells["RecordType"].String() != "regex_match" {
				return nil
			}
			matches++
			if matches > 16 {
				t.Fatal("unbounded matches")
			}
			source := row.Cells["Source"].Data.(map[string]evidence.Value)
			var expected []byte
			for _, part := range source["Parts"].Data.([]map[string]evidence.Value) {
				physical, _ := part["Physical"].Uint()
				length, _ := part["Length"].Uint()
				if physical > uint64(len(data)) || length > uint64(len(data))-physical {
					t.Fatal("source outside image")
				}
				expected = append(expected, data[physical:physical+length]...)
			}
			if !bytes.Equal(expected, row.Cells["MatchRaw"].Data.([]byte)) {
				t.Fatal("false byte attribution")
			}
			return nil
		})
	})
}
