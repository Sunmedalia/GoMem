package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsStringsActualParserOracle(t *testing.T) {
	raw, err := os.ReadFile("../engine/testdata/windows-strings-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Parser []struct {
			Raw, Offset, Text string
			Error             bool
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Parser) != 1038 {
		t.Fatal("fixture drift")
	}
	for _, test := range fixture.Parser {
		data, _ := hex.DecodeString(test.Raw)
		offset, text, err := parseWindowsStringLine(data)
		want, overflow := strconv.ParseUint(test.Offset, 10, 64)
		if test.Error || overflow != nil {
			if err == nil {
				t.Fatalf("accepted %q: %d %q", data, offset, text)
			}
			continue
		}
		if err != nil || offset != want || hex.EncodeToString(text) != test.Text {
			t.Fatalf("%q: %d %q %v; want %s %s", data, offset, text, err, test.Offset, test.Text)
		}
	}
}

func FuzzWindowsStringsPipeline(f *testing.F) {
	raw, err := os.ReadFile("../engine/testdata/windows-strings-oracle.json")
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
	var image []byte
	var table *symbols.ISF
	for _, c := range fixture.Cases {
		if c.Width == 8 && c.Name == "normal" {
			image = make([]byte, c.Size)
			for _, w := range c.Writes {
				data, err := hex.DecodeString(w.Data)
				if err != nil {
					f.Fatal(err)
				}
				copy(image[w.Offset:], data)
			}
			table, err = symbols.Parse(c.ISF)
			if err != nil {
				f.Fatal(err)
			}
			break
		}
	}
	if table == nil {
		f.Fatal("missing fixture")
	}
	f.Add([]byte("1572864 alpha\n1048576 beta\n"), uint16(0x3003), uint8(0))
	f.Add([]byte("123\ninvalid\n"), uint16(0), uint8(8))
	f.Fuzz(func(t *testing.T, input []byte, entry uint16, cut uint8) {
		if len(input) > 2048 {
			input = input[:2048]
		}
		data := flatMemory(append([]byte(nil), image...))
		binary.LittleEndian.PutUint64(data[0x20000:], uint64(entry))
		calls := 0
		physical := stringsFuzzLayer{data, &calls}
		translator, err := memory.NewIntelForOS(physical, 0x8000, "x64", "windows", 4)
		if err != nil {
			t.Fatal(err)
		}
		kernel := &memory.Virtual{Physical: physical, Translator: translator, ID: "kernel"}
		hash := sha256.Sum256(input)
		env := plugin.Environment{OS: "windows", Architecture: "x64", KernelBase: 0x10000, Kernel: kernel, Physical: physical, Symbols: table, Objects: &object.Reader{Layer: kernel, Symbols: table}, Inputs: map[string]plugin.Input{"strings_file": {SHA256: hex.EncodeToString(hash[:]), Size: int64(len(input)), Reader: bytes.NewReader(input)}}}
		b := windowsStringsPlugins()[0]
		p, err := plugin.Parameters(b.Spec(), map[string]string{"strings_file": "fuzz", "max-nodes": "16", "max-lines": "32", "max-line-bytes": "512", "max-map-tables": "64", "max-map-entries": "10000", "max-mappings": "128", "max-associations": "128", "max-read-bytes": "262144"})
		if err != nil {
			t.Fatal(err)
		}
		stop := errors.New("strings fuzz output stopped")
		emitted, stopCalls := 0, -1
		err = b.Run(context.Background(), env, p, func(row evidence.Row) error {
			if stopCalls >= 0 {
				t.Fatal("emitted after stop")
			}
			emitted++
			if emitted > 4096 {
				t.Fatal("unbounded output")
			}
			if emitted == 1+int(cut)%32 {
				stopCalls = calls
				return stop
			}
			return nil
		})
		if stopCalls >= 0 && (!errors.Is(err, stop) || calls != stopCalls) {
			t.Fatal("output stop lost", err, calls, stopCalls)
		}
	})
}

type stringsFuzzLayer struct {
	memory.MemoryLayer
	calls *int
}

func (l stringsFuzzLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	*l.calls++
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
