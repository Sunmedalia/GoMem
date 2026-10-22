package winconsole

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"

	"encoding/json"
	"os"
	"testing"
)

func TestOriginalConhostVersionSelections(t *testing.T) {
	raw, err := os.ReadFile("testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit   string
		Memories map[string]struct {
			ISF    json.RawMessage
			Size   int
			Writes []struct {
				Offset int
				Data   string
			}
		}
		Cases []struct {
			Arch                          string
			Width                         int
			Major, Minor, Build, Revision uint64
			Result                        struct {
				Name, Error  string
				Windows10X64 bool `json:"win10_x64"`
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 663 {
		t.Fatal("version fixture drift")
	}
	for _, c := range fixture.Cases {
		mem := fixture.Memories[c.Arch]
		physical := original{data: make([]byte, mem.Size)}
		for _, w := range mem.Writes {
			raw, err := hex.DecodeString(w.Data)
			if err != nil || w.Offset < 0 || w.Offset > len(physical.data) || len(raw) > len(physical.data)-w.Offset {
				t.Fatal("invalid original write")
			}
			copy(physical.data[w.Offset:], raw)
		}
		binary.LittleEndian.PutUint16(physical.data[0x1002:], uint16(c.Build))
		binary.LittleEndian.PutUint32(physical.data[0x18000:], uint32(c.Major))
		binary.LittleEndian.PutUint32(physical.data[0x18004:], uint32(c.Minor))
		table, err := symbols.Parse(mem.ISF)
		if err != nil {
			t.Fatal(err)
		}
		translator, err := memory.NewIntel(physical, 0x8000, c.Arch, 64)
		if err != nil {
			t.Fatal(err)
		}
		reader := &object.Reader{Layer: &memory.Virtual{Physical: physical, Translator: translator, ID: c.Arch}, Symbols: table}
		measured, err := VersionFromMemory(context.Background(), reader, 0)
		if err != nil || measured.Width != c.Width || measured.Major != c.Major || measured.Minor != c.Minor || measured.Build != c.Build || measured.Revision != 0 {
			t.Fatal("measured version mismatch", measured, c, err)
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := VersionFromMemory(canceled, reader, 0); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if _, err := VersionFromMemory(context.Background(), reader, ^uint64(0)); err == nil {
			t.Fatal("debug block address overflow ignored")
		}
		// A readable debug block does not justify guessing missing KUSER data.
		broken := physical
		broken.holes = [][2]uint64{{0x18000, 8}}
		badTranslator, err := memory.NewIntel(broken, 0x8000, c.Arch, 64)
		if err != nil {
			t.Fatal(err)
		}
		badReader := &object.Reader{Layer: &memory.Virtual{Physical: broken, Translator: badTranslator, ID: c.Arch}, Symbols: table}
		if _, err := VersionFromMemory(context.Background(), badReader, 0); err == nil {
			t.Fatal("unreadable KUSER substituted")
		}
		v := Version{Width: c.Width, Major: c.Major, Minor: c.Minor, Build: c.Build, Revision: c.Revision}
		got, err := Select(v)
		if c.Result.Error != "" {
			if err == nil {
				t.Fatal("unsupported version selected", v, got)
			}
			continue
		}
		if err != nil || got.Name != c.Result.Name || got.Windows10X64 != c.Result.Windows10X64 {
			t.Fatal(v, got, c.Result, err)
		}
		if _, ok := catalogPins[got.Name]; !ok {
			t.Fatal("unpinned selection", got)
		}
		if got.MatchedBuild > v.Build || got.MatchedRevision > got.EffectiveRevision {
			t.Fatal("invalid fallback", v, got)
		}
	}
	if _, err := Select(Version{Width: 16}); err == nil {
		t.Fatal("invalid width accepted")
	}
	for _, v := range []Version{{Width: 8, Major: 10, Build: 17763}, {Width: 8, Major: 10, Build: 20348}, {Width: 8, Major: 10, Build: 22621}} {
		if !v.NeedsRevision() {
			t.Fatal("missing revision dependency", v)
		}
	}
	for _, v := range []Version{{Width: 4, Major: 10, Build: 17763}, {Width: 8, Major: 10, Build: 25398}, {Width: 8, Major: 10, Build: 22622}} {
		if v.NeedsRevision() {
			t.Fatal("unexpected revision dependency", v)
		}
	}
}
