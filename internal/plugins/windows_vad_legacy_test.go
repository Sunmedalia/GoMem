package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type vadRootFixture struct {
	Name     string
	ISF      json.RawMessage
	Size     int
	Segments []struct {
		Offset int
		Hex    string
	}
	Expected []struct {
		Address, Start, End, Parent, Left, Right uint64
		Tag                                      string
		File                                     *string
	}
}

func vadRootFixtures(t *testing.T) []vadRootFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/windows-vad-roots-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Cases []vadRootFixture }
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 12 {
		t.Fatal(len(fixture.Cases))
	}
	return fixture.Cases
}
func vadRootEnvironment(t *testing.T, c vadRootFixture) (plugin.Environment, flatMemory) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	mem := make(flatMemory, c.Size)
	for _, seg := range c.Segments {
		raw, err := hex.DecodeString(seg.Hex)
		if err != nil {
			t.Fatal(err)
		}
		copy(mem[seg.Offset:], raw)
	}
	return plugin.Environment{Kernel: mem, Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}}, mem
}
func TestWindowsLegacyVADOracle(t *testing.T) {
	for _, c := range vadRootFixtures(t) {
		t.Run(c.Name, func(t *testing.T) {
			e, _ := vadRootEnvironment(t, c)
			rows, err := windowsVADRegions(context.Background(), e, 0x100, 100)
			if err != nil || len(rows) != len(c.Expected) {
				t.Fatal(len(rows), err)
			}
			for i, want := range c.Expected {
				got := rows[i]
				if want.File == nil {
					if got.file.Kind != "missing" {
						t.Errorf("unexpected path: %v", got.file)
					}
				} else if got.file.String() != *want.File {
					t.Errorf("path: %v; want %s", got.file, *want.File)
				}
				if got.address != want.Address || got.start != want.Start || got.end != want.End || got.parent != want.Parent || got.left != want.Left || got.right != want.Right || got.tag != want.Tag {
					t.Errorf("node %d: %+v; want %+v", i, got, want)
				}
			}
		})
	}
}
func TestWindowsLegacyVADCorruptionAndCancellation(t *testing.T) {
	for _, c := range vadRootFixtures(t) {
		for _, scenario := range []string{"parent", "cycle", "tag", "limit", "short-read", "cancel"} {
			t.Run(c.Name+"/"+scenario, func(t *testing.T) {
				e, mem := vadRootEnvironment(t, c)
				width := uint64(e.Symbols.PointerSize())
				put := func(offset, value uint64) {
					if width == 8 {
						putU64(mem, offset, value)
					} else {
						putU32(mem, offset, uint32(value))
					}
				}
				ctx := context.Background()
				max := 100
				switch scenario {
				case "parent":
					put(0x600, 0x800)
				case "cycle":
					put(0x400+width, 0x400)
				case "tag":
					bias := uint64(12)
					if width == 4 {
						bias = 4
					}
					copy(mem[0x600-bias:], "bad!")
				case "limit":
					max = 2
				case "short-read":
					put(0x400+width, 0x4000)
				case "cancel":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				_, err := windowsLegacyVADRegions(ctx, e, 0x100, max)
				if err == nil {
					t.Fatal("corruption became a complete VAD index")
				}
				if scenario == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestWindowsLegacyVADNullAndEmptySentinel(t *testing.T) {
	for _, c := range vadRootFixtures(t) {
		t.Run(c.Name, func(t *testing.T) {
			e, mem := vadRootEnvironment(t, c)
			width := e.Symbols.PointerSize()
			// Empty inline roots have no tag, and must not become a memory range.
			if strings.HasPrefix(c.Name, "balanced-") {
				clear(mem[0x108 : 0x108+width*3])
			} else {
				clear(mem[0x108 : 0x108+width])
			}
			rows, err := windowsVADRegions(context.Background(), e, 0x100, 100)
			if err != nil || len(rows) != 0 {
				t.Fatal(rows, err)
			}
		})
	}
}

func TestWindowsLegacyVADFileFaultKeepsCause(t *testing.T) {
	for _, c := range vadRootFixtures(t) {
		t.Run(c.Name, func(t *testing.T) {
			e, mem := vadRootEnvironment(t, c)
			if e.Symbols.PointerSize() == 8 {
				putU64(mem, 0x1000, 0x4000)
			} else {
				putU32(mem, 0x1000, 0x4000)
			}
			rows, err := windowsVADRegions(context.Background(), e, 0x100, 100)
			if err != nil || len(rows) != 3 {
				t.Fatal(rows, err)
			}
			cell := rows[1].file
			if cell.Kind != "missing" || cell.Error == "" {
				t.Fatal("file failure lost its cause", cell)
			}
		})
	}
}

func FuzzWindowsVADTraversal(f *testing.F) {
	raw, err := os.ReadFile("testdata/windows-vad-roots-oracle.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture struct{ Cases []vadRootFixture }
	if err = json.Unmarshal(raw, &fixture); err != nil {
		f.Fatal(err)
	}
	type seed struct {
		table *symbols.ISF
		mem   flatMemory
	}
	var seeds []seed
	for i, c := range fixture.Cases {
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			f.Fatal(err)
		}
		mem := make(flatMemory, c.Size)
		for _, segment := range c.Segments {
			b, err := hex.DecodeString(segment.Hex)
			if err != nil {
				f.Fatal(err)
			}
			copy(mem[segment.Offset:], b)
		}
		seeds = append(seeds, seed{table, mem})
		f.Add(uint8(i), uint16(0), []byte{})
		f.Add(uint8(i), uint16(0x400), []byte{0xff, 0xff, 0xff, 0xff})
	}
	f.Fuzz(func(t *testing.T, index uint8, offset uint16, data []byte) {
		c := seeds[int(index)%len(seeds)]
		mem := append(flatMemory{}, c.mem...)
		if len(data) > 512 {
			data = data[:512]
		}
		copy(mem[int(offset)%len(mem):], data)
		e := plugin.Environment{Kernel: mem, Symbols: c.table, Objects: &object.Reader{Layer: mem, Symbols: c.table}}
		_, _ = windowsVADPaths(context.Background(), e, 0x100, 64)
	})
}
