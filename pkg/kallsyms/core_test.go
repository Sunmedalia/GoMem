package kallsyms_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/kallsyms"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type coreRow struct {
	Name, Type string
	Address    uint64
	Size       *uint64
	Exported   *bool
}
type coreCase struct {
	Width            int
	Layout, Scenario string
	Config           kallsyms.Config
	ISF              json.RawMessage
	Writes           [][]json.RawMessage
	Expected         []coreRow
}
type buffer []byte

func (b buffer) Name() string           { return "core-fixture" }
func (b buffer) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(b))}} }
func (b buffer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at >= uint64(len(b)) {
		return 0, memory.ErrUnmapped
	}
	n := copy(p, b[at:])
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func cases(t testing.TB) []coreCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/core-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Commit string
		Cases  []coreCase
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(v.Cases) != 52 {
		t.Fatal(err, len(v.Cases))
	}
	return v.Cases
}
func dataFor(t testing.TB, c coreCase) buffer {
	t.Helper()
	data := make(buffer, 0x18000)
	for _, w := range c.Writes {
		var at int
		var value string
		if err := json.Unmarshal(w[0], &at); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(w[1], &value); err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], raw)
	}
	return data
}
func bounds() kallsyms.Limits {
	return kallsyms.Limits{Symbols: 1000, Bytes: 1 << 20, TokenBytes: 4096, NameBytes: 4096}
}
func TestPinnedCoreObjects(t *testing.T) {
	for _, c := range cases(t) {
		t.Run(fmt.Sprintf("%d/%s/%s", c.Width, c.Layout, c.Scenario), func(t *testing.T) {
			table, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			config, err := kallsyms.FromSymbols(table, 0, c.Config.AddressMask)
			if err != nil || !reflect.DeepEqual(config, c.Config) {
				t.Fatal(config, c.Config, err)
			}
			core, err := kallsyms.Open(context.Background(), dataFor(t, c), config, bounds())
			if err != nil {
				t.Fatal(err)
			}
			got := []coreRow{}
			err = core.Stream(context.Background(), func(s kallsyms.Symbol) error {
				row := coreRow{Name: s.Name, Type: s.Type, Address: s.Address, Exported: s.Exported}
				if s.SizeAvailable {
					value := s.Size
					row.Size = &value
				}
				if s.NextOffset != s.NameOffset+s.CompressedLength+1 {
					t.Fatal(s)
				}
				if c.Scenario == "big-last" && s.Index == 2 && s.HeaderBytes != 2 {
					t.Fatal(s)
				}
				got = append(got, row)
				return nil
			})
			if err != nil || !reflect.DeepEqual(got, c.Expected) {
				t.Fatalf("%v\ngot %+v\nwant %+v", err, got, c.Expected)
			}
			if core.Stats().AcquiredBytes == 0 || core.Count() != uint64(len(got)) {
				t.Fatal(core.Stats())
			}
		})
	}
}

func TestCoreFailuresAndLimits(t *testing.T) {
	c := cases(t)[0]
	for _, fault := range []string{"short-count", "count-bound", "byte-bound", "index-hole", "address-hole", "unordered", "name-hole", "token-hole", "unterminated", "non-ascii", "name-bound", "relative-without-base"} {
		t.Run(fault, func(t *testing.T) {
			config := c.Config
			data := dataFor(t, c)
			limits := bounds()
			switch fault {
			case "short-count":
				config.Count = uint64(len(data) - 1)
			case "count-bound":
				limits.Symbols = 1
			case "byte-bound":
				limits.Bytes = 8
			case "index-hole":
				config.TokenIndex = uint64(len(data))
			case "address-hole":
				config.Addresses = uint64(len(data))
			case "unordered":
				binary.LittleEndian.PutUint32(data[0x16104:], 1)
			case "name-hole":
				config.Names = uint64(len(data))
			case "token-hole":
				config.TokenTable = uint64(len(data))
			case "unterminated":
				for i := 0x17400; i < len(data); i++ {
					data[i] = 'a'
				}
				limits.TokenBytes = 32
			case "non-ascii":
				data[0x17400] = 0xff
			case "name-bound":
				limits.NameBytes = 2
			case "relative-without-base":
				config.Offsets = config.Addresses
				config.RelativeBase = 0
			}
			core, err := kallsyms.Open(context.Background(), data, config, limits)
			if err == nil {
				err = core.Stream(context.Background(), func(kallsyms.Symbol) error { return nil })
			}
			if err == nil {
				t.Fatal("failure became success")
			}
		})
	}
}
func TestCoreEveryEmissionBoundaryAndCancellation(t *testing.T) {
	c := cases(t)[0]
	stop := errors.New("output stopped")
	for boundary := 1; boundary <= 3; boundary++ {
		core, err := kallsyms.Open(context.Background(), dataFor(t, c), c.Config, bounds())
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		err = core.Stream(context.Background(), func(kallsyms.Symbol) error {
			calls++
			if calls == boundary {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) || calls != boundary {
			t.Fatal(calls, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		calls = 0
		err = core.Stream(ctx, func(kallsyms.Symbol) error {
			calls++
			if calls == boundary {
				cancel()
			}
			return nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || calls != boundary {
			t.Fatal(calls, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := kallsyms.Open(ctx, dataFor(t, c), c.Config, bounds()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestCoreBigEndian(t *testing.T) {
	c := cases(t)[0]
	data := dataFor(t, c)
	// Swap only the typed words. Compressed strings/tokens are byte-oriented.
	for _, region := range []struct{ at, count, width int }{{0x16000, 1, 4}, {0x16100, 3, 4}, {0x16800, 256, 2}} {
		for i := 0; i < region.count; i++ {
			p := data[region.at+i*region.width : region.at+(i+1)*region.width]
			for a, b := 0, len(p)-1; a < b; a, b = a+1, b-1 {
				p[a], p[b] = p[b], p[a]
			}
		}
	}
	c.Config.Endian = "big"
	core, err := kallsyms.Open(context.Background(), data, c.Config, bounds())
	if err != nil {
		t.Fatal(err)
	}
	got := []coreRow{}
	err = core.Stream(context.Background(), func(s kallsyms.Symbol) error {
		size := s.Size
		got = append(got, coreRow{s.Name, s.Type, s.Address, &size, s.Exported})
		return nil
	})
	if err != nil || !reflect.DeepEqual(got, c.Expected) {
		t.Fatal(got, c.Expected, err)
	}
}
func FuzzCoreTables(f *testing.F) {
	c := cases(f)[0]
	original := dataFor(f, c)
	f.Add([]byte{0xff}, uint8(0))
	f.Add([]byte{0, 0, 0, 0}, uint8(2))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 512 {
			return
		}
		data := append(buffer(nil), original...)
		at := []int{0x16000, 0x16100, 0x16800, 0x17000, 0x17400}[int(region)%5]
		copy(data[at:], payload)
		limits := bounds()
		limits.Symbols = 32
		limits.Bytes = 4096
		limits.NameBytes = 512
		limits.TokenBytes = 512
		core, err := kallsyms.Open(context.Background(), data, c.Config, limits)
		if err != nil {
			return
		}
		count := 0
		_ = core.Stream(context.Background(), func(kallsyms.Symbol) error {
			count++
			if count > 32 {
				t.Fatal("unbounded output")
			}
			return nil
		})
	})
}

func TestCoreConfigSlideAndMask(t *testing.T) {
	c := cases(t)[0]
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kallsyms_num_syms", "_end", "_etext", "_sinittext", "_einittext"} {
		symbol := table.Symbols[name]
		symbol.Address |= 0xffff000000000000
		table.Symbols[name] = symbol
	}
	config, err := kallsyms.FromSymbols(table, 0x1000, 0x0000ffffffffffff)
	if err != nil || config.Count != 0xffff000000017000 || config.End != 0x9800 || config.TextEnd != 0x9600 || config.InitStart != 0x9700 {
		t.Fatal(config, err)
	}
	delete(table.Symbols, "kallsyms_names")
	if _, err = kallsyms.FromSymbols(table, 0, 0xffffffff); err == nil {
		t.Fatal("missing symbol accepted")
	}
}

func TestCoreInvalidConfiguration(t *testing.T) {
	c := cases(t)[0]
	for _, field := range []string{"width", "count-width", "mask", "endian", "symbols", "bytes", "token-bytes", "name-bytes"} {
		t.Run(field, func(t *testing.T) {
			config, limit := c.Config, bounds()
			switch field {
			case "width":
				config.Width = 2
			case "count-width":
				config.CountSize = 2
			case "mask":
				config.AddressMask = 0
			case "endian":
				config.Endian = "unknown"
			case "symbols":
				limit.Symbols = 10000001
			case "bytes":
				limit.Bytes = 1<<30 + 1
			case "token-bytes":
				limit.TokenBytes = 0
			case "name-bytes":
				limit.NameBytes = 0
			}
			if _, err := kallsyms.Open(context.Background(), dataFor(t, c), config, limit); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

type invalidReadLayer struct {
	buffer
	n int
}

func (l invalidReadLayer) ReadAt(context.Context, []byte, uint64) (int, error) { return l.n, nil }
func TestCoreRejectsInvalidReadCounts(t *testing.T) {
	c := cases(t)[0]
	for _, n := range []int{-1, 8} {
		if _, err := kallsyms.Open(context.Background(), invalidReadLayer{dataFor(t, c), n}, c.Config, bounds()); err == nil {
			t.Fatal(n)
		}
	}
	core, err := kallsyms.Open(context.Background(), dataFor(t, c), c.Config, bounds())
	if err != nil {
		t.Fatal(err)
	}
	if err = core.Stream(context.Background(), nil); err == nil {
		t.Fatal("nil emitter")
	}
	if _, _, _, _, err = core.Expand(context.Background(), ^uint64(0)); err == nil {
		t.Fatal("name address overflow")
	}
}
