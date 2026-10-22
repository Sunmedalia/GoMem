package winnet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestActualNetStatIndexes(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for all original NetStat index schemas")
	}
	raw, err := os.ReadFile("../../internal/plugins/testdata/windows-netstat-index-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []struct {
			Layout, Mode, Scenario string
			SHA256                 string `json:"source_sha256"`
			Size                   int
			Kernel                 json.RawMessage `json:"kernel_isf"`
			TCPIP                  json.RawMessage `json:"tcpip_isf"`
			Writes                 []struct {
				Offset int
				Data   string
			}
			Rows []struct {
				Address uint64
				Type    string
			}
			Faults []json.RawMessage `json:"read_faults"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 256 {
		t.Fatal("index fixture drift")
	}
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%d/%s/%s/%s", i, c.Layout, c.Mode, c.Scenario), func(t *testing.T) {
			schema, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", c.Layout+".json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(schema)
			if hex.EncodeToString(sum[:]) != c.SHA256 {
				t.Fatal("source schema differs")
			}
			layout, err := Parse(schema)
			if err != nil {
				t.Fatal(err)
			}
			kernel, err := symbols.Parse(c.Kernel)
			if err != nil {
				t.Fatal(err)
			}
			tcpip, err := symbols.Parse(c.TCPIP)
			if err != nil {
				t.Fatal(err)
			}
			data := make(original, c.Size)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset > len(data) || len(b) > len(data)-w.Offset {
					t.Fatal("invalid source writes")
				}
				copy(data[w.Offset:], b)
			}
			x := &Index{Layout: layout, Layer: data, Kernel: kernel, TCPIP: tcpip, MaxNodes: 1000000}
			var got []struct {
				Address uint64
				Type    string
			}
			err = x.Walk(context.Background(), func(entry IndexEntry) error {
				got = append(got, struct {
					Address uint64
					Type    string
				}{entry.Address, entry.Type})
				return nil
			})
			// The baseline silently treats oversize indexes as empty; the native walk
			// keeps matching readable entities but explicitly fails completeness.
			bad := len(c.Faults) > 0 || c.Scenario == "oversize-hash" || c.Scenario == "oversize-bitmap"
			if (err != nil) != bad {
				t.Fatal("index completeness", err, len(c.Faults))
			}
			if len(got) == 0 && len(c.Rows) == 0 {
			} else if !reflect.DeepEqual(got, c.Rows) {
				t.Fatal("actual index entries differ", got, c.Rows, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := x.Walk(ctx, func(IndexEntry) error { t.Fatal("output after cancel"); return nil }); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if c.Scenario == "normal" {
				stop := errors.New("stop output")
				calls := 0
				if err := x.Walk(context.Background(), func(IndexEntry) error { calls++; return stop }); !errors.Is(err, stop) || calls != 1 {
					t.Fatal("emitter failure lost", calls, err)
				}
				x.MaxNodes = 1
				if err := x.Walk(context.Background(), func(IndexEntry) error { return nil }); err == nil {
					t.Fatal("index bound ignored")
				}
			}
		})
	}
}

func indexControl(t testing.TB) (*Index, original) {
	t.Helper()
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Skip("set GOMEM_BASELINE_DIR for index mutation controls")
	}
	raw, err := os.ReadFile("../../internal/plugins/testdata/windows-netstat-index-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Layout, Mode, Scenario string
			Size                   int
			Kernel                 json.RawMessage `json:"kernel_isf"`
			TCPIP                  json.RawMessage `json:"tcpip_isf"`
			Writes                 []struct {
				Offset int
				Data   string
			}
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		if c.Layout == "netscan-win7-x64" && c.Mode == "direct" && c.Scenario == "normal" {
			schema, err := os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/netscan", c.Layout+".json"))
			if err != nil {
				t.Fatal(err)
			}
			layout, err := Parse(schema)
			if err != nil {
				t.Fatal(err)
			}
			kernel, err := symbols.Parse(c.Kernel)
			if err != nil {
				t.Fatal(err)
			}
			tcpip, err := symbols.Parse(c.TCPIP)
			if err != nil {
				t.Fatal(err)
			}
			data := make(original, c.Size)
			for _, w := range c.Writes {
				b, err := hex.DecodeString(w.Data)
				if err != nil || w.Offset < 0 || w.Offset > len(data) || len(b) > len(data)-w.Offset {
					t.Fatal("invalid mutation fixture")
				}
				copy(data[w.Offset:], b)
			}
			return &Index{Layout: layout, Layer: data, Kernel: kernel, TCPIP: tcpip, MaxNodes: 100000}, data
		}
	}
	t.Fatal("normal index control absent")
	return nil, nil
}

func TestIndexCyclesUnderflowAndCorruptSymbols(t *testing.T) {
	for _, mode := range []string{"cycle", "underflow", "schema", "symbols", "width", "overflow", "zero-budget"} {
		t.Run(mode, func(t *testing.T) {
			x, data := indexControl(t)
			switch mode {
			case "cycle":
				next, err := x.member("_TCP_LISTENER", "Next")
				if err != nil {
					t.Fatal(err)
				}
				binary.LittleEndian.PutUint64(data[0x23000+next.Offset:], 0x22000+next.Offset|3)
			case "underflow":
				entry := x.Layout.table.Types["_PORT_ASSIGNMENT_ENTRY"].Fields["Entry"]
				stride := x.Layout.table.Types["_PORT_ASSIGNMENT_ENTRY"].Size
				binary.LittleEndian.PutUint64(data[0x14000+2*stride+entry.Offset:], 4)
			case "schema":
				delete(x.Layout.table.Types, "_PARTITION_TABLE")
			case "symbols":
				delete(x.TCPIP.(*symbols.ISF).Symbols, "PartitionTable")
			case "width":
				x.Kernel.(*symbols.ISF).Bases["pointer"] = symbols.Type{Kind: "int", Size: 4, Endian: "little"}
			case "overflow":
				x.ModuleBase = ^uint64(0) - 0x80
			case "zero-budget":
				x.MaxNodes = 0
			}
			calls := 0
			if err := x.Walk(context.Background(), func(IndexEntry) error {
				calls++
				if calls > 100 {
					t.Fatal("unbounded cycle")
				}
				return nil
			}); err == nil {
				t.Fatal("invalid index became success", mode)
			}
		})
	}
}

func FuzzNetworkIndexes(f *testing.F) {
	x, source := indexControl(f)
	f.Add([]byte{}, uint16(0), uint8(0))
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255}, uint16(0), uint8(2))
	f.Add([]byte{0, 0, 0, 0}, uint16(4), uint8(3))
	f.Fuzz(func(t *testing.T, mutation []byte, offset uint16, region uint8) {
		if len(mutation) > 256 {
			mutation = mutation[:256]
		}
		data := append(original(nil), source...)
		regions := []int{0x100, 0x1000, 0x2000, 0x3000, 0x4000, 0x8000, 0xc000, 0xd000, 0x14000, 0x22000}
		at := regions[int(region)%len(regions)] + int(offset)%256
		copy(data[at:], mutation)
		walk := *x
		walk.Layer = data
		walk.MaxNodes = 4096
		count := 0
		_ = walk.Walk(context.Background(), func(e IndexEntry) error {
			count++
			if count > 4096 {
				t.Fatal("unbounded index output")
			}
			if e.Type != "_TCP_ENDPOINT" && e.Type != "_TCP_LISTENER" && e.Type != "_UDP_ENDPOINT" {
				t.Fatal("unknown object kind")
			}
			return nil
		})
	})
}
