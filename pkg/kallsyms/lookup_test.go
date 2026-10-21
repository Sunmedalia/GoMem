package kallsyms_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/kallsyms"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type lookupCase struct {
	coreCase
	Order    string
	Expected []struct {
		Query  uint64
		Result *coreRow
		Error  *string
	}
}

func lookupCases(t testing.TB) []lookupCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/lookup-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []lookupCase
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 180 {
		t.Fatal("unexpected oracle provenance/count")
	}
	return fixture.Cases
}
func TestPinnedCoreLookup(t *testing.T) {
	for _, c := range lookupCases(t) {
		t.Run(fmt.Sprintf("%d/%s/%s/%s", c.Width, c.Layout, c.Scenario, c.Order), func(t *testing.T) {
			table, err := symbols.Parse(c.ISF)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := kallsyms.FromSymbols(table, 0, c.Config.AddressMask)
			if err != nil || !reflect.DeepEqual(cfg, c.Config) {
				t.Fatal(cfg, c.Config, err)
			}
			core, err := kallsyms.Open(context.Background(), dataFor(t, c.coreCase), cfg, bounds())
			if err != nil {
				t.Fatal(err)
			}
			if c.Order == "after-stream" {
				if err := core.Stream(context.Background(), func(kallsyms.Symbol) error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			for n, want := range c.Expected {
				got, err := core.Lookup(context.Background(), want.Query)
				// The baseline reads a stale first entry despite a zero symbol count.
				// Native lookup refuses to present unindexed bytes as a valid symbol.
				masked := want.Query & cfg.AddressMask
				inside := cfg.TextStart <= masked && masked < cfg.TextEnd || cfg.HasInit && cfg.InitStart <= masked && masked < cfg.InitEnd
				if c.Scenario == "empty" && inside {
					if err == nil || got != nil {
						t.Fatalf("empty index query %#x accepted", want.Query)
					}
					continue
				}
				if want.Error != nil {
					if err == nil {
						t.Fatalf("query %d %#x: expected baseline %s, got %+v", n, want.Query, *want.Error, got)
					}
					continue
				}
				if err != nil {
					t.Fatalf("query %d %#x: %v", n, want.Query, err)
				}
				var row *coreRow
				if got != nil {
					row = &coreRow{Name: got.Name, Type: got.Type, Address: got.Address, Exported: got.Exported}
					if got.SizeAvailable {
						size := got.Size
						row.Size = &size
					}
				}
				if !reflect.DeepEqual(row, want.Result) {
					t.Fatalf("query %d %#x: got %+v want %+v", n, want.Query, row, want.Result)
				}
			}
		})
	}
}
func TestLookupFailures(t *testing.T) {
	c := lookupCases(t)[0]
	for _, fault := range []string{"no-text", "no-markers", "marker-width", "marker-hole", "marker-overflow", "names-overflow", "name-hole", "byte-limit"} {
		t.Run(fault, func(t *testing.T) {
			cfg := c.Config
			data := dataFor(t, c.coreCase)
			limits := bounds()
			switch fault {
			case "no-text":
				cfg.HasText = false
			case "no-markers":
				cfg.Markers = 0
			case "marker-width":
				cfg.MarkerSize = 2
			case "marker-hole":
				cfg.Markers = uint64(len(data))
			case "marker-overflow":
				cfg.Markers = ^uint64(0) - 1
			case "names-overflow":
				cfg.Names = ^uint64(0)
			case "name-hole":
				cfg.Names = uint64(len(data))
			case "byte-limit":
				limits.Bytes = uint64(c.Config.CountSize) + 3*uint64(c.Config.Width) + 512
			}
			core, err := kallsyms.Open(context.Background(), data, cfg, limits)
			if err == nil {
				_, err = core.Lookup(context.Background(), 0x8421)
			}
			if err == nil {
				t.Fatal("invalid lookup accepted")
			}
		})
	}
	core, err := kallsyms.Open(context.Background(), dataFor(t, c.coreCase), c.Config, bounds())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := core.Lookup(ctx, 0x8421); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Successful cached offsets must never bypass cancellation.
	if _, err := core.Lookup(context.Background(), 0x8421); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Lookup(ctx, 0x8421); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func FuzzCoreLookup(f *testing.F) {
	c := lookupCases(f)[0]
	original := dataFor(f, c.coreCase)
	f.Add([]byte{0}, uint8(0), uint64(0x8421))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, uint8(1), uint64(0x8500))
	f.Fuzz(func(t *testing.T, payload []byte, region uint8, address uint64) {
		if len(payload) > 512 {
			return
		}
		data := append(buffer(nil), original...)
		at := []int{0x16a00, 0x17000, 0x16800, 0x17400, 0x16100}[int(region)%5]
		copy(data[at:], payload)
		limits := bounds()
		limits.Bytes = 8192
		limits.NameBytes = 512
		limits.TokenBytes = 512
		core, err := kallsyms.Open(context.Background(), data, c.Config, limits)
		if err != nil {
			return
		}
		for _, query := range []uint64{address, 0x8400, 0x8421, 0x8500, address} {
			_, _ = core.Lookup(context.Background(), query)
		}
		if core.Stats().AcquiredBytes > limits.Bytes {
			t.Fatal("read budget exceeded")
		}
	})
}

func TestLookupBigEndianMarkers(t *testing.T) {
	c := lookupCases(t)[0]
	data := dataFor(t, c.coreCase)
	for _, region := range []struct{ at, count, width int }{{0x16000, 1, 4}, {0x16100, 3, 4}, {0x16800, 256, 2}, {0x16a00, 1, 4}} {
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
	got, err := core.Lookup(context.Background(), 0x8421)
	if err != nil || got == nil || got.Name != "worker" || got.Address != 0x8420 || got.Size != 0x20 {
		t.Fatal(got, err)
	}
}
