package plugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type pidTestFixture struct {
	table *symbols.ISF
	data  flatMemory
	width int
}

// Seed real PID/hash and namespace IDR layouts from the independently executed
// pinned oracle. Mutate both index pointers and task metadata under small bounds.
func pidTestFixtures(f testing.TB) []pidTestFixture {
	f.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-pidhashtable-oracle.json")
	if err != nil {
		f.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Width            int
			Layout, Scenario string
			ISF              json.RawMessage
			Writes           [][]json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		f.Fatal(err)
	}
	var fixtures []pidTestFixture
	for _, c := range oracle.Cases {
		if c.Scenario != "normal" || c.Layout != "legacy" && c.Layout != "xarray" {
			continue
		}
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			f.Fatal(err)
		}
		data := make(flatMemory, 0x20000)
		for _, w := range c.Writes {
			var at int
			var s string
			if err = json.Unmarshal(w[0], &at); err != nil {
				f.Fatal(err)
			}
			if err = json.Unmarshal(w[1], &s); err != nil {
				f.Fatal(err)
			}
			b, err := hex.DecodeString(s)
			if err != nil {
				f.Fatal(err)
			}
			copy(data[at:], b)
		}
		fixtures = append(fixtures, pidTestFixture{table, data, c.Width})
	}
	if len(fixtures) != 4 {
		f.Fatal(len(fixtures))
	}
	return fixtures
}

func FuzzLinuxPIDHash(f *testing.F) {
	fixtures := pidTestFixtures(f)
	for i := range fixtures {
		f.Add(uint8(i), uint16(0x1000), []byte{0, 0, 0, 0, 0, 0, 0, 0})
	}
	f.Fuzz(func(t *testing.T, which uint8, offset uint16, mutation []byte) {
		seed := fixtures[int(which)%len(fixtures)]
		data := append(flatMemory(nil), seed.data...)
		if len(mutation) > 256 {
			mutation = mutation[:256]
		}
		at := 0x10000 + int(offset)%0x5000
		copy(data[at:], mutation)
		arch := "x64"
		if seed.width == 4 {
			arch = "x86"
		}
		e := plugin.Environment{Kernel: data, Physical: data, Symbols: seed.table, Objects: &object.Reader{Layer: data, Symbols: seed.table}, Architecture: arch, OS: "linux"}
		calls := 0
		_ = linuxPIDHash(context.Background(), e, map[string]string{"max-nodes": "8", "max-tasks": "8", "max-buckets": "8", "decorate-comm": "true"}, func(row evidence.Row) error {
			calls++
			if calls > 2000 {
				t.Fatal("unbounded evidence")
			}
			if row.Cells["RecordType"].String() == "index_read" {
				fields := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
				at, _ := fields["Address"].Uint()
				b := fields["Raw"].Data.([]byte)
				if len(b) > 0 && (at > uint64(len(data)) || uint64(len(b)) > uint64(len(data))-at || string(b) != string(data[at:at+uint64(len(b))])) {
					t.Fatal("invalid raw capture")
				}
			}
			return nil
		})
	})
}

// Exercise failures at each output boundary, including reads made while a
// candidate is being parsed, without engine-level emitter suppression.
func TestLinuxPIDHashStopsAtEveryOutputBoundary(t *testing.T) {
	for _, seed := range pidTestFixtures(t) {
		arch := "x64"
		if seed.width == 4 {
			arch = "x86"
		}
		e := plugin.Environment{Kernel: seed.data, Physical: seed.data, Symbols: seed.table, Objects: &object.Reader{Layer: seed.data, Symbols: seed.table}, Architecture: arch, OS: "linux"}
		params := map[string]string{"max-nodes": "8", "max-tasks": "8", "max-buckets": "8", "decorate-comm": "true"}
		total := 0
		if err := linuxPIDHash(context.Background(), e, params, func(evidence.Row) error { total++; return nil }); err != nil {
			t.Fatal(err)
		}
		for boundary := 1; boundary <= total; boundary++ {
			stop := errors.New("writer closed")
			calls := 0
			err := linuxPIDHash(context.Background(), e, params, func(evidence.Row) error {
				calls++
				if calls >= boundary {
					return stop
				}
				return nil
			})
			if !errors.Is(err, stop) || calls != boundary {
				t.Fatal("output failure", boundary, calls, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			calls = 0
			err = linuxPIDHash(ctx, e, params, func(evidence.Row) error {
				calls++
				if calls >= boundary {
					cancel()
				}
				return nil
			})
			cancel()
			// Cancellation on the final summary needs no additional output. Earlier
			// boundaries must return cancellation and never call the sink again.
			if calls != boundary || boundary < total && !errors.Is(err, context.Canceled) {
				t.Fatal("cancel", boundary, calls, err)
			}
		}
	}
}
