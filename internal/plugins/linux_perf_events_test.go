package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"os"
	"testing"
)

type perfTestFixture struct {
	table  *symbols.ISF
	data   flatMemory
	width  int
	layout string
}

func perfTestFixtures(t testing.TB) []perfTestFixture {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-perf-events-oracle.json")
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	var fixtures []perfTestFixture
	for _, c := range oracle.Cases {
		if c.Scenario != "normal" {
			continue
		}
		table, err := symbols.Parse(c.ISF)
		if err != nil {
			t.Fatal(err)
		}
		data := make(flatMemory, 0x20000)
		for _, w := range c.Writes {
			var at int
			var s string
			if err = json.Unmarshal(w[0], &at); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(w[1], &s); err != nil {
				t.Fatal(err)
			}
			b, err := hex.DecodeString(s)
			if err != nil {
				t.Fatal(err)
			}
			copy(data[at:], b)
		}
		fixtures = append(fixtures, perfTestFixture{table, data, c.Width, c.Layout})
	}
	if len(fixtures) != 4 {
		t.Fatal(len(fixtures))
	}
	return fixtures
}
func (f perfTestFixture) environment() plugin.Environment {
	arch := "x64"
	if f.width == 4 {
		arch = "x86"
	}
	return plugin.Environment{Kernel: f.data, Physical: f.data, Symbols: f.table, Objects: &object.Reader{Layer: f.data, Symbols: f.table}, Architecture: arch, OS: "linux"}
}
func perfTestParams() map[string]string {
	return map[string]string{"max-nodes": "8", "max-tasks": "8", "max-events": "8", "max-bytes": "16384"}
}

func TestLinuxPerfEventsEveryOutputBoundary(t *testing.T) {
	for _, f := range perfTestFixtures(t) {
		t.Run(fmt.Sprintf("%d/%s", f.width, f.layout), func(t *testing.T) {
			total := 0
			if err := linuxPerfEvents(context.Background(), f.environment(), perfTestParams(), func(evidence.Row) error { total++; return nil }); err != nil {
				t.Fatal(err)
			}
			for boundary := 1; boundary <= total; boundary++ {
				stop := errors.New("writer stopped")
				calls := 0
				err := linuxPerfEvents(context.Background(), f.environment(), perfTestParams(), func(evidence.Row) error {
					calls++
					if calls >= boundary {
						return stop
					}
					return nil
				})
				if !errors.Is(err, stop) || calls != boundary {
					t.Fatal(boundary, calls, err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				calls = 0
				err = linuxPerfEvents(ctx, f.environment(), perfTestParams(), func(evidence.Row) error {
					calls++
					if calls >= boundary {
						cancel()
					}
					return nil
				})
				cancel()
				if calls != boundary || boundary < total && !errors.Is(err, context.Canceled) {
					t.Fatal(boundary, calls, err)
				}
			}
		})
	}
}
func TestLinuxPerfEventsMalformedListsAndLimits(t *testing.T) {
	for _, seed := range perfTestFixtures(t) {
		for _, fault := range []string{"pmu-hole", "aux-hole", "task-cycle", "event-cycle", "thread-owner", "byte-bound", "task-bound", "event-bound", "bad-limit", "scalar-pointer"} {
			t.Run(fmt.Sprintf("%d/%s/%s", seed.width, seed.layout, fault), func(t *testing.T) {
				f := seed
				f.data = append(flatMemory(nil), f.data...)
				p := perfTestParams()
				put := func(at, value uint64) {
					if f.width == 4 {
						binary.LittleEndian.PutUint32(f.data[at:], uint32(value))
					} else {
						binary.LittleEndian.PutUint64(f.data[at:], value)
					}
				}
				switch fault {
				case "pmu-hole":
					put(0x13000+24, 0x300000)
				case "aux-hole":
					put(0x15000, 0x300000)
				case "task-cycle":
					put(0x12400, 0x12000)
				case "event-cycle":
					put(0x13100, 0x13000)
				case "thread-owner":
					binary.LittleEndian.PutUint32(f.data[0x12200+20:], 99)
				case "byte-bound":
					p["max-bytes"] = "1"
				case "task-bound":
					p["max-tasks"] = "1"
				case "event-bound":
					p["max-events"] = "1"
				case "bad-limit":
					p["max-events"] = "1000001"
				case "scalar-pointer":
					raw, err := f.table.Encode()
					if err != nil {
						t.Fatal(err)
					}
					f.table, err = symbols.Parse(raw)
					if err != nil {
						t.Fatal(err)
					}
					typ := f.table.Types["perf_event"]
					field := typ.Fields["pmu"]
					field.Type = symbols.TypeRef{Kind: "base", Name: "u32"}
					typ.Fields["pmu"] = field
					f.table.Types["perf_event"] = typ
				}
				selected := 0
				err := linuxPerfEvents(context.Background(), f.environment(), p, func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "perf_event" {
						selected++
					}
					if row.Cells["RecordType"].String() == "event_summary" && row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data != false {
						t.Fatal("false complete inventory")
					}
					return nil
				})
				if err == nil {
					t.Fatal("accepted incomplete input")
				}
				if (fault == "pmu-hole" || fault == "aux-hole") && selected != 2 {
					t.Fatal("discarded independent events", selected)
				}
			})
		}
	}
}
func FuzzLinuxPerfEvents(f *testing.F) {
	fixtures := perfTestFixtures(f)
	for i := range fixtures {
		f.Add(uint8(i), uint16(0x3000), []byte{0, 0, 0, 0, 0, 0, 0, 0})
	}
	f.Fuzz(func(t *testing.T, which uint8, offset uint16, mutation []byte) {
		seed := fixtures[int(which)%len(fixtures)]
		seed.data = append(flatMemory(nil), seed.data...)
		if len(mutation) > 256 {
			mutation = mutation[:256]
		}
		at := 0x10000 + int(offset)%0x7000
		copy(seed.data[at:], mutation)
		calls := 0
		_ = linuxPerfEvents(context.Background(), seed.environment(), perfTestParams(), func(row evidence.Row) error {
			calls++
			if calls > 2000 {
				t.Fatal("unbounded output")
			}
			if row.Cells["RecordType"].String() == "event_read" {
				proof := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
				at, _ := proof["Address"].Uint()
				raw := proof["Raw"].Data.([]byte)
				if len(raw) > 0 && (at > uint64(len(seed.data)) || uint64(len(raw)) > uint64(len(seed.data))-at || string(raw) != string(seed.data[at:at+uint64(len(raw))])) {
					t.Fatal("invalid raw capture")
				}
			}
			return nil
		})
	})
}
