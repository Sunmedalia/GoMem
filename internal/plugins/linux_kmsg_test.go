package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type kmsgTestFixture struct {
	table  *symbols.ISF
	data   flatMemory
	width  int
	layout string
}

func kmsgTestFixtures(t testing.TB) []kmsgTestFixture {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-kmsg-oracle.json")
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
	var fixtures []kmsgTestFixture
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
		fixtures = append(fixtures, kmsgTestFixture{table, data, c.Width, c.Layout})
	}
	if len(fixtures) != 8 {
		t.Fatal(len(fixtures))
	}
	return fixtures
}
func (f kmsgTestFixture) environment() plugin.Environment {
	arch := "x64"
	if f.width == 4 {
		arch = "x86"
	}
	return plugin.Environment{Kernel: f.data, Physical: f.data, Symbols: f.table, Objects: &object.Reader{Layer: f.data, Symbols: f.table}, Architecture: arch, OS: "linux"}
}
func kmsgTestParams() map[string]string {
	return map[string]string{"max-records": "8", "max-lines": "64", "max-bytes": "16384"}
}
func TestLinuxKmsgEveryOutputBoundary(t *testing.T) {
	for _, f := range kmsgTestFixtures(t) {
		t.Run(fmt.Sprintf("%d/%s", f.width, f.layout), func(t *testing.T) {
			e := f.environment()
			total := 0
			if err := linuxKmsg(context.Background(), e, kmsgTestParams(), func(evidence.Row) error { total++; return nil }); err != nil {
				t.Fatal(err)
			}
			for boundary := 1; boundary <= total; boundary++ {
				stop := errors.New("writer closed")
				calls := 0
				err := linuxKmsg(context.Background(), e, kmsgTestParams(), func(evidence.Row) error {
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
				err = linuxKmsg(ctx, e, kmsgTestParams(), func(evidence.Row) error {
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
func TestLinuxKmsgMalformedRingsAndLimits(t *testing.T) {
	for _, f := range kmsgTestFixtures(t) {
		for _, fault := range []string{"hole", "cycle", "byte-bound", "line-bound", "record-bound", "bad-parameter"} {
			t.Run(fmt.Sprintf("%d/%s/%s", f.width, f.layout, fault), func(t *testing.T) {
				f := f
				f.data = append(flatMemory(nil), f.data...)
				p := kmsgTestParams()
				put := func(at, value uint64) {
					if f.width == 4 {
						binary.LittleEndian.PutUint32(f.data[at:], uint32(value))
					} else {
						binary.LittleEndian.PutUint64(f.data[at:], value)
					}
				}
				switch fault {
				case "hole":
					put(0x10000, 0x300000)
				case "cycle":
					switch f.layout {
					case "modern":
						put(0x11018, 0)
					case "text":
						binary.LittleEndian.PutUint32(f.data[0x10008:], 0)
					default:
						binary.LittleEndian.PutUint16(f.data[0x11008:], 0)
					}
				case "byte-bound":
					p["max-bytes"] = "1"
				case "line-bound":
					p["max-lines"] = "1"
				case "record-bound":
					p["max-records"] = "1"
				case "bad-parameter":
					p["max-records"] = "1000001"
				}
				// A contiguous structured ring has exactly one record; use a zero record
				// bound (invalid parameter) to exercise this layout's record limit gate.
				if fault == "record-bound" && (f.layout == "log" || f.layout == "printk_log") {
					p["max-records"] = "0"
				}
				err := linuxKmsg(context.Background(), f.environment(), p, func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "ring_summary" && row.Cells["Coverage"].Data.(map[string]evidence.Value)["Completed"].Data != false {
						t.Fatal("false completion")
					}
					return nil
				})
				if err == nil {
					t.Fatal("accepted malformed/incomplete ring")
				}
			})
		}
	}
}
func TestLinuxKmsgProducerGate(t *testing.T) {
	f := kmsgTestFixtures(t)[0]
	for _, c := range []struct {
		version string
		fail    bool
	}{{"0.4.0", true}, {"0.4.1", true}, {"0.4", true}, {"0.4.1.0", false}, {"0.4.2", false}, {"1.0.0", false}, {"", false}, {"development", false}} {
		f.table.Meta["producer"] = json.RawMessage(fmt.Sprintf(`{"name":"dwarf2json","version":%q}`, c.version))
		if err := kmsgCheckProducer(f.environment()); (err != nil) != c.fail {
			t.Fatal(c, err)
		}
	}
}
func FuzzLinuxKmsgRings(f *testing.F) {
	fixtures := kmsgTestFixtures(f)
	for i := range fixtures {
		f.Add(uint8(i), uint16(0x1000), []byte{0, 0, 0, 0, 0, 0, 0, 0})
	}
	f.Fuzz(func(t *testing.T, which uint8, offset uint16, mutation []byte) {
		seed := fixtures[int(which)%len(fixtures)]
		seed.data = append(flatMemory(nil), seed.data...)
		if len(mutation) > 256 {
			mutation = mutation[:256]
		}
		at := 0x10000 + int(offset)%0x5000
		copy(seed.data[at:], mutation)
		calls := 0
		_ = linuxKmsg(context.Background(), seed.environment(), kmsgTestParams(), func(row evidence.Row) error {
			calls++
			if calls > 2000 {
				t.Fatal("unbounded output")
			}
			if row.Cells["RecordType"].String() == "ring_read" {
				proof := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
				at, _ := proof["Address"].Uint()
				raw := proof["Raw"].Data.([]byte)
				if len(raw) > 0 && (at > uint64(len(seed.data)) || uint64(len(raw)) > uint64(len(seed.data))-at || string(raw) != string(seed.data[at:at+uint64(len(raw))])) {
					t.Fatal("invalid capture")
				}
			}
			return nil
		})
	})
}

func TestLinuxKmsgRejectsScalarRingPointers(t *testing.T) {
	for _, f := range kmsgTestFixtures(t) {
		name := "log_buf"
		if f.layout == "modern" {
			name = "prb"
		}
		sym := f.table.Symbols[name]
		sym.Type = &symbols.TypeRef{Kind: "base", Name: "ulong"}
		f.table.Symbols[name] = sym
		if err := linuxKmsg(context.Background(), f.environment(), kmsgTestParams(), func(evidence.Row) error { return nil }); err == nil {
			t.Fatal(f.layout, "accepted scalar ring pointer")
		}
	}
}
