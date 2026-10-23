package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type sockscanOracleCase struct {
	Width, Size int
	Scenario    string
	ISF         json.RawMessage
	Writes      [][]json.RawMessage
	Rows        [][]any
	NativeRows  [][]any `json:"native_rows"`
}

func socketScanCases(t testing.TB) []sockscanOracleCase {
	t.Helper()
	raw, err := os.ReadFile("../engine/testdata/linux-sockscan-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commit string
		Cases  []sockscanOracleCase
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 56 {
		t.Fatal("wrong socket oracle")
	}
	return fixture.Cases
}
func socketScanEnvironment(t testing.TB, c sockscanOracleCase, arch string) (plugin.Environment, flatMemory) {
	t.Helper()
	table, err := symbols.Parse(c.ISF)
	if err != nil {
		t.Fatal(err)
	}
	data := make(flatMemory, c.Size)
	for _, w := range c.Writes {
		var at int
		var text string
		if err = json.Unmarshal(w[0], &at); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(w[1], &text); err != nil {
			t.Fatal(err)
		}
		v, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[at:], v)
	}
	dtb := uint64(0x70000)
	if arch == "pae" {
		dtb = 0x75000
		binary.LittleEndian.PutUint64(data[0x75000:], 0x76001)
		binary.LittleEndian.PutUint64(data[0x76000:], 0x77003)
		for page := 0; page < 128; page++ {
			value := uint64(binary.LittleEndian.Uint32(data[0x73000+page*4:]))
			binary.LittleEndian.PutUint64(data[0x77000+page*8:], value)
		}
	}
	intel, err := memory.NewIntel(data, dtb, arch, 64)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
	return plugin.Environment{OS: "linux", Architecture: arch, Symbols: table, Physical: data, Kernel: kernel, Objects: &object.Reader{Layer: kernel, Symbols: table}}, data
}
func socketScanParameters(t testing.TB) map[string]string {
	t.Helper()
	p, err := plugin.Parameters(linuxSockscanPlugins()[0].spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestLinuxSockscanPinnedPhysicalAndNativeObjects(t *testing.T) {
	for _, c := range socketScanCases(t) {
		archs := []string{"x64"}
		if c.Width == 4 {
			archs = []string{"x86", "pae"}
		}
		for _, arch := range archs {
			profiles := []bool{false}
			if strings.HasPrefix(c.Scenario, "ipv6") {
				profiles = append(profiles, true)
			}
			for _, baseline := range profiles {
				t.Run(fmt.Sprintf("%s/%s/baseline=%t", arch, c.Scenario, baseline), func(t *testing.T) {
					e, data := socketScanEnvironment(t, c, arch)
					p := socketScanParameters(t)
					p["baseline-ipv6"] = strconv.FormatBool(baseline)
					expected := c.NativeRows
					if baseline {
						expected = c.Rows
					}
					var rows []evidence.Row
					reads := 0
					err := linuxSockscan(context.Background(), e, p, func(r evidence.Row) error {
						if r.Cells["RecordType"].String() == "socket_read" {
							reads++
							proof := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
							at, _ := proof["Address"].Uint()
							count, _ := proof["CapturedBytes"].Uint()
							layer := e.Kernel
							if r.Provenance.Layer == data.Name() {
								layer = e.Physical
							}
							actual, err := memory.Read(context.Background(), layer, at, int(count))
							if err != nil {
								t.Fatal(err)
							}
							if !bytes.Equal(actual, proof["Raw"].Data.([]byte)) {
								t.Fatal("acquisition differs from independent read")
							}
						}
						if r.Cells["RecordType"].String() == "socket" {
							rows = append(rows, r)
						}
						return nil
					})
					if c.Scenario == "missing-symbols" {
						if err == nil {
							t.Fatal("missing needles became empty success")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(rows) != len(expected) {
						t.Fatalf("%d native sockets != %d reference", len(rows), len(expected))
					}
					if len(expected) > 0 && reads == 0 {
						t.Fatal("no raw acquisitions")
					}
					keys := []string{"Offset", "Family", "Type", "Proto", "Source", "SourcePort", "Destination", "DestinationPort", "State", "Filter"}
					for i, want := range expected {
						for j, key := range keys {
							value := rows[i].Cells[key]
							if want[j] == nil {
								if value.Kind != "missing" || value.Error != "" {
									t.Fatalf("row%d %s unexpected %v", i, key, value)
								}
								continue
							}
							if j == 0 {
								v, err := value.Uint()
								if err != nil || v != uint64(want[j].(float64)) {
									t.Fatalf("row%d %s: %v != %v", i, key, value, want[j])
								}
							} else if value.String() != want[j].(string) {
								t.Fatalf("row%d %s: %q != %q", i, key, value.String(), want[j])
							}
						}
					}
				})
			}
		}

	}
}

type socketScanFaultLayer struct {
	memory.MemoryLayer
	at                          uint64
	length, occurrence, matches int
	injected                    bool
	short                       bool
}

func (l *socketScanFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if at == l.at && len(p) == l.length {
		l.matches++
		if !l.injected && l.matches == l.occurrence {
			l.injected = true
			if l.short {
				return 0, nil
			}
			n := len(p) / 2
			if n > 0 {
				if _, err := l.MemoryLayer.ReadAt(ctx, p[:n], at); err != nil {
					return 0, err
				}
			}
			return n, io.ErrUnexpectedEOF
		}
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func socketScanReplacePhysical(t testing.TB, e plugin.Environment, layer memory.MemoryLayer) plugin.Environment {
	t.Helper()
	intel, err := memory.NewIntel(layer, 0x70000, e.Architecture, 64)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: layer, Translator: intel, ID: "kernel"}
	e.Physical, e.Kernel = layer, kernel
	e.Objects = &object.Reader{Layer: kernel, Symbols: e.Symbols}
	return e
}
func socketScanControl(t testing.TB) sockscanOracleCase {
	t.Helper()
	for _, c := range socketScanCases(t) {
		if c.Width == 8 && c.Scenario == "normal" {
			return c
		}
	}
	t.Fatal("missing socket control")
	return sockscanOracleCase{}
}
func TestLinuxSockscanEveryReadFaultAndOutputBoundary(t *testing.T) {
	c := socketScanControl(t)
	e, _ := socketScanEnvironment(t, c, "x64")
	p := socketScanParameters(t)
	type request struct {
		at                 uint64
		length, occurrence int
	}
	var requests []request
	total := 0
	occurrences := map[string]int{}
	if err := linuxSockscan(context.Background(), e, p, func(r evidence.Row) error {
		total++
		if r.Cells["RecordType"].String() != "socket_read" {
			return nil
		}
		proof := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
		at, _ := proof["Address"].Uint()
		length, _ := proof["RequestedBytes"].Uint()
		if r.Provenance.Layer != e.Physical.Name() {
			translation, err := e.Kernel.(*memory.Virtual).Translator.Translate(context.Background(), at)
			if err != nil {
				t.Fatal(err)
			}
			at = translation.Physical
		}
		key := fmt.Sprintf("%x/%d", at, length)
		occurrences[key]++
		requests = append(requests, request{at, int(length), occurrences[key]})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for index, q := range requests {
		t.Run(fmt.Sprintf("read-%d", index), func(t *testing.T) {
			e, _ := socketScanEnvironment(t, c, "x64")
			fault := &socketScanFaultLayer{MemoryLayer: e.Physical, at: q.at, length: q.length, occurrence: q.occurrence}
			e = socketScanReplacePhysical(t, e, fault)
			captures := 0
			err := linuxSockscan(context.Background(), e, p, func(r evidence.Row) error {
				if r.Cells["RecordType"].String() == "socket_read" && r.Cells["Error"].Error != "" {
					captures++
					proof := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
					if proof["ReadComplete"].Data != false {
						t.Fatal("fault capture marked complete")
					}
				}
				return nil
			})
			if err == nil || !fault.injected || captures == 0 {
				t.Fatal("missing failed acquisition", err, fault.injected, captures)
			}
			// A failed attempt cannot poison an independent repeat over readable bytes.
			clean, _ := socketScanEnvironment(t, c, "x64")
			if err := linuxSockscan(context.Background(), clean, p, func(evidence.Row) error { return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, cancelOutput := range []bool{false, true} {
		for boundary := 1; boundary <= total; boundary++ {
			t.Run(fmt.Sprintf("output-%t-%d", cancelOutput, boundary), func(t *testing.T) {
				e, _ := socketScanEnvironment(t, c, "x64")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				stop := errors.New("stop at socket output")
				err := linuxSockscan(ctx, e, p, func(evidence.Row) error {
					calls++
					if calls == boundary {
						if cancelOutput {
							cancel()
							return nil
						}
						return stop
					}
					return nil
				})
				want := stop
				if cancelOutput {
					want = context.Canceled
				}
				if !errors.Is(err, want) || calls != boundary {
					t.Fatal(err, calls, boundary)
				}
			})
		}
	}
}
func TestLinuxSockscanLimitsAndInvalidLayouts(t *testing.T) {
	c := socketScanControl(t)
	for _, name := range []string{"max-candidates", "max-scan-bytes", "max-bytes", "max-nodes"} {
		for _, value := range []string{"0", "1000000000000000", "bad"} {
			e, _ := socketScanEnvironment(t, c, "x64")
			p := socketScanParameters(t)
			p[name] = value
			if err := linuxSockscan(context.Background(), e, p, func(evidence.Row) error { return nil }); err == nil {
				t.Fatal(name, value)
			}
		}
	}
	for _, p := range []map[string]string{{"max-candidates": "1"}, {"max-scan-bytes": "1"}, {"max-bytes": "1"}, {"baseline-ipv6": "bad"}} {
		e, _ := socketScanEnvironment(t, c, "x64")
		all := socketScanParameters(t)
		for k, v := range p {
			all[k] = v
		}
		rows := 0
		if err := linuxSockscan(context.Background(), e, all, func(evidence.Row) error { rows++; return nil }); err == nil {
			t.Fatal(p)
		}
		if rows > 20 {
			t.Fatal("limit did not stop acquisition", p, rows)
		}
	}
	for _, scenario := range []string{"missing-file-field", "bad-filter-field", "bad-unix-container", "bad-file-pointer", "bad-sock-pointer", "arm", "nil-physical", "nil-symbols", "nil-kernel"} {
		t.Run(scenario, func(t *testing.T) {
			e, _ := socketScanEnvironment(t, c, "x64")
			table := e.Symbols.(*symbols.ISF)
			switch scenario {
			case "missing-file-field":
				v := table.Types["file"]
				delete(v.Fields, "f_op")
				table.Types["file"] = v
			case "bad-filter-field":
				v := table.Types["sock"]
				f := v.Fields["sk_filter"]
				f.Offset = 10000
				v.Fields["sk_filter"] = f
				table.Types["sock"] = v
			case "bad-unix-container":
				v := table.Types["unix_sock"]
				f := v.Fields["sk"]
				f.Offset = 10000
				v.Fields["sk"] = f
				table.Types["unix_sock"] = v
			case "bad-file-pointer":
				v := table.Types["path"]
				f := v.Fields["dentry"]
				f.Type.Kind = "base"
				f.Type.Name = "u32"
				v.Fields["dentry"] = f
				table.Types["path"] = v
			case "bad-sock-pointer":
				v := table.Types["socket"]
				f := v.Fields["sk"]
				f.Type.Subtype = nil
				v.Fields["sk"] = f
				table.Types["socket"] = v
			case "arm":
				e.Architecture = "arm"
			case "nil-physical":
				e.Physical = nil
			case "nil-symbols":
				e.Symbols = nil
			case "nil-kernel":
				e.Kernel = nil
			}
			if err := linuxSockscan(context.Background(), e, socketScanParameters(t), func(evidence.Row) error { return nil }); err == nil {
				t.Fatal("invalid socket layout became success")
			}
		})
	}
	for _, short := range []bool{false, true} {
		e, _ := socketScanEnvironment(t, c, "x64")
		fault := &socketScanFaultLayer{MemoryLayer: e.Physical, at: 0, length: c.Size, occurrence: 1, short: short}
		e = socketScanReplacePhysical(t, e, fault)
		if err := linuxSockscan(context.Background(), e, socketScanParameters(t), func(evidence.Row) error { return nil }); err == nil || !fault.injected {
			t.Fatal("failed/zero-progress scan did not stop", err)
		}
	}
}

func FuzzLinuxSockscan(f *testing.F) {
	c := socketScanControl(f)
	original, _ := socketScanEnvironment(f, c, "x64")
	table := original.Symbols
	_, bytes := socketScanEnvironment(f, c, "x64")
	f.Add([]byte{0}, uint8(0))
	f.Add([]byte{0xff}, uint8(5))
	f.Add([]byte{0, 0, 0, 0}, uint8(7))
	p := socketScanParameters(f)
	p["max-candidates"] = "32"
	p["max-nodes"] = "8"
	p["max-bytes"] = "4096"
	f.Fuzz(func(t *testing.T, payload []byte, region uint8) {
		if len(payload) > 256 {
			return
		}
		data := append(flatMemory(nil), bytes...)
		at := []int{0x18000, 0x18040, 0x18058, 0x1a000, 0x1b000, 0x1c000, 0x1d000, 0x73000}[int(region)%8]
		copy(data[at:], payload)
		intel, err := memory.NewIntel(data, 0x70000, "x64", 8)
		if err != nil {
			t.Fatal(err)
		}
		layer := &memory.Virtual{Physical: data, Translator: intel, ID: "kernel"}
		e := plugin.Environment{OS: "linux", Architecture: "x64", Symbols: table, Physical: data, Kernel: layer, Objects: &object.Reader{Layer: layer, Symbols: table}}
		rows := 0
		_ = linuxSockscan(context.Background(), e, p, func(r evidence.Row) error {
			rows++
			if rows > 10000 {
				return errors.New("fuzz output bound")
			}
			if r.Cells["RecordType"].String() == "socket" && r.Cells["Error"].Error != "" {
				t.Fatal("failed candidate became socket")
			}
			return nil
		})
		if rows > 10001 {
			t.Fatal("unbounded socket output")
		}
	})
}

type socketScanRanges struct {
	memory.MemoryLayer
	ranges []memory.Range
}

func (l socketScanRanges) Ranges() []memory.Range { return l.ranges }
func TestLinuxSockscanPhysicalRangeBoundaries(t *testing.T) {
	c := socketScanControl(t)
	e, _ := socketScanEnvironment(t, c, "x64")
	value := uint64(0x1122334455667788)
	data := make(flatMemory, 16)
	binary.LittleEndian.PutUint64(data, value)
	for _, scenario := range []struct {
		name    string
		ranges  []memory.Range
		want    int
		failure bool
	}{
		{"adjacent", []memory.Range{{Length: 4}, {Start: 4, Length: 4}}, 1, false},
		{"hole", []memory.Range{{Length: 4}, {Start: 5, Length: 4}}, 0, false},
		{"overlap", []memory.Range{{Length: 8}, {Start: 4, Length: 4}}, 0, true},
		{"zero", []memory.Range{{Length: 0}}, 0, true},
		{"overflow", []memory.Range{{Start: ^uint64(0) - 3, Length: 8}}, 0, true},
		{"unknown-ranges", nil, 0, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s := &linuxSocketScan{ctx: context.Background(), e: e, out: func(evidence.Row) error { return nil }}
			hits := 0
			err := s.scan(socketScanRanges{MemoryLayer: data, ranges: scenario.ranges}, map[uint64]linuxSocketNeedle{value: {destruct: true}}, 1024, func(at, v uint64) error {
				hits++
				if at != 0 || v != value {
					t.Fatal(at, v)
				}
				return nil
			})
			if (err != nil) != scenario.failure || !scenario.failure && hits != scenario.want {
				t.Fatal(err, hits, scenario.want)
			}
		})
	}
}
