package memory

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
	"strings"
	"testing"
)

type qemuOracleCase struct {
	QEMUReference struct {
		Reads []struct{ Address, SHA256 string }
	} `json:"qemu_reference"`
	Name     string
	Raw      []byte
	SHA256   string
	Expected []struct {
		Address      string
		Offset, Size uint64
		Fill         bool
		SHA256       string
	}
	Upstream struct {
		Error string
		Reads []struct{ Address, SHA256 string }
	}
}

func qemuOracle(t testing.TB) []qemuOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/qemu-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Baseline string `json:"baseline_commit"`
		QEMUHash string `json:"qemu_analyzer_sha256"`
		Cases    []qemuOracleCase
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 20 || fixture.QEMUHash != "5d92df832acebee546695648f378dde7b303798effaaea17048ec6dd2f33a7c9" {
		t.Fatal("oracle drift")
	}
	return fixture.Cases
}
func TestQEMUActualBaselineAndPageReads(t *testing.T) {
	for _, test := range qemuOracle(t) {
		t.Run(test.Name, func(t *testing.T) {
			sum := sha256.Sum256(test.Raw)
			if hex.EncodeToString(sum[:]) != test.SHA256 {
				t.Fatal("fixture digest")
			}
			layer, format, err := Detect(context.Background(), bufferSource(test.Raw))
			if err != nil || format != "qemu" {
				t.Fatal(format, err)
			}
			header := layer.(*QEMULayer).QEMUHeader()
			if header.Version != 3 || header.Pages != 2 {
				t.Fatal(header)
			}
			updated := test.Name == "updated-raw" || test.Name == "updated-fill"
			device := strings.HasPrefix(test.Name, "device-")
			if updated {
				if header.Updates != 1 || test.Upstream.Error != "InvalidAddressException" {
					t.Fatal("upstream update behavior drift", header, test.Upstream)
				}
			} else if device {
				if test.Upstream.Error != "LayerException" {
					t.Fatal("fixed device behavior changed", test.Upstream)
				}
			} else if test.Upstream.Error != "" || header.Updates != 0 {
				t.Fatal(test.Upstream, header)
			}
			for _, expected := range test.Expected {
				foundQEMU := false
				for _, reference := range test.QEMUReference.Reads {
					if reference.Address == expected.Address && reference.SHA256 == expected.SHA256 {
						foundQEMU = true
					}
				}
				if !foundQEMU {
					t.Fatal("actual QEMU analyzer bytes differ")
				}

				address, err := strconv.ParseUint(expected.Address, 0, 64)
				if err != nil {
					t.Fatal(err)
				}
				data, err := Read(context.Background(), layer, address, int(expected.Size))
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(data)
				if hex.EncodeToString(sum[:]) != expected.SHA256 {
					t.Fatal("physical bytes differ")
				}
				if !updated && !device {
					found := false
					for _, r := range test.Upstream.Reads {
						if r.Address == expected.Address && r.SHA256 == expected.SHA256 {
							found = true
						}
					}
					if !found {
						t.Fatal("upstream page mismatch")
					}
				}
				for _, offset := range []uint64{0, 1, expected.Size - 1} {
					data, err := Read(context.Background(), layer, address+offset, 1)
					if err != nil {
						t.Fatal(err)
					}
					want := test.Raw[expected.Offset]
					if !expected.Fill {
						want = test.Raw[expected.Offset+offset]
					}
					if data[0] != want {
						t.Fatal("partial decoded read differs")
					}
				}
			}
			address, _ := strconv.ParseUint(test.Expected[0].Address, 0, 64)
			cross, err := Read(context.Background(), layer, address+header.PageSize-1, 2)
			if err != nil || cross[1] != 'B' {
				t.Fatal("cross-page read", cross, err)
			}
			if _, err := Read(context.Background(), layer, address+2*header.PageSize, 1); !errors.Is(err, ErrUnmapped) {
				t.Fatal("invented missing page", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := Read(ctx, layer, address, 1); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
func qemuFooterJSON(t testing.TB, raw []byte, payload string) []byte {
	t.Helper()
	offset := bytes.LastIndex(raw, []byte(`{"page_size"`)) - 5
	if offset < 0 {
		t.Fatal("description missing")
	}
	out := bytes.Clone(raw[:offset])
	out = append(out, 6, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[offset+1:], uint32(len(payload)))
	return append(out, []byte(payload)...)
}
func TestQEMURejectsMalformedMigration(t *testing.T) {
	raw := qemuOracle(t)[0].Raw
	for _, name := range []string{"version", "bad-footer", "unknown-part", "unknown-device", "unknown-ram-version", "bad-page-flags", "continue-first", "missing-eof", "bad-json", "bad-page-size", "zero-block", "large-block", "page-outside-block", "fake-description"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(raw)
			ram := bytes.Index(data, []byte("ram"))
			record := ram + 3 + 8
			switch name {
			case "version":
				data[7] = 4
			case "bad-footer":
				at := bytes.Index(data, []byte{0x7e, 0, 0, 0, 1})
				data[at+4] = 9
			case "unknown-part":
				at := bytes.Index(data, []byte{4, 0, 0, 0, 2, 3, 'r', 'a', 'm'})
				data[at] = 2
			case "unknown-device":
				copy(data[ram:], "xyz")
			case "unknown-ram-version":
				data[record-1] = 3
			case "bad-page-flags":
				data[record+7] = 0x40
			case "continue-first":
				at := bytes.Index(data, []byte{6, 'p', 'c', '.', 'r', 'a', 'm'})
				at += 1 + bytes.Index(data[at+1:], []byte{6, 'p', 'c', '.', 'r', 'a', 'm'})
				data[at-1] |= 32
			case "missing-eof":
				at := bytes.LastIndex(data, []byte(`{"page_size"`)) - 6
				data[at] = 5
			case "bad-json":
				data = qemuFooterJSON(t, data, `{"page_size":`)
			case "bad-page-size":
				data = qemuFooterJSON(t, data, `{"page_size":4095}`)
			case "zero-block":
				at := bytes.Index(data, []byte("pc.ram"))
				clear(data[at+6 : at+14])
			case "large-block":
				at := bytes.Index(data, []byte("pc.ram"))
				binary.BigEndian.PutUint64(data[at+6:], 1<<50)
			case "page-outside-block":
				at := bytes.Index(data, []byte{6, 'p', 'c', '.', 'r', 'a', 'm'})
				at += 1 + bytes.Index(data[at+1:], []byte{6, 'p', 'c', '.', 'r', 'a', 'm'})
				binary.BigEndian.PutUint64(data[at-8:], 0x3008)
			case "fake-description":
				at := bytes.LastIndex(data, []byte(`{"page_size"`)) - 5
				data = append(bytes.Clone(data[:at]), append([]byte{0}, data[at:]...)...)
			}
			if _, _, err := Detect(context.Background(), bufferSource(data)); err == nil {
				t.Fatal("invalid stream accepted")
			}
		})
	}
	for end := 0; end < len(raw); end += 127 {
		if _, _, err := Detect(context.Background(), bufferSource(raw[:end])); err == nil {
			t.Fatalf("truncated stream accepted at %d", end)
		}
	}
}
func FuzzQEMUSuspend(f *testing.F) {
	for _, test := range qemuOracle(f) {
		f.Add(test.Raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2<<20 {
			t.Skip()
		}
		layer, err := qemuImage(context.Background(), bufferSource(raw))
		if err != nil {
			return
		}
		var end uint64
		for _, r := range layer.Ranges() {
			if r.Length == 0 || r.Start < end {
				t.Fatal("invalid page index")
			}
			var err error
			end, err = Add(r.Start, r.Length)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Read(context.Background(), layer, r.Start, 1); err != nil {
				t.Fatal("accepted unreadable page", err)
			}
		}
	})
}

func TestQEMUDeviceDescriptionsMustMatchPayload(t *testing.T) {
	var raw []byte
	for _, test := range qemuOracle(t) {
		if test.Name == "device-subsection" {
			raw = test.Raw
		}
	}
	if len(raw) == 0 {
		t.Fatal("device control absent")
	}
	for _, name := range []string{"version", "instance", "missing-fields", "oversized-field", "oversized-array", "unknown-subsection", "subsection-version", "duplicate-description", "deep-struct"} {
		t.Run(name, func(t *testing.T) {
			at := bytes.LastIndex(raw, []byte(`{"page_size"`))
			var description map[string]any
			if err := json.Unmarshal(raw[at:], &description); err != nil {
				t.Fatal(err)
			}
			devices := description["devices"].([]any)
			cpu := devices[1].(map[string]any)
			switch name {
			case "version":
				cpu["version"] = 9
			case "instance":
				cpu["instance_id"] = 9
			case "missing-fields":
				delete(cpu, "fields")
			case "oversized-field":
				cpu["fields"] = []any{map[string]any{"type": "buffer", "size": 1 << 40}}
			case "oversized-array":
				cpu["fields"] = []any{map[string]any{"type": "uint8", "size": 0, "array_len": 1 << 30}}
			case "unknown-subsection":
				cpu["subsections"].([]any)[0].(map[string]any)["vmsd_name"] = "wrong-name"
			case "subsection-version":
				cpu["subsections"].([]any)[0].(map[string]any)["version"] = 8
			case "duplicate-description":
				description["devices"] = append(devices, cpu)
			case "deep-struct":
				var nested any = map[string]any{"fields": []any{map[string]any{"type": "buffer", "size": 4}}}
				for i := 0; i < 66; i++ {
					nested = map[string]any{"fields": []any{map[string]any{"type": "struct", "struct": nested}}}
				}
				cpu["fields"] = []any{map[string]any{"type": "struct", "struct": nested}}
			}
			encoded, err := json.Marshal(description)
			if err != nil {
				t.Fatal(err)
			}
			data := qemuFooterJSON(t, raw, string(encoded))
			if _, _, err := Detect(context.Background(), bufferSource(data)); err == nil {
				t.Fatal("mismatched device description accepted")
			}
		})
	}
}

func TestQEMUHTABAndDirtyBitmapBoundaries(t *testing.T) {
	raw := qemuOracle(t)[0].Raw
	at := bytes.Index(raw, []byte{4, 0, 0, 0, 2, 3, 'r', 'a', 'm'})
	if at < 0 {
		t.Fatal("RAM section absent")
	}
	for _, test := range []struct {
		name    string
		version uint32
		payload []byte
		fail    bool
	}{
		{"spapr/htab", 1, []byte{0, 0, 0, 18}, false},
		{"spapr/htab", 1, make([]byte, 12), false},
		{"spapr/htab", 1, append(append([]byte{0, 0, 0, 0, 0, 0, 0, 8, 0, 1, 0, 2}, bytes.Repeat([]byte{0x55}, 16)...), make([]byte, 8)...), false},
		{"spapr/htab", 2, []byte{0, 0, 0, 18}, true},
		{"dirty-bitmap", 1, []byte{0}, false},
	} {
		var prefix bytes.Buffer
		prefix.Write([]byte{4, 0, 0, 0, 9, byte(len(test.name))})
		prefix.WriteString(test.name)
		prefix.Write(make([]byte, 4))
		binary.Write(&prefix, binary.BigEndian, test.version)
		prefix.Write(test.payload)
		prefix.Write([]byte{0x7e, 0, 0, 0, 9})
		data := append(bytes.Clone(raw[:at]), prefix.Bytes()...)
		data = append(data, raw[at:]...)
		layer, _, err := Detect(context.Background(), bufferSource(data))
		if test.fail {
			if err == nil {
				t.Fatal("unsupported HTAB version accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(test.name, err)
		}
		page, err := Read(context.Background(), layer, 0, 4096)
		if err != nil || !bytes.Equal(page, bytes.Repeat([]byte{'A'}, 4096)) {
			t.Fatal("auxiliary section shifted RAM", err)
		}
	}
}

type qemuFaultSource struct {
	MemorySource
	fail  bool
	short bool
}

func (s *qemuFaultSource) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if s.fail {
		return 0, errors.New("injected QEMU source failure")
	}
	if s.short {
		return 0, nil
	}
	return s.MemorySource.ReadAt(ctx, p, at)
}
func TestQEMUSourceErrorsAndReadBounds(t *testing.T) {
	for _, test := range qemuOracle(t)[:2] {
		source := &qemuFaultSource{MemorySource: bufferSource(test.Raw)}
		layer, err := qemuImage(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		source.fail = true
		if _, err := Read(context.Background(), layer, 0, 1); err == nil {
			t.Fatal("source error lost")
		}
		if _, err := qemuImage(context.Background(), source); err == nil {
			t.Fatal("assembly source error lost")
		}
		source.fail = false
		source.short = true
		if _, err := Read(context.Background(), layer, 0, 1); err == nil {
			t.Fatal("short page read accepted")
		}
		if _, err := qemuImage(context.Background(), source); err == nil {
			t.Fatal("short metadata read accepted")
		}
		source.short = false
		if _, err := layer.ReadAt(context.Background(), make([]byte, MaxRead+1), 0); err == nil {
			t.Fatal("unbounded read")
		}
		if _, err := layer.ReadAt(context.Background(), make([]byte, 2), ^uint64(0)); err == nil {
			t.Fatal("overflow read")
		}
	}
}
