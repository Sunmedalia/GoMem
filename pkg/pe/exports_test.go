package pe

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
)

type exportOracleCase struct {
	Is64     bool     `json:"is64"`
	Scenario string   `json:"scenario"`
	Base     uint64   `json:"base"`
	Data     []byte   `json:"data"`
	Rows     []Export `json:"rows"`
	Lookups  []struct {
		Address uint64
		Name    *string
	} `json:"lookups"`
}

func exportCases(t testing.TB) []exportOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/exports-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Commit string
		Cases  []exportOracleCase
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(f.Cases) != 18 {
		t.Fatal("wrong PE export reference")
	}
	return f.Cases
}

func TestExportsPinnedPEFileAndExactSymbolLookup(t *testing.T) {
	for _, c := range exportCases(t) {
		t.Run(fmt.Sprintf("%t/%s", c.Is64, c.Scenario), func(t *testing.T) {
			before := append([]byte(nil), c.Data...)
			limits := DefaultExportLimits()
			var bytes uint64
			limits.Observe = func(r ExportRead) error {
				if r.Err != nil || len(r.Raw) != r.Requested || r.Address < c.Base {
					t.Fatal(r)
				}
				at := r.Address - c.Base
				if !reflect.DeepEqual(r.Raw, c.Data[at:at+uint64(len(r.Raw))]) {
					t.Fatal("acquisition differs from image")
				}
				bytes += uint64(len(r.Raw))
				return nil
			}
			table, err := ReadExports(context.Background(), testLayer{c.Base, c.Data}, c.Base, limits)
			if err != nil || !table.Complete || table.ReadBytes != bytes || !reflect.DeepEqual(before, c.Data) {
				t.Fatal(table, err)
			}
			if len(table.Entries) != len(c.Rows) {
				t.Fatal(table.Entries, c.Rows)
			}
			for i, e := range table.Entries {
				if !reflect.DeepEqual(e, c.Rows[i]) {
					t.Fatal(i, e, c.Rows[i])
				}
			}
			for _, lookup := range c.Lookups {
				name, ok := table.NameAt(lookup.Address)
				if lookup.Name == nil {
					if ok {
						t.Fatal(lookup, string(name))
					}
					continue
				}
				if !ok || string(name) != *lookup.Name {
					t.Fatal(lookup, string(name), ok)
				}
			}
			for _, e := range table.Entries {
				if e.Named {
					address, found := table.AddressForName(e.Name)
					if !found || address != e.Address {
						t.Fatal(e, address, found)
					}
				}
			}
			if _, found := table.AddressForName([]byte("absent")); found {
				t.Fatal("guessed symbol")
			}
		})
	}
}

type exportFaultLayer struct {
	testLayer
	fail, reads int
	invalid     bool
}

func (l *exportFaultLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.reads++
	if l.reads == l.fail {
		if l.invalid {
			return len(p) + 1, nil
		}
		n := len(p) / 2
		if n > 0 {
			_, _ = l.testLayer.ReadAt(ctx, p[:n], at)
		}
		return n, io.ErrUnexpectedEOF
	}
	return l.testLayer.ReadAt(ctx, p, at)
}

func TestExportsEveryAcquisitionFaultAndObserverCancellation(t *testing.T) {
	c := exportCases(t)[0]
	requests := 0
	limits := DefaultExportLimits()
	limits.Observe = func(r ExportRead) error { requests++; return nil }
	if _, err := ReadExports(context.Background(), testLayer{c.Base, c.Data}, c.Base, limits); err != nil {
		t.Fatal(err)
	}
	for boundary := 1; boundary <= requests; boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			layer := &exportFaultLayer{testLayer: testLayer{c.Base, c.Data}, fail: boundary}
			captures := 0
			limits.Observe = func(r ExportRead) error {
				if r.Err != nil {
					captures++
					if len(r.Raw) == r.Requested {
						t.Fatal("short read hidden")
					}
				}
				return nil
			}
			table, err := ReadExports(context.Background(), layer, c.Base, limits)
			if err == nil || table.Complete || captures != 1 || layer.reads != boundary {
				t.Fatal(table, err, captures, layer.reads, boundary)
			}
			for _, cancelled := range []bool{false, true} {
				ctx, cancel := context.WithCancel(context.Background())
				calls := 0
				stop := errors.New("observer stopped")
				limits.Observe = func(r ExportRead) error {
					calls++
					if calls == boundary {
						if cancelled {
							cancel()
						} else {
							return stop
						}
					}
					return nil
				}
				table, err := ReadExports(ctx, testLayer{c.Base, c.Data}, c.Base, limits)
				cancel()
				want := stop
				if cancelled {
					want = context.Canceled
				}
				if !errors.Is(err, want) || table.Complete || calls != boundary {
					t.Fatal(table, err, calls, boundary)
				}
			}
		})
	}
}

func TestExportsMalformedBoundsAndBudgets(t *testing.T) {
	c := exportCases(t)[0]
	for _, scenario := range []string{"directory-null", "directory-small", "directory-overflow", "optional-short", "name-count", "function-count", "eat-null", "name-null", "ordinal-null", "name-index", "name-rva", "target-rva", "name-unterminated", "forwarder-unterminated", "invalid-read-count", "bytes", "entries", "string", "nil-layer", "base-overflow"} {
		t.Run(scenario, func(t *testing.T) {
			data := append([]byte(nil), c.Data...)
			limits := DefaultExportLimits()
			base := c.Base
			put := func(at int, v uint32) { binary.LittleEndian.PutUint32(data[at:], v) }
			switch scenario {
			case "directory-null":
				put(0x98+96, 0)
			case "directory-small":
				put(0x98+100, 39)
			case "directory-overflow":
				put(0x98+100, 0xffffffff)
			case "optional-short":
				binary.LittleEndian.PutUint16(data[0x94:], 96)
			case "name-count":
				put(0x1618, 1000001)
			case "function-count":
				put(0x1614, 1000001)
			case "eat-null":
				put(0x161c, 0)
			case "name-null":
				put(0x1620, 0)
			case "ordinal-null":
				put(0x1624, 0)
			case "name-index":
				binary.LittleEndian.PutUint16(data[0x1660:], 4)
			case "name-rva":
				put(0x1650, 0x4000)
			case "target-rva":
				put(0x1640, 0x4000)
			case "name-unterminated":
				for i := 0x1a00; i < len(data); i++ {
					data[i] = 'X'
				}
			case "forwarder-unterminated":
				for i := 0x1700; i < 0x1800; i++ {
					data[i] = 'X'
				}
			case "bytes":
				limits.MaxBytes = 64
			case "entries":
				limits.MaxEntries = 2
			case "string":
				limits.MaxString = 3
			case "base-overflow":
				base = ^uint64(0) - 1
			}
			layer := &exportFaultLayer{testLayer: testLayer{base, data}}
			if scenario == "invalid-read-count" {
				layer.invalid = true
				layer.fail = 1
			}
			table, err := ReadExports(context.Background(), layer, base, limits)
			if scenario == "nil-layer" {
				table, err = ReadExports(context.Background(), nil, base, limits)
			}
			if err == nil || table.Complete {
				t.Fatal("invalid export accepted", table, err)
			}
			if table.ReadBytes > limits.MaxBytes {
				t.Fatal("acquisition budget exceeded")
			}
		})
	}
	for _, limits := range []ExportLimits{{}, {MaxEntries: 1000001, MaxBytes: 1, MaxString: 1}, {MaxEntries: 1, MaxBytes: 1<<30 + 1, MaxString: 1}, {MaxEntries: 1, MaxBytes: 1, MaxString: 65537}} {
		if _, err := ReadExports(context.Background(), testLayer{c.Base, c.Data}, c.Base, limits); err == nil {
			t.Fatal("invalid limits accepted")
		}
	}
}

func TestExportsPartialEntriesRemainExplicit(t *testing.T) {
	c := exportCases(t)[0]
	data := append([]byte(nil), c.Data...)
	binary.LittleEndian.PutUint32(data[0x1654:], 0x4000)
	table, err := ReadExports(context.Background(), testLayer{c.Base, data}, c.Base, DefaultExportLimits())
	if err == nil || table.Complete || len(table.Entries) != 1 || string(table.Entries[0].Name) != "Alpha" {
		t.Fatal(table, err)
	}
}

func FuzzMappedPEExports(f *testing.F) {
	for _, c := range exportCases(f) {
		f.Add(c.Data)
	}
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		limits := ExportLimits{MaxEntries: 64, MaxBytes: 65536, MaxString: 128}
		table, err := ReadExports(context.Background(), testLayer{0x400000, data}, 0x400000, limits)
		if table.ReadBytes > limits.MaxBytes || len(table.Entries) > int(limits.MaxEntries) {
			t.Fatal("unbounded export parsing")
		}
		if err != nil && table.Complete {
			t.Fatal("failed parse marked complete")
		}
		for _, e := range table.Entries {
			if e.RVA == 0 || uint64(e.RVA) >= table.ImageSize || e.Address != table.Base+uint64(e.RVA) || len(e.Name) > int(limits.MaxString) || len(e.Forwarder) > int(limits.MaxString) {
				t.Fatal(e)
			}
		}
	})
}

type exportUnrelatedHole struct{ testLayer }

func (l exportUnrelatedHole) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	for _, hole := range []uint64{l.base + 0x1200, l.base + 0x1a06} {
		if at <= hole && uint64(len(p)) > hole-at {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return l.testLayer.ReadAt(ctx, p, at)
}
func TestExportsDoNotReadFunctionBodiesOrPastStringNUL(t *testing.T) {
	c := exportCases(t)[0]
	table, err := ReadExports(context.Background(), exportUnrelatedHole{testLayer{c.Base, c.Data}}, c.Base, DefaultExportLimits())
	if err != nil || !table.Complete || len(table.Entries) != 4 {
		t.Fatal(table, err)
	}
	name, ok := table.NameAt(c.Base + 0x1200)
	if !ok || string(name) != "Alpha" {
		t.Fatal(string(name), ok)
	}
	name[0] = 'X'
	again, _ := table.NameAt(c.Base + 0x1200)
	if string(again) != "Alpha" {
		t.Fatal("caller mutated the index through lookup")
	}
}
