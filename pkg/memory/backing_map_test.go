package memory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func backingMapFixture(t testing.TB, mode string) (*Intel, *Virtual) {
	t.Helper()
	ram, _, _ := swappedFixture(t, mode, 0, -1)
	width, at, high := 8, 0x4000, uint(32)
	if mode == "x86" {
		width, at, high = 4, 0x2000, 12
	} else if mode == "pae" {
		at = 0x3000
	}
	values := []uint64{0x8003, uint64(2)<<high | 128, uint64(3)<<high | 128, uint64(4)<<high | 128 | 2, 0x9003}
	for n, v := range values {
		if width == 4 {
			binary.LittleEndian.PutUint32(ram[at+n*width:], uint32(v))
		} else {
			binary.LittleEndian.PutUint64(ram[at+n*width:], v)
		}
	}
	copy(ram[0x8000:], "RAM-A")
	copy(ram[0x9000:], "RAM-B")
	file0, file1 := make([]byte, 0x5000), make([]byte, 0x6000)
	copy(file0[0x2000:], "FILE-0-A")
	copy(file0[0x3000:], "FILE-0-B")
	copy(file1[0x4000:], "FILE-1")
	physical, err := WithPagefiles(raw(t, ram), map[uint8]MemoryLayer{0: raw(t, file0), 1: raw(t, file1)})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewIntelForOS(physical, 0x1000, mode, "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	return tr, &Virtual{Physical: physical, Translator: tr, ID: "mixed-space"}
}

func TestBackingMappingsSeparateSourcesAndReadOriginalBytes(t *testing.T) {
	for _, mode := range []string{"x64", "x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			tr, virtual := backingMapFixture(t, mode)
			var maps []BackingMapping
			stats, err := tr.VisitBackingMappings(context.Background(), BackingMapOptions{MaxTables: 100, MaxEntries: 10000}, func(m BackingMapping) error { maps = append(maps, m); return nil })
			if err != nil || stats.Mappings != 4 || stats.Unavailable != 0 || len(maps) != 4 {
				t.Fatal(stats, maps, err)
			}
			want := []struct {
				virtual, offset, length uint64
				file                    int
			}{{0, 0x8000, 4096, -1}, {0x1000, 0x2000, 8192, 0}, {0x3000, 0x4000, 4096, 1}, {0x4000, 0x9000, 4096, -1}}
			for n, m := range maps {
				gotFile := -1
				if m.Pagefile != nil {
					gotFile = int(*m.Pagefile)
				}
				if m.Virtual != want[n].virtual || m.Offset != want[n].offset || m.Length != want[n].length || gotFile != want[n].file {
					t.Fatal(n, m)
				}
				original, err := Read(context.Background(), m.Layer, m.Offset, int(m.Length))
				if err != nil {
					t.Fatal(err)
				}
				actual, err := Read(context.Background(), virtual, m.Virtual, int(m.Length))
				if err != nil || !bytes.Equal(original, actual) {
					t.Fatal("mapping disagrees with virtual bytes", n, err)
				}
			}
		})
	}
}

func TestBackingMappingsSectionsFaultsLimitsAndCancellation(t *testing.T) {
	ctx := context.Background()
	tr, _ := backingMapFixture(t, "x64")
	var maps []BackingMapping
	options := BackingMapOptions{MaxTables: 10, MaxEntries: 100, Sections: []Range{{Start: 0x1123, Length: 8}, {Start: 0x3123, Length: 8}}}
	stats, err := tr.VisitBackingMappings(ctx, options, func(m BackingMapping) error { maps = append(maps, m); return nil })
	if err != nil || stats.Mappings != 2 || maps[0].Offset != 0x2123 || maps[1].Offset != 0x4123 || maps[0].Length != 8 {
		t.Fatal(maps, stats, err)
	}
	for _, limit := range []string{"tables", "entries"} {
		o := BackingMapOptions{MaxTables: 10, MaxEntries: 10000}
		if limit == "tables" {
			o.MaxTables = 1
		} else {
			o.MaxEntries = 1
		}
		if _, err := tr.VisitBackingMappings(ctx, o, func(BackingMapping) error { return nil }); err == nil {
			t.Fatal("limit ignored", limit)
		}
	}
	sentinel := errors.New("stop backing maps")
	if _, err := tr.VisitBackingMappings(ctx, BackingMapOptions{MaxTables: 10, MaxEntries: 10000}, func(BackingMapping) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	count := 0
	_, err = tr.VisitBackingMappings(canceled, BackingMapOptions{MaxTables: 10, MaxEntries: 10000}, func(BackingMapping) error { count++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || count != 1 {
		t.Fatal(count, err)
	}
	// A missing configured file retains the preceding RAM run and fails.
	delete(tr.pagefiles, 0) // Test-only fault injection before traversal.
	count = 0
	stats, err = tr.VisitBackingMappings(ctx, BackingMapOptions{MaxTables: 10, MaxEntries: 10000}, func(BackingMapping) error { count++; return nil })
	if !errors.Is(err, ErrUnmapped) || stats.Unavailable != 1 || count != 1 {
		t.Fatal(count, stats, err)
	}
	faults := 0
	stats, err = tr.VisitBackingMappings(ctx, BackingMapOptions{MaxTables: 10, MaxEntries: 10000, OnUnavailableMapping: func(m BackingMapping, err error) error {
		faults++
		if m.Pagefile == nil || *m.Pagefile != 0 || !errors.Is(err, ErrUnmapped) {
			t.Fatal(m, err)
		}
		return nil
	}}, func(BackingMapping) error { return nil })
	if err != nil || stats.Unavailable != 2 || faults != 2 {
		t.Fatal(stats, faults, err)
	}
	// Table faults also fail unless an explicit callback retains them.
	broken, _ := NewIntelForOS(raw(t, make([]byte, 4096)), 0x1000, "x64", "windows", 4)
	if _, err := broken.VisitBackingMappings(ctx, options, func(BackingMapping) error { return nil }); err == nil {
		t.Fatal("missing root silently skipped")
	}
	options.OnReadError = func(at uint64, err error) error {
		if at != 0x1000 || err == nil {
			t.Fatal(at, err)
		}
		return nil
	}
	stats, err = broken.VisitBackingMappings(ctx, options, func(BackingMapping) error { t.Fatal("missing root emitted a map"); return nil })
	if err != nil || stats.Unavailable != 1 {
		t.Fatal(stats, err)
	}
}

func TestBackingMappingJSONKeepsAddressesLossless(t *testing.T) {
	number := uint8(15)
	data, err := json.Marshal(BackingMapping{Virtual: 0xffff800000001123, Offset: 0xfedcba9876543123, Length: 8, Pagefile: &number})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"virtual":"0xffff800000001123"`, `"offset":"0xfedcba9876543123"`, `"pagefile":15`, `"source":"pagefile"`} {
		if !strings.Contains(string(data), want) {
			t.Fatal(fmt.Sprintf("missing %s", want), string(data))
		}
	}
}

func TestBackingMappingsUnresolvedAndCanonicalBoundary(t *testing.T) {
	ctx := context.Background()
	ram, _, _ := swappedFixture(t, "x64", 0, -1)
	binary.LittleEndian.PutUint64(ram[0x4000:], uint64(7)<<32|1024)
	tr, _ := NewIntelForOS(raw(t, ram), 0x1000, "x64", "windows", 8)
	options := BackingMapOptions{MaxTables: 10, MaxEntries: 100, Sections: []Range{{Start: 0x123, Length: 8}}}
	if _, err := tr.VisitBackingMappings(ctx, options, func(BackingMapping) error { t.Fatal("unresolved entry emitted as readable"); return nil }); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	options.OnUnavailableMapping = func(m BackingMapping, err error) error {
		if !m.Unresolved || m.Layer != nil || m.Virtual != 0x123 || m.Length != 8 || !errors.Is(err, ErrUnsupported) {
			t.Fatal(m, err)
		}
		wire, _ := json.Marshal(m)
		if !strings.Contains(string(wire), `"source":"unresolved"`) || strings.Contains(string(wire), `"offset"`) {
			t.Fatal(string(wire))
		}
		return nil
	}
	stats, err := tr.VisitBackingMappings(ctx, options, func(BackingMapping) error { return nil })
	if err != nil || stats.Unavailable != 1 {
		t.Fatal(stats, err)
	}
	// Adjacent flat x64 coordinates straddle a noncanonical gap. Even
	// contiguous RAM frames must remain two distinct canonical runs.
	ram = make([]byte, 0x10000)
	put := func(at, value uint64) { binary.LittleEndian.PutUint64(ram[at:], value) }
	put(0x1000+255*8, 0x2003)
	put(0x2000+511*8, 0x3003)
	put(0x3000+511*8, 0x4003)
	put(0x4000+511*8, 0x8003)
	put(0x1000+256*8, 0x5003)
	put(0x5000, 0x6003)
	put(0x6000, 0x7003)
	put(0x7000, 0x9003)
	tr, _ = NewIntelForOS(raw(t, ram), 0x1000, "x64", "windows", 8)
	var maps []BackingMapping
	stats, err = tr.VisitBackingMappings(ctx, BackingMapOptions{MaxTables: 10, MaxEntries: 100, Sections: []Range{{Start: 0x7ffffffff000, Length: 4096}, {Start: 0xffff800000000000, Length: 4096}}}, func(m BackingMapping) error { maps = append(maps, m); return nil })
	if err != nil || stats.Mappings != 2 || len(maps) != 2 || maps[0].Virtual != 0x7ffffffff000 || maps[1].Virtual != 0xffff800000000000 || maps[0].Length != 4096 || maps[1].Length != 4096 {
		t.Fatal(stats, maps, err)
	}
}

func TestBackingMappingsInspectUniformLeafTables(t *testing.T) {
	ram, _, _ := swappedFixture(t, "x64", 0, -1)
	for n := 0; n < 512; n++ {
		binary.LittleEndian.PutUint64(ram[0x4000+n*8:], 0x8003)
	}
	tr, _ := NewIntelForOS(raw(t, ram), 0x1000, "x64", "windows", 8)
	count := 0
	stats, err := tr.VisitBackingMappings(context.Background(), BackingMapOptions{MaxTables: 10, MaxEntries: 10000}, func(m BackingMapping) error {
		if m.Virtual != uint64(count)*4096 || m.Offset != 0x8000 || m.Length != 4096 {
			t.Fatal(count, m)
		}
		count++
		return nil
	})
	if err != nil || count != 512 || stats.Mappings != 512 || stats.Unavailable != 0 {
		t.Fatal(count, stats, err)
	}
}
