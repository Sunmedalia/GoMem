package memory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestPageMapSelectedSectionsAgainstActualIntel(t *testing.T) {
	rawJSON, err := os.ReadFile("../../internal/engine/testdata/regex-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		VMAs []struct {
			Name, Arch string
			Size       int
			Writes     []struct {
				Offset int
				Data   string
			}
			Sections [][2]uint64
			Mappings [][4]uint64
		}
	}
	if err = json.Unmarshal(rawJSON, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.VMAs) != 42 {
		t.Fatal("reference fixture drift")
	}
	for _, c := range fixture.VMAs {
		t.Run(c.Arch+"/"+c.Name, func(t *testing.T) {
			data := make([]byte, c.Size)
			for _, w := range c.Writes {
				v, err := hex.DecodeString(w.Data)
				if err != nil {
					t.Fatal(err)
				}
				copy(data[w.Offset:], v)
			}
			intel, err := NewIntelForOS(raw(t, data), 0x8000, c.Arch, "linux", 1)
			if err != nil {
				t.Fatal(err)
			}
			sections := []Range{}
			for _, s := range c.Sections {
				sections = append(sections, Range{Start: s[0], Length: s[1]})
			}
			got := [][4]uint64{}
			_, err = intel.VisitPageMappings(context.Background(), PageMapOptions{MaxTables: 100, MaxEntries: 1000, Sections: sections}, func(m PageMapping) error {
				got = append(got, [4]uint64{m.Virtual, m.Length, m.Physical, m.Length})
				return nil
			})
			want := append([][4]uint64{}, c.Mappings...)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("selected mappings=%v, %v; want %v", got, err, want)
			}
		})
	}
}

func TestPageMapSectionsLimitTraversalAndClipBeforeAvailability(t *testing.T) {
	data := make([]byte, 0x5000)
	installX64(data, 0x1000, 0x4000, 3)
	put64(data, 0x1008, 0x9003) // Outside selected 1 GiB branch: must not be acquired.
	sparse, err := NewMapped(bufferSource(data), "partial-leaf", []Range{{Start: 0, Length: 0x4080}})
	if err != nil {
		t.Fatal(err)
	}
	reader := &mappingCountingLayer{MemoryLayer: sparse}
	intel, _ := NewIntelForOS(reader, 0, "x64", "linux", 1)
	var got []PageMapping
	stats, err := intel.VisitPageMappings(context.Background(), PageMapOptions{MaxTables: 4, MaxEntries: 4, Sections: []Range{{Start: 0x1010, Length: 32}}, OnReadError: func(at uint64, err error) error { t.Fatalf("unexpected table read %#x: %v", at, err); return err }}, func(m PageMapping) error { got = append(got, m); return nil })
	want := []PageMapping{{Virtual: 0x1010, Physical: 0x4010, Length: 32}}
	if err != nil || !reflect.DeepEqual(got, want) || stats.Tables != 4 || stats.Entries != 4 || stats.Unavailable != 0 || reader.calls != 4 {
		t.Fatal(got, stats, reader.calls, err)
	}
	reader.calls = 0
	_, err = intel.VisitPageMappings(context.Background(), PageMapOptions{MaxTables: 1, MaxEntries: 1, Sections: []Range{}}, func(PageMapping) error { t.Fatal("empty selection emitted"); return nil })
	if err != nil || reader.calls != 0 {
		t.Fatal("empty selection read source", reader.calls, err)
	}
}

func TestPageMapSectionCanonicalTailAndValidation(t *testing.T) {
	data := make([]byte, 0x5000)
	installX64(data, 0xfffffffff000, 0x4000, 3)
	intel, _ := NewIntelForOS(raw(t, data), 0, "x64", "linux", 1)
	for _, start := range []uint64{0xfffffffff000, 0xfffffffffffff000} {
		var got []PageMapping
		_, err := intel.VisitPageMappings(context.Background(), PageMapOptions{MaxTables: 4, MaxEntries: 4, Sections: []Range{{Start: start, Length: 4096}}}, func(m PageMapping) error { got = append(got, m); return nil })
		if err != nil || len(got) != 1 || got[0].Virtual != 0xfffffffffffff000 || got[0].Length != 4096 {
			t.Fatal(got, err)
		}
	}
	for _, section := range []Range{{Start: 0x1000, Length: 0}, {Start: 0x1000000000000, Length: 1}, {Start: 0xffff000000000000, Length: 1}, {Start: 0xfffffffffffff000, Length: 4097}} {
		_, err := intel.VisitPageMappings(context.Background(), PageMapOptions{MaxTables: 4, MaxEntries: 4, Sections: []Range{section}}, func(PageMapping) error { return nil })
		if err == nil {
			t.Fatal("invalid section accepted", section)
		}
	}
}

func TestPageMapSharedProgressStopsBeforeTableAcquisition(t *testing.T) {
	data := make([]byte, 0x5000)
	installX64(data, 0x1000, 0x4000, 3)
	reader := &mappingCountingLayer{MemoryLayer: raw(t, data)}
	intel, _ := NewIntelForOS(reader, 0, "x64", "linux", 1)
	sentinel := errors.New("shared table budget")
	var last PageMapStats
	_, err := intel.VisitPageMappings(context.Background(), PageMapOptions{MaxTables: 10, MaxEntries: 100, Sections: []Range{{Start: 0x1000, Length: 16}}, OnProgress: func(stats PageMapStats) error {
		if stats.Tables < last.Tables || stats.Entries < last.Entries {
			t.Fatal("nonmonotonic progress")
		}
		last = stats
		if stats.Tables == 2 {
			return sentinel
		}
		return nil
	}}, func(PageMapping) error { t.Fatal("emitted after progress stop"); return nil })
	if !errors.Is(err, sentinel) || reader.calls != 1 {
		t.Fatal("acquired table after shared budget stop", reader.calls, err)
	}
}
