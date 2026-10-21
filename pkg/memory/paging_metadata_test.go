package memory

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestIntelLeafEvidenceAndDirtyState(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		shift uint
	}{
		{"x64", 12}, {"x64", 21}, {"x64", 30}, {"pae", 12}, {"pae", 21}, {"x86", 12}, {"x86", 22},
	} {
		for _, dirty := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%d/dirty=%v", tc.mode, tc.shift, dirty), func(t *testing.T) {
				data := make([]byte, 0x6000)
				shifts := []uint{39, 30, 21, 12}
				width := 8
				if tc.mode == "pae" {
					shifts = []uint{30, 21, 12}
				}
				if tc.mode == "x86" {
					shifts = []uint{22, 12}
					width = 4
				}
				put := func(at, entry uint64) {
					if width == 4 {
						binary.LittleEndian.PutUint32(data[at:], uint32(entry))
					} else {
						binary.LittleEndian.PutUint64(data[at:], entry)
					}
				}
				table, leaf := uint64(0x1000), uint64(0)
				expected := uint64(0x81)
				if tc.shift == 12 {
					expected = 0x8003
				}
				if dirty {
					expected |= 64
				}
				for _, shift := range shifts {
					if shift == tc.shift {
						leaf = table
						put(leaf, expected)
						break
					}
					// Dirty bits on non-leaf entries must not mark the mapped page dirty.
					put(table, table+0x1000|0x43)
					table += 0x1000
				}
				translator, err := NewIntel(raw(t, data), 0x1000, tc.mode, 8)
				if err != nil {
					t.Fatal(err)
				}
				tr, err := translator.Translate(context.Background(), 0x123)
				if err != nil || tr.PageSize != uint64(1)<<tc.shift || tr.Available != tr.PageSize-0x123 || !tr.DirtyKnown || tr.Dirty != dirty || tr.EntryAddress != leaf || int(tr.EntryWidth) != width || tr.Entry != expected {
					t.Fatal(tr, err)
				}
				actual := uint64(binary.LittleEndian.Uint32(data[tr.EntryAddress:]))
				if tr.EntryWidth == 8 {
					actual = binary.LittleEndian.Uint64(data[tr.EntryAddress:])
				}
				if actual != tr.Entry {
					t.Fatal("leaf provenance differs from physical bytes")
				}
				again, err := translator.Translate(context.Background(), 0x456)
				if err != nil || again.Entry != tr.Entry || again.EntryAddress != tr.EntryAddress || again.PageSize != tr.PageSize || again.Dirty != dirty {
					t.Fatal(again, err)
				}
			})
		}
	}
}

func TestIntelTransitionDirtyStateUnknown(t *testing.T) {
	data := make([]byte, 0x5000)
	for at, entry := range map[int]uint64{0x1000: 0x2003, 0x2000: 0x3003, 0x3000: 0x4003, 0x4000: 0x8840} {
		binary.LittleEndian.PutUint64(data[at:], entry)
	}
	translator, err := NewIntelForOS(raw(t, data), 0x1000, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := translator.Translate(context.Background(), 0x123)
	if err != nil || !tr.Transition || tr.DirtyKnown || tr.Dirty || tr.Entry != 0x8840 || tr.EntryAddress != 0x4000 || tr.PageSize != 4096 {
		t.Fatal(tr, err)
	}
}
