package memory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestWindowsSwapPinnedOracle(t *testing.T) {
	data, err := os.ReadFile("testdata/windows-swap-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Arch                 string
			Level, Number, Width int
			Address, Entry       uint64
			Writes               []struct{ Offset, Value uint64 }
			ReferenceOffset      uint64 `json:"reference_offset"`
			CorrectedOffset      uint64 `json:"corrected_offset"`
			PageSize             uint64 `json:"page_size"`
			ReferenceBytes       []byte `json:"reference_bytes"`
			CorrectedBytes       []byte `json:"corrected_bytes"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 54 {
		t.Fatal("incomplete fixed layer oracle")
	}
	for n, tc := range fixture.Cases {
		t.Run(fmt.Sprintf("%s-%d-%d-%x", tc.Arch, tc.Level, tc.Number, tc.Address), func(t *testing.T) {
			ram := make([]byte, 0x10000)
			for _, write := range tc.Writes {
				if tc.Width == 4 {
					binary.LittleEndian.PutUint32(ram[write.Offset:], uint32(write.Value))
				} else {
					binary.LittleEndian.PutUint64(ram[write.Offset:], write.Value)
				}
			}
			file := make([]byte, 0x4000)
			for n := range file {
				file[n] = byte(n % 251)
			}
			physical, _ := WithPagefiles(raw(t, ram), map[uint8]MemoryLayer{uint8(tc.Number): raw(t, file)})
			tr, _ := NewIntelForOS(physical, 0x1000, tc.Arch, "windows", 4)
			_, err := tr.Translate(context.Background(), tc.Address)
			var swapped *SwappedPageError
			if !errors.As(err, &swapped) || swapped.Offset != tc.ReferenceOffset || swapped.PageSize != tc.PageSize || swapped.Entry != tc.Entry {
				t.Fatal(n, swapped, tc, err)
			}
			resolved, err := tr.Resolve(context.Background(), tc.Address)
			if err != nil || resolved.Offset != tc.CorrectedOffset || resolved.Pagefile == nil || int(*resolved.Pagefile) != tc.Number {
				t.Fatal(resolved, err)
			}
			var mapped []BackingMapping
			unavailable := 0
			stats, mapErr := tr.VisitBackingMappings(context.Background(), BackingMapOptions{MaxTables: 10, MaxEntries: 100, Sections: []Range{{Start: tc.Address, Length: 8}}, OnUnavailableMapping: func(m BackingMapping, err error) error {
				unavailable++
				if m.Offset != tc.CorrectedOffset || m.Pagefile == nil || int(*m.Pagefile) != tc.Number || !errors.Is(err, ErrUnmapped) {
					t.Fatal(m, err)
				}
				return nil
			}}, func(m BackingMapping) error { mapped = append(mapped, m); return nil })
			if mapErr != nil {
				t.Fatal(mapErr)
			}
			if tc.CorrectedBytes == nil {
				if unavailable != 1 || stats.Unavailable != 1 || len(mapped) != 0 {
					t.Fatal("unavailable intermediate swap block was treated as readable", stats, mapped)
				}
			} else if unavailable != 0 || len(mapped) != 1 || mapped[0].Offset != tc.CorrectedOffset || mapped[0].Virtual != tc.Address || mapped[0].Length != 8 {
				t.Fatal(mapped, stats)
			}
			if tc.CorrectedBytes != nil {
				actual, err := Read(context.Background(), &Virtual{Physical: physical, Translator: tr}, tc.Address, len(tc.CorrectedBytes))
				if err != nil || !bytes.Equal(actual, tc.CorrectedBytes) {
					t.Fatal(actual, tc.CorrectedBytes, err)
				}
				if tc.Address == 0 && !bytes.Equal(actual, tc.ReferenceBytes) {
					t.Fatal("aligned fixed baseline mismatch")
				}
				if tc.Address != 0 && bytes.Equal(actual, tc.ReferenceBytes) {
					t.Fatal("unaligned upstream divergence lost")
				}
			}
		})
	}
}

func TestWindowsSwapRejectsNonSwapFlags(t *testing.T) {
	for _, mode := range []string{"x64", "x86", "pae"} {
		for _, scenario := range []string{"prototype", "transition-prototype", "no-protection-bit", "zero-index", "empty"} {
			ram, entry, _ := swappedFixture(t, mode, 0, -1)
			width, at := 8, 0x4000
			if mode == "x86" {
				width, at = 4, 0x2000
			} else if mode == "pae" {
				at = 0x3000
			}
			switch scenario {
			case "prototype":
				entry |= 1024
			case "transition-prototype":
				entry |= 1024 | 2048
			case "no-protection-bit":
				entry &^= 128
			case "zero-index":
				entry = 128
			case "empty":
				entry = 0
			}
			if width == 4 {
				binary.LittleEndian.PutUint32(ram[at:], uint32(entry))
			} else {
				binary.LittleEndian.PutUint64(ram[at:], entry)
			}
			physical, _ := WithPagefiles(raw(t, ram), map[uint8]MemoryLayer{0: raw(t, make([]byte, 0x4000))})
			tr, _ := NewIntelForOS(physical, 0x1000, mode, "windows", 4)
			var swapped *SwappedPageError
			if _, err := tr.Resolve(context.Background(), 0); !errors.Is(err, ErrUnmapped) || errors.As(err, &swapped) {
				t.Fatal(mode, scenario, err)
			}
		}
	}
}

func TestWindowsSwapOverflowAndAttachmentIsolation(t *testing.T) {
	ram, _, _ := swappedFixture(t, "x64", 0, 0)
	binary.LittleEndian.PutUint64(ram[0x1000:], uint64(0xffffffff)<<32|128)
	files := map[uint8]MemoryLayer{0: raw(t, make([]byte, 0x4000))}
	attached, err := WithPagefiles(raw(t, ram), files)
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := NewIntelForOS(attached, 0x1000, "x64", "windows", 4)
	if _, err := tr.Resolve(context.Background(), 0x123); !errors.Is(err, ErrUnmapped) {
		t.Fatal("overflow became a valid offset", err)
	}
	ram, _, _ = swappedFixture(t, "x64", 0, -1)
	file := make([]byte, 0x4000)
	copy(file[0x2123:], "original")
	files = map[uint8]MemoryLayer{0: raw(t, file)}
	attached, _ = WithPagefiles(raw(t, ram), files)
	delete(files, 0)
	tr, _ = NewIntelForOS(attached, 0x1000, "x64", "windows", 4)
	got, err := Read(context.Background(), &Virtual{Physical: attached, Translator: tr}, 0x123, 8)
	if err != nil || string(got) != "original" {
		t.Fatal("caller changed attached numbering", string(got), err)
	}
	merged, err := WithPagefiles(attached, map[uint8]MemoryLayer{1: raw(t, file)})
	if err != nil {
		t.Fatal(err)
	}
	mergedTr, _ := NewIntelForOS(merged, 0x1000, "x64", "windows", 4)
	if len(mergedTr.pagefiles) != 2 {
		t.Fatal("reattachment lost an existing source")
	}
	if _, err := WithPagefiles(merged, map[uint8]MemoryLayer{0: raw(t, file)}); err == nil {
		t.Fatal("silently replaced a captured source")
	}
}

func FuzzWindowsPagefileResolve(f *testing.F) {
	f.Add(uint64(2)<<32|128, uint8(0), uint16(0x123))
	f.Add(uint64(2)<<12|128, uint8(1), uint16(0xffe))
	f.Add(uint64(2)<<32|128|30, uint8(2), uint16(0))
	f.Fuzz(func(t *testing.T, entry uint64, which uint8, address uint16) {
		mode := []string{"x64", "x86", "pae"}[int(which)%3]
		ram, _, _ := swappedFixture(t, mode, 0, -1)
		at := 0x4000
		if mode == "x86" {
			at = 0x2000
			binary.LittleEndian.PutUint32(ram[at:], uint32(entry))
		} else {
			if mode == "pae" {
				at = 0x3000
			}
			binary.LittleEndian.PutUint64(ram[at:], entry)
		}
		file := make([]byte, 0x4000)
		for n := range file {
			file[n] = byte(n % 251)
		}
		files := map[uint8]MemoryLayer{}
		layer := raw(t, file)
		for n := uint8(0); n < 16; n++ {
			files[n] = layer
		}
		physical, _ := WithPagefiles(raw(t, ram), files)
		tr, _ := NewIntelForOS(physical, 0x1000, mode, "windows", 4)
		va := uint64(address) & 4095
		resolved, err := tr.Resolve(context.Background(), va)
		_, mapErr := tr.VisitBackingMappings(context.Background(), BackingMapOptions{MaxTables: 10, MaxEntries: 100, Sections: []Range{{Start: va, Length: 1}}}, func(m BackingMapping) error {
			if err != nil || m.Virtual != va || m.Offset != resolved.Offset || m.Length != 1 || (m.Pagefile == nil) != (resolved.Pagefile == nil) {
				t.Fatal("map and resolver disagree", m, resolved, err)
			}
			if m.Pagefile != nil && *m.Pagefile != *resolved.Pagefile {
				t.Fatal("wrong pagefile source")
			}
			actual, readErr := Read(context.Background(), m.Layer, m.Offset, 1)
			original, virtualErr := Read(context.Background(), &Virtual{Physical: physical, Translator: tr}, va, 1)
			if readErr != nil || virtualErr != nil || !bytes.Equal(actual, original) {
				t.Fatal("map bytes differ", readErr, virtualErr)
			}
			return nil
		})
		if mapErr != nil && !errors.Is(mapErr, ErrUnmapped) && !errors.Is(mapErr, ErrUnsupported) {
			t.Fatal(mapErr)
		}
		if err != nil || resolved.Pagefile == nil {
			return
		}
		if resolved.Physical != 0 || resolved.PermissionsKnown || resolved.DirtyKnown || resolved.Available != 4096-va {
			t.Fatal("swap mislabelled as physical", resolved)
		}
		if resolved.Offset > uint64(len(file)) || uint64(len(file))-resolved.Offset < 8 || resolved.Available < 8 {
			return
		}
		actual, err := Read(context.Background(), &Virtual{Physical: physical, Translator: tr}, va, 8)
		if err != nil || !bytes.Equal(actual, file[resolved.Offset:resolved.Offset+8]) {
			t.Fatal("wrong backing bytes", err)
		}
	})
}

func swappedFixture(t testing.TB, mode string, number uint8, level int) ([]byte, uint64, uint64) {
	t.Helper()
	raw := make([]byte, 0x10000)
	width := 8
	shifts := []uint{39, 30, 21, 12}
	if mode == "x86" {
		width = 4
		shifts = []uint{22, 12}
	} else if mode == "pae" {
		shifts = []uint{30, 21, 12}
	}
	if level < 0 {
		level = len(shifts) - 1
	}
	bitOffset := uint(32)
	if mode == "x86" {
		bitOffset = 12
	}
	entry := uint64(2)<<bitOffset | 128 | uint64(number)<<1
	for n := 0; n <= level; n++ {
		value := uint64((n+2)*4096) | 3
		if n == level {
			value = entry
		}
		if width == 4 {
			binary.LittleEndian.PutUint32(raw[(n+1)*4096:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(raw[(n+1)*4096:], value)
		}
	}
	return raw, entry, uint64(1) << shifts[level]
}

func TestWindowsPagefileResolutionAndCoordinates(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"x64", "x86", "pae"} {
		for _, number := range []uint8{0, 1, 15} {
			t.Run(mode+string(rune('a'+number)), func(t *testing.T) {
				ram, entry, _ := swappedFixture(t, mode, number, -1)
				file := make([]byte, 0x4000)
				copy(file[0x2123:], "external")
				attached, err := WithPagefiles(raw(t, ram), map[uint8]MemoryLayer{number: raw(t, file)})
				if err != nil {
					t.Fatal(err)
				}
				tr, err := NewIntelForOS(attached, 0x1000, mode, "windows", 4)
				if err != nil {
					t.Fatal(err)
				}
				_, err = tr.Translate(ctx, 0x123)
				var swapped *SwappedPageError
				if !errors.As(err, &swapped) || !errors.Is(err, ErrUnmapped) || swapped.Number != number || swapped.Offset != 0x2000 || swapped.Entry != entry {
					t.Fatal("pagefile became RAM or lost metadata", swapped, err)
				}
				backing, err := tr.Resolve(ctx, 0x123)
				if err != nil || backing.Pagefile == nil || *backing.Pagefile != number || backing.Offset != 0x2123 || backing.Physical != 0 || backing.Available != 4096-0x123 || backing.PermissionsKnown || backing.DirtyKnown {
					t.Fatal(backing, err)
				}
				v := &Virtual{Physical: attached, Translator: tr, ID: "pagefile-process"}
				got, err := Read(ctx, v, 0x123, 8)
				if err != nil || string(got) != "external" {
					t.Fatal(string(got), err)
				}
				if _, err := tr.MappedRanges(ctx); !errors.Is(err, ErrUnsupported) {
					t.Fatal("incomplete scan coverage accepted", err)
				}
				if _, err := tr.PageMappings(ctx); !errors.Is(err, ErrUnsupported) {
					t.Fatal("pagefile offset labelled physical", err)
				}
				generic, _ := NewIntelForOS(attached, 0x1000, mode, "linux", 4)
				if _, err := generic.Resolve(ctx, 0x123); !errors.Is(err, ErrUnmapped) {
					t.Fatal("Windows encoding applied to Linux", err)
				}
			})
		}
	}
}

func TestWindowsPagefileBoundsHolesAndCrossPage(t *testing.T) {
	ctx := context.Background()
	ram, _, _ := swappedFixture(t, "x64", 0, -1)
	// The next virtual page is resident, so a read may cross source boundaries.
	binary.LittleEndian.PutUint64(ram[0x4008:], 0x8003)
	copy(ram[0x8000:], "RAM")
	file := make([]byte, 0x3000)
	copy(file[0x2ffd:], "SWP")
	attached, _ := WithPagefiles(raw(t, ram), map[uint8]MemoryLayer{0: raw(t, file)})
	tr, _ := NewIntelForOS(attached, 0x1000, "x64", "windows", 4)
	v := &Virtual{Physical: attached, Translator: tr, ID: "mixed"}
	got, err := Read(ctx, v, 0xffd, 6)
	if err != nil || string(got) != "SWPRAM" {
		t.Fatal(string(got), err)
	}
	missing, _ := NewIntelForOS(raw(t, ram), 0x1000, "x64", "windows", 4)
	if _, err := missing.Resolve(ctx, 0); !errors.Is(err, ErrUnmapped) {
		t.Fatal(err)
	}
	short, _ := WithPagefiles(raw(t, ram), map[uint8]MemoryLayer{0: raw(t, make([]byte, 0x2001))})
	shortTr, _ := NewIntelForOS(short, 0x1000, "x64", "windows", 4)
	buf := bytes.Repeat([]byte{0xcc}, 4)
	n, err := (&Virtual{Physical: short, Translator: shortTr}).ReadAt(ctx, buf, 0)
	if err == nil || n != 1 || !bytes.Equal(buf[1:], []byte{0xcc, 0xcc, 0xcc}) {
		t.Fatal("missing pagefile bytes padded", n, buf, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := tr.Resolve(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, files := range []map[uint8]MemoryLayer{{16: raw(t, file)}, {0: nil}} {
		if _, err := WithPagefiles(raw(t, ram), files); err == nil {
			t.Fatal("invalid pagefile attachment accepted")
		}
	}
}
