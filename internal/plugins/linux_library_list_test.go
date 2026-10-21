package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func libraryTestImage(width int, dyn bool) flatMemory {
	data := make(flatMemory, 0x10000)
	base := uint64(0x1000)
	copy(data[base:], "\x7fELF")
	data[base+4] = 2
	data[base+5] = 1
	data[base+6] = 1
	u16 := func(at uint64, n uint16) { binary.LittleEndian.PutUint16(data[at:], n) }
	u32 := func(at uint64, n uint32) { binary.LittleEndian.PutUint32(data[at:], n) }
	put := func(at, n uint64) {
		if width == 4 {
			u32(at, uint32(n))
		} else {
			binary.LittleEndian.PutUint64(data[at:], n)
		}
	}
	typ := uint16(2)
	if dyn {
		typ = 3
	}
	u16(base+16, typ)
	phoff, phsize := uint64(64), uint64(56)
	if width == 4 {
		data[base+4] = 1
		phoff, phsize = 52, 32
		u32(base+28, uint32(phoff))
		u16(base+44, 2)
	} else {
		put(base+32, phoff)
		u16(base+56, 2)
	}
	// Header e_phentsize is deliberately zero: the pinned reader uses its
	// class-specific structure sizes, rather than that untrusted field.
	ph := base + phoff
	u32(ph, 1)
	u32(ph+phsize, 2)
	vaddr := uint64(0x2000)
	if dyn {
		vaddr -= base
	}
	off := uint64(16)
	if width == 4 {
		off = 8
	}
	put(ph+phsize+off, vaddr)
	put(0x2000, 3)
	put(0x2000+uint64(width), 0x3000)
	put(0x3000+uint64(width), 0x4000)
	link := func(at, load, name, next uint64) {
		put(at, load)
		put(at+uint64(width), name)
		put(at+uint64(width*3), next)
	}
	link(0x4000, 0, 0x6000, 0x4100) // Zero load address is skipped.
	link(0x4100, 0x700000, 0x6100, 0x4200)
	link(0x4200, 0x800000, 0x6200, 0x4300)
	link(0x4300, 0x700000, 0x6300, 0) // First load wins.
	copy(data[0x6100:], "/lib/libone.so\x00")
	copy(data[0x6200:], []byte{'/', 0xe2, 0x82, 0, 0})
	copy(data[0x6300:], "/duplicate.so\x00")
	return data
}
func TestLinuxLibraryListGOTLayoutsAndRawProof(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, dyn := range []bool{false, true} {
			data := libraryTestImage(width, dyn)
			remaining := uint64(100)
			var got []linuxLibraryObservation
			fields, err := scanLinuxLibraries(context.Background(), data, 0x1000, width, &remaining, map[uint64]bool{}, func(o linuxLibraryObservation) error { got = append(got, o); return nil })
			if err != nil || len(got) != 2 || got[0].path.String() != "/lib/libone.so" || got[1].path.String() != "/�" || remaining != 96 {
				t.Fatal(width, dyn, got, fields, err)
			}
			for _, o := range got {
				for _, key := range []string{"Header", "ProgramHeader", "Dynamic", "GOT", "LinkMap", "Name"} {
					f := o.fields[key].Data.(map[string]evidence.Value)
					at, _ := f["Address"].Uint()
					raw := f["Raw"].Data.([]byte)
					if !reflect.DeepEqual(raw, []byte(data[at:at+uint64(len(raw))])) {
						t.Fatal(key, "raw bytes differ")
					}
				}
			}
		}
	}
}
func TestLinuxLibraryListSelectionFailuresAndBounds(t *testing.T) {
	for _, scenario := range []string{"nonelf", "class", "endian", "overflow", "cycle", "name-hole", "node-hole", "limit", "empty-first", "unterminated", "duplicate-dynamic"} {
		t.Run(scenario, func(t *testing.T) {
			data := libraryTestImage(8, false)
			remaining := uint64(100)
			want, failed := 2, true
			put := func(at, n uint64) { binary.LittleEndian.PutUint64(data[at:], n) }
			var layer memory.MemoryLayer = data
			switch scenario {
			case "nonelf":
				data[0x1000] = 0
				want, failed = 0, false
			case "class":
				data[0x1004] = 9
				want = 0
			case "endian":
				data[0x1005] = 2
				want = 0
			case "overflow":
				put(0x2008, ^uint64(0)-3)
				want = 0
			case "cycle":
				put(0x4318, 0x4000)
			case "name-hole":
				put(0x4108, 0xfff0)
			case "node-hole":
				put(0x4218, 0xfff0)
			case "limit":
				remaining = 1
				want = 0
			case "empty-first":
				clear(data[0x6100:0x6200])
				want, failed = 1, false
			case "unterminated":
				for i := 0; i < 256; i++ {
					put(0x2000+uint64(i*16), 42)
				}
				want = 0
			case "duplicate-dynamic":
				put(0x2010, 3)
				put(0x2018, 0x3000)
				failed = false
			}
			got := 0
			_, err := scanLinuxLibraries(context.Background(), layer, 0x1000, 8, &remaining, map[uint64]bool{}, func(o linuxLibraryObservation) error { got++; return nil })
			if (err != nil) != failed || got != want {
				t.Fatal(got, want, err)
			}
		})
	}
}
func TestLinuxLibraryListCompatKernelPointerWidthAndControlFlow(t *testing.T) {
	data := libraryTestImage(4, false)
	remaining := uint64(100)
	// The pinned ELF32 path reads GOT[1] using the kernel's pointer type.
	binary.LittleEndian.PutUint32(data[0x3008:], 1)
	_, err := scanLinuxLibraries(context.Background(), data, 0x1000, 8, &remaining, map[uint64]bool{}, func(linuxLibraryObservation) error { t.Fatal("compat pointer high half ignored"); return nil })
	if err == nil {
		t.Fatal("unreadable 64-bit pointer silently narrowed")
	}
	sentinel := errors.New("output failed")
	remaining = 100
	_, err = scanLinuxLibraries(context.Background(), libraryTestImage(8, false), 0x1000, 8, &remaining, map[uint64]bool{}, func(linuxLibraryObservation) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = scanLinuxLibraries(ctx, data, 0x1000, 4, &remaining, map[uint64]bool{}, func(linuxLibraryObservation) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func FuzzLinuxLibraryList(f *testing.F) {
	f.Add([]byte(libraryTestImage(8, false)))
	f.Add([]byte(libraryTestImage(4, true)))
	f.Add([]byte("\x7fELF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		remaining := uint64(32)
		_, _ = scanLinuxLibraries(context.Background(), flatMemory(data), 0x1000, 8, &remaining, map[uint64]bool{}, func(linuxLibraryObservation) error { return nil })
	})
}

func TestLinuxLibraryListPinnedByteBackedObjects(t *testing.T) {
	raw, err := os.ReadFile("testdata/linux-library-list-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		LinkMap uint64 `json:"link_map"`
		Load    uint64 `json:"load_address"`
		Path    string `json:"path"`
	}
	var oracle struct {
		Commit string
		Cases  []struct {
			Width       int
			KernelWidth int `json:"kernel_width"`
			Dynamic     bool
			Scenario    string
			Size        int
			Writes      [][]json.RawMessage
			Rows        []result
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 30 {
		t.Fatal(err, len(oracle.Cases))
	}
	for _, c := range oracle.Cases {
		t.Run(fmt.Sprintf("%d/%t/%s", c.Width, c.Dynamic, c.Scenario), func(t *testing.T) {
			data := make(flatMemory, c.Size)
			for _, write := range c.Writes {
				var at int
				var text string
				if err = json.Unmarshal(write[0], &at); err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(write[1], &text); err != nil {
					t.Fatal(err)
				}
				b, err := hex.DecodeString(text)
				if err != nil {
					t.Fatal(err)
				}
				copy(data[at:], b)
			}
			remaining := uint64(100)
			selected := map[uint64]bool{}
			got := []result{}
			for i := 0; i < 2; i++ {
				_, err = scanLinuxLibraries(context.Background(), data, 0x1000, c.KernelWidth, &remaining, selected, func(o linuxLibraryObservation) error {
					if o.err == nil {
						got = append(got, result{o.address, o.load, o.path.String()})
					}
					return nil
				})
				if err != nil && c.Scenario != "cycle" && c.Scenario != "name-hole" && c.Scenario != "compat-high-half" {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(got, c.Rows) {
				t.Fatal("pinned selected library rows differ", got, c.Rows)
			}
		})
	}
}
