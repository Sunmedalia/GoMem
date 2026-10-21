package memory

import (
	"context"
	"encoding/binary"
	"testing"
)

func installX64(buf []byte, virt, data, flags uint64) {
	shifts := []uint{39, 30, 21, 12}
	tables := []uint64{0, 0x1000, 0x2000, 0x3000}
	table := tables[0]
	for level, shift := range shifts {
		index := (virt >> shift) & 511
		off := table + index*8
		if shift == 12 {
			put64(buf, off, data|flags)
			return
		}
		put64(buf, off, tables[level+1]|3)
		table = tables[level+1]
	}
}

func TestPageMappingsMergeMaskClipAndHoles(t *testing.T) {
	buf := make([]byte, 0x6000)
	installX64(buf, 0x1000, 0x4000, 3)
	installX64(buf, 0x2000, 0x5000, 3)
	tr, err := NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tr.PageMappings(context.Background())
	if err != nil || len(got) != 1 || got[0].Virtual != 0x1000 || got[0].Physical != 0x4000 || got[0].Length != 0x2000 {
		t.Fatalf("merged = %+v %v", got, err)
	}

	buf = make([]byte, 0x6000)
	installX64(buf, 0x1000, 0x4000, 3)
	installX64(buf, 0x2000, 0x6000, 3)
	sparse, err := NewMapped(bufferSource(buf), "sparse", []Range{{Start: 0, Length: 0x5000}, {Start: 0x6000, Length: 0x1000, FileOffset: 0x5000}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err = NewIntelForOS(sparse, 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.PageMappings(context.Background())
	if err != nil || len(got) != 2 || got[0].Physical != 0x4000 || got[1].Virtual != 0x2000 || got[1].Physical != 0x6000 {
		t.Fatalf("split = %+v %v", got, err)
	}

	buf = make([]byte, 0x5000)
	installX64(buf, 0x1000, 0x4000, 3)
	hole, err := NewMapped(bufferSource(buf), "hole", []Range{{Start: 0, Length: 0x4000}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err = NewIntelForOS(hole, 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.PageMappings(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("physical hole was emitted: %+v %v", got, err)
	}

	buf = make([]byte, 0x5000)
	installX64(buf, 0x1000, 0x4000, 2048|(uint64(1)<<45))
	tr, err = NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.PageMappings(context.Background())
	if err != nil || len(got) != 1 || got[0].Virtual != 0x1000 || got[0].Physical != 0x4000 || got[0].Length != 0x1000 {
		t.Fatalf("transition mask = %+v %v", got, err)
	}
	plain, err := NewIntelForOS(raw(t, buf), 0, "x64", "linux", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = plain.PageMappings(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("linux accepted a windows transition entry: %+v %v", got, err)
	}

	buf = make([]byte, 0x5000)
	put64(buf, 0, 0x1000|3)
	put64(buf, 0x1000, 0x2000|3)
	put64(buf, 0x2000, 0x3000|3)
	for n := 0; n < 512; n++ {
		put64(buf, 0x3000+uint64(n*8), 0x4000|3)
	}
	tr, err = NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.PageMappings(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("uniform page table was mapped: %+v %v", got, err)
	}
}

func TestPageMappingsCrossCanonicalAndFinalByte(t *testing.T) {
	// The two pages differ at every table index, so each level needs its own
	// table. Sharing one table would map the cartesian product of those indices.
	buf := make([]byte, 0x9000)
	put64(buf, 255*8, 0x1000|3)
	put64(buf, 256*8, 0x2000|3)
	put64(buf, 0x1000+511*8, 0x3000|3)
	put64(buf, 0x2000+0*8, 0x4000|3)
	put64(buf, 0x3000+511*8, 0x5000|3)
	put64(buf, 0x4000+0*8, 0x6000|3)
	put64(buf, 0x5000+511*8, 0x7000|3)
	put64(buf, 0x6000+0*8, 0x8000|3)
	tr, err := NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tr.PageMappings(context.Background())
	if err != nil || len(got) != 1 || got[0].Virtual != 0x7ffffffff000 || got[0].Physical != 0x7000 || got[0].Length != 0x2000 {
		t.Fatalf("boundary = %+v %v", got, err)
	}

	buf = make([]byte, 0x5000)
	installX64(buf, 0xfffffffff000, 0x4000, 3)
	tr, err = NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.PageMappings(context.Background())
	if err != nil || len(got) != 1 || got[0].Virtual != 0xfffffffffffff000 || got[0].Physical != 0x4000 || got[0].Length != 0xfff {
		t.Fatalf("clipped tail = %+v %v", got, err)
	}
}

func TestPageMappingsLargePageAndX86(t *testing.T) {
	buf := make([]byte, 0x3000)
	put64(buf, 0, 0x1000|3)
	put64(buf, 0x1000, 0x2000|3)
	put64(buf, 0x2000, 128|3)
	source := partialSource{data: buf, size: 1 << 21}
	layer, err := NewMapped(source, "large", []Range{{Start: 0, Length: 1 << 21}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewIntelForOS(layer, 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tr.PageMappings(context.Background())
	if err != nil || len(got) != 1 || got[0].Virtual != 0 || got[0].Physical != 0 || got[0].Length != 1<<21 {
		t.Fatalf("large = %+v %v", got, err)
	}
	short, err := NewMapped(source, "short", []Range{{Start: 0, Length: 0x3000}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err = NewIntelForOS(short, 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.PageMappings(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("partial large page was emitted: %+v %v", got, err)
	}

	x86 := make([]byte, 0x4000)
	binary.LittleEndian.PutUint32(x86[0:], 0x1000|3)
	binary.LittleEndian.PutUint32(x86[0x1000:], 0x2000|3)
	binary.LittleEndian.PutUint32(x86[0x1004:], 0x3000|3)
	tr, err = NewIntelForOS(raw(t, x86), 0, "x86", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.PageMappings(context.Background())
	if err != nil || len(got) != 1 || got[0].Virtual != 0 || got[0].Physical != 0x2000 || got[0].Length != 0x2000 {
		t.Fatalf("x86 = %+v %v", got, err)
	}
}

type partialSource struct {
	data []byte
	size uint64
}

func (p partialSource) Name() string { return "partial" }
func (p partialSource) Size() uint64 { return p.size }
func (p partialSource) Close() error { return nil }
func (p partialSource) ReadAt(ctx context.Context, dst []byte, addr uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	end, err := Add(addr, uint64(len(dst)))
	if err != nil || end > uint64(len(p.data)) {
		return 0, errShort
	}
	return copy(dst, p.data[addr:end]), nil
}

var errShort = errString("short source")

type errString string

func (e errString) Error() string { return string(e) }
