package memory

import (
	"context"
	"encoding/binary"
	"testing"
)

func put64(b []byte, addr, value uint64) {
	binary.LittleEndian.PutUint64(b[addr:], value)
}

func TestMappedRangesCoalesceHolesTransitionAndCanonical(t *testing.T) {
	buf := make([]byte, 0x6000)
	put64(buf, 0x0000, 0x1000|3)
	put64(buf, 0x1000, 0x2000|3)
	put64(buf, 0x2000, 0x3000|3)
	put64(buf, 0x3000+8, 0x4000|3)
	put64(buf, 0x3000+16, 0x5000|3)
	p := raw(t, buf)
	tr, err := NewIntelForOS(p, 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tr.MappedRanges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Start != 0x1000 || got[0].Length != 0x2000 {
		t.Fatalf("coalesced ranges = %+v", got)
	}

	buf[0x3000+16] = 0
	put64(buf, 0x3000+24, 0x5000|3)
	tr, err = NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.MappedRanges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Start != 0x1000 || got[0].Length != 0x1000 || got[1].Start != 0x3000 || got[1].Length != 0x1000 {
		t.Fatalf("hole ranges = %+v", got)
	}

	for n := 0; n < 512; n++ {
		put64(buf, 0x3000+uint64(n*8), 0x4000|3)
	}
	tr, err = NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.MappedRanges(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("uniform page table was scanned: %+v", got)
	}
	if _, err := tr.Translate(context.Background(), 0x1000); err != nil {
		t.Fatal("translator itself still accepts the repeated page", err)
	}

	buf = make([]byte, 0x5000)
	put64(buf, 0x0000, 0x1000|3)
	put64(buf, 0x1000, 0x2000|3)
	put64(buf, 0x2000, 0x3000|3)
	put64(buf, 0x3008, 0x4000|2048|(1<<45))
	tr, err = NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.MappedRanges(context.Background())
	if err != nil || len(got) != 1 || got[0].Start != 0x1000 || got[0].Length != 0x1000 {
		t.Fatal(got, err)
	}
	plain, err := NewIntelForOS(raw(t, buf), 0, "x64", "linux", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = plain.MappedRanges(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatal("non-windows translator included a transition page", got, err)
	}

	buf = make([]byte, 0x5000)
	put64(buf, 256*8, 0x1000|3)
	put64(buf, 0x1000, 0x2000|3)
	put64(buf, 0x2000, 0x3000|3)
	put64(buf, 0x3000, 0x4000|3)
	tr, err = NewIntelForOS(raw(t, buf), 0, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tr.MappedRanges(context.Background())
	if err != nil || len(got) != 1 || got[0].Start != 0xffff800000000000 || got[0].Length != 0x1000 {
		t.Fatal(got, err)
	}
}
