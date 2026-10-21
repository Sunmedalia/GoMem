package memory

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

func TestARM64Walk(t *testing.T) {
	for _, shift := range []uint{12, 21, 30} {
		t.Run(fmt.Sprint(shift), func(t *testing.T) {
			data := make([]byte, 0x6000)
			put := func(at, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
			va := uint64(0xffff800000001234)
			put(0x1800, 0x2003)
			put(0x2000, 0x3003)
			put(0x3000, 0x4003)
			put(0x4008, 0x5003)
			frame := uint64(0x5000)
			if shift == 21 {
				frame = 0x200000
				put(0x3000, frame|1)
			}
			if shift == 30 {
				frame = 0x40000000
				put(0x2000, frame|1)
			}
			tr, err := NewARM64(raw(t, data), 0x1000, 2)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tr.Translate(context.Background(), va)
			if err != nil {
				t.Fatal(err)
			}
			want := frame + (va & ((uint64(1) << shift) - 1))
			if got.Physical != want || got.PageSize != uint64(1)<<shift || !got.Writable || !got.Executable || got.DirtyKnown {
				t.Fatalf("%+v want %#x", got, want)
			}
		})
	}
}
func TestARM64PermissionsAndErrors(t *testing.T) {
	data := make([]byte, 0x6000)
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
	put(0x1000, 0x2003|(uint64(1)<<62))
	put(0x2000, 0x3003)
	put(0x3000, 0x4003)
	put(0x4000, 0x5003|(uint64(1)<<54))
	tr, _ := NewARM64(raw(t, data), 0x1000, 2)
	got, err := tr.Translate(context.Background(), 0x123)
	if err != nil || got.Writable || got.Executable {
		t.Fatal(got, err)
	}
	if _, err = tr.Translate(context.Background(), 0x1000); !errors.Is(err, ErrUnmapped) {
		t.Fatal(err)
	}
	if _, err = tr.Translate(context.Background(), 0xab00000000000000); err == nil {
		t.Fatal("accepted invalid VA")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = tr.Translate(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, bad := range []uint64{0x1001, 1 << 48} {
		if _, err = NewARM64(raw(t, data), bad, 2); err == nil {
			t.Fatal("accepted invalid root")
		}
	}
	for _, entry := range []uint64{1, 0x2001, (uint64(1) << 48) | 0x2003} {
		put(0x1000, entry)
		tr, _ = NewARM64(raw(t, data), 0x1000, 2)
		if _, err = tr.Translate(context.Background(), 0); err == nil {
			t.Fatal("accepted reserved or misaligned descriptor")
		}
	}
}
func TestARM64SparseTableRequiresOnlyRequestedDescriptor(t *testing.T) {
	data := make([]byte, 0x3000)
	binary.LittleEndian.PutUint64(data[0x1000:], 0x2003)
	binary.LittleEndian.PutUint64(data[0x2000:], 0x40000001)
	tr, _ := NewARM64(raw(t, data[:0x2008]), 0x1000, 2)
	got, err := tr.Translate(context.Background(), 0x1234)
	if err != nil || got.Physical != 0x40001234 {
		t.Fatal(got, err)
	}
	tr, _ = NewARM64(raw(t, data[:0x2007]), 0x1000, 2)
	if _, err = tr.Translate(context.Background(), 0); err == nil {
		t.Fatal("accepted truncated descriptor")
	}
}
