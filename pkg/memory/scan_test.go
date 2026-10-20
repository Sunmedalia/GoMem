package memory

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestLiteralScanOverlapsChunksAndPhysicalRanges(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		data   []byte
		ranges []Range
		needle string
		want   []uint64
	}{
		{"overlap", []byte("ababa"), []Range{{Length: 5}}, "aba", []uint64{0, 2}},
		{"adjacent-container-segments", []byte("abXXaba"), []Range{{Start: 0x1000, Length: 2}, {Start: 0x1002, Length: 3, FileOffset: 4}}, "aba", []uint64{0x1000, 0x1002}},
		{"hole", []byte("abXXaba"), []Range{{Start: 0x1000, Length: 2}, {Start: 0x1003, Length: 3, FileOffset: 4}}, "aba", []uint64{0x1003}},
	}
	large := make([]byte, (1<<20)+10)
	copy(large[(1<<20)-2:], "boundary")
	tests = append(tests, struct {
		name   string
		data   []byte
		ranges []Range
		needle string
		want   []uint64
	}{"chunk-boundary", large, []Range{{Length: uint64(len(large))}}, "boundary", []uint64{(1 << 20) - 2}})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			layer, err := NewMapped(bufferSource(tc.data), "scan", tc.ranges)
			if err != nil {
				t.Fatal(err)
			}
			var got []uint64
			if err = Scan(ctx, layer, []byte(tc.needle), func(a uint64) error { got = append(got, a); return nil }); err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatal(got, tc.want, err)
			}
		})
	}
	stop := errors.New("output failed")
	if err := Scan(ctx, raw(t, []byte("ababa")), []byte("aba"), func(uint64) error { return stop }); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := Scan(canceled, raw(t, []byte("ababa")), []byte("aba"), func(uint64) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
