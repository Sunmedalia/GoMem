package memory

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func TestPointerScanUnalignedChunksAndContainers(t *testing.T) {
	for _, width := range []int{4, 8} {
		needle := []byte("ABCDEFGH")[:width]
		value := uint64(binary.LittleEndian.Uint32(needle))
		if width == 8 {
			value = binary.LittleEndian.Uint64(needle)
		}
		large := make([]byte, (1<<20)+20)
		copy(large[(1<<20)-2:], needle)
		copy(large[3:], needle)
		for _, tc := range []struct {
			name   string
			data   []byte
			ranges []Range
			want   []uint64
		}{
			{"unaligned-chunk", large, []Range{{Length: uint64(len(large))}}, []uint64{3, (1 << 20) - 2}},
			{"adjacent", append(append([]byte{}, needle[:2]...), append([]byte("XX"), needle[2:]...)...), []Range{{Start: 0x1000, Length: 2}, {Start: 0x1002, Length: uint64(width - 2), FileOffset: 4}}, []uint64{0x1000}},
			{"hole", append(append([]byte{}, needle[:2]...), append([]byte("XX"), needle[2:]...)...), []Range{{Start: 0x1000, Length: 2}, {Start: 0x1003, Length: uint64(width - 2), FileOffset: 4}}, nil},
		} {
			t.Run(tc.name+string(rune('0'+width)), func(t *testing.T) {
				layer, err := NewMapped(bufferSource(tc.data), "pointers", tc.ranges)
				if err != nil {
					t.Fatal(err)
				}
				var hits []uint64
				err = ScanPointers(context.Background(), layer, []uint64{value, 0x11223344}, width, func(a, v uint64) error {
					if v != value {
						t.Fatal("unexpected match", v)
					}
					hits = append(hits, a)
					return nil
				})
				if err != nil || !reflect.DeepEqual(hits, tc.want) {
					t.Fatal(hits, tc.want, err)
				}
			})
		}
	}
}

func TestPointerScanBoundsAndImmediateCancellation(t *testing.T) {
	layer := raw(t, make([]byte, 100))
	for _, width := range []int{4, 8} {
		count := 0
		ctx, cancel := context.WithCancel(context.Background())
		err := ScanPointers(ctx, layer, []uint64{0}, width, func(uint64, uint64) error { count++; cancel(); return nil })
		if !errors.Is(err, context.Canceled) || count != 1 {
			t.Fatal(count, err)
		}
		sentinel := errors.New("stop")
		if err = ScanPointers(context.Background(), layer, []uint64{0}, width, func(uint64, uint64) error { return sentinel }); !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		values []uint64
		width  int
	}{{nil, 8}, {[]uint64{1, 1}, 8}, {[]uint64{1 << 32}, 4}, {[]uint64{1}, 5}, {make([]uint64, 4097), 8}} {
		if err := ScanPointers(context.Background(), layer, tc.values, tc.width, func(uint64, uint64) error { return nil }); err == nil {
			t.Fatal("invalid scan accepted", tc.width)
		}
	}
}

func FuzzPointerScan(f *testing.F) {
	f.Add([]byte("aaaaABCDabcdABCD"), uint64(0x44434241), false, uint16(3))
	f.Add([]byte("AAAAAAAAAAAA"), uint64(0x4141414141414141), true, uint16(4))
	f.Fuzz(func(t *testing.T, data []byte, value uint64, wide bool, split uint16) {
		if len(data) == 0 || len(data) > 1<<16 {
			return
		}
		width := 4
		if wide {
			width = 8
		} else {
			value &= 0xffffffff
		}
		at := int(split) % len(data)
		var ranges []Range
		if at > 0 {
			ranges = append(ranges, Range{Start: 0x1000, Length: uint64(at)})
		}
		ranges = append(ranges, Range{Start: 0x1000 + uint64(at), Length: uint64(len(data) - at), FileOffset: uint64(at)})
		layer, err := NewMapped(bufferSource(data), "oracle", ranges)
		if err != nil {
			t.Fatal(err)
		}
		other := value ^ 0x11223344
		var expected, actual [][2]uint64
		for i := 0; i+width <= len(data); i++ {
			v := uint64(binary.LittleEndian.Uint32(data[i:]))
			if width == 8 {
				v = binary.LittleEndian.Uint64(data[i:])
			}
			if v == value || v == other {
				expected = append(expected, [2]uint64{0x1000 + uint64(i), v})
			}
		}
		err = ScanPointers(context.Background(), layer, []uint64{value, other}, width, func(a, v uint64) error { actual = append(actual, [2]uint64{a, v}); return nil })
		if err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatal(actual, expected, err)
		}
	})
}
