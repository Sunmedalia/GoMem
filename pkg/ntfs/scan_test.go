package ntfs

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type sparseScanMemory struct {
	testMemory
	ranges []memory.Range
}

func (m sparseScanMemory) Ranges() []memory.Range { return m.ranges }
func (m sparseScanMemory) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	// Verify that a scan never fills a hole or crosses an unmapped interval.
	for i := range p {
		mapped := false
		for _, r := range m.ranges {
			if pos := at + uint64(i); pos >= r.Start && pos-r.Start < r.Length {
				mapped = true
				break
			}
		}
		if !mapped {
			return i, fmt.Errorf("scan read crossed a physical hole")
		}
	}
	return m.testMemory.ReadAt(ctx, p, at)
}

func TestScanPhysicalRangeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ranges []memory.Range
		want   []uint64
	}{
		{"adjacent-unsorted", []memory.Range{{Start: 4, Length: 12}, {Start: 0, Length: 4}}, []uint64{2, 10}},
		{"hole-breaks-signature", []memory.Range{{Start: 0, Length: 4}, {Start: 5, Length: 11}}, []uint64{10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make(testMemory, 16)
			copy(data[2:], "FILE0")
			copy(data[10:], "BAAD")
			var got []uint64
			err := Scan(context.Background(), sparseScanMemory{data, tc.ranges}, func(at uint64) error {
				got = append(got, at)
				return nil
			})
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("matches=%v error=%v; want %v", got, err, tc.want)
			}
		})
	}
}
