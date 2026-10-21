package plugins

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type serviceSparseMemory struct {
	data  flatMemory
	spans []memory.Range
	reads int
}

func (m *serviceSparseMemory) Name() string           { return "service-sparse" }
func (m *serviceSparseMemory) Ranges() []memory.Range { return m.spans }
func (m *serviceSparseMemory) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	m.reads++
	end := a + uint64(len(p))
	cursor := a
	for _, span := range m.spans {
		if span.Start > cursor {
			break
		}
		if cursor >= span.Start && cursor < span.Start+span.Length {
			cursor = min(end, span.Start+span.Length)
		}
		if cursor == end {
			return m.data.ReadAt(ctx, p, a)
		}
	}
	return 0, memory.ErrUnmapped
}
func TestServiceResidentScanMatchesFullVADScan(t *testing.T) {
	rng := rand.New(rand.NewSource(37))
	for iteration := 0; iteration < 250; iteration++ {
		mem := &serviceSparseMemory{data: make(flatMemory, 32768)}
		for i := 0; i < 300; i++ {
			copy(mem.data[rng.Intn(len(mem.data)-4):], "serH")
		}
		// Explicitly include tags split across scanner blocks and range boundaries.
		copy(mem.data[4094:], "serH")
		copy(mem.data[8190:], "serH")
		for base := uint64(0); base < uint64(len(mem.data)); base += 1024 {
			if rng.Intn(4) != 0 {
				mem.spans = append(mem.spans, memory.Range{Start: base, Length: 1024})
			}
		}
		resident, err := serviceResidentRanges(context.Background(), mem)
		if err != nil {
			t.Fatal(err)
		}
		start := uint64(rng.Intn(500))
		size := uint64(len(mem.data)) - start - uint64(rng.Intn(2000))
		var want, got []uint64
		if err := scanServicePattern(context.Background(), mem, start, size, []byte("serH"), func(a uint64) error { want = append(want, a); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := scanResidentServicePattern(context.Background(), mem, resident, start, size, []byte("serH"), func(a uint64) error { got = append(got, a); return nil }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d start %#x size %#x: got %v want %v spans %v", iteration, start, size, got, want, mem.spans)
		}
	}
}
func TestServiceResidentScanSkipsHugeHoleAndKeepsBoundaryTag(t *testing.T) {
	mem := &serviceSparseMemory{data: make(flatMemory, 8192), spans: []memory.Range{{Length: 4096}, {Start: 4096, Length: 4096}}}
	copy(mem.data[4094:], "serH")
	resident, err := serviceResidentRanges(context.Background(), mem)
	if err != nil {
		t.Fatal(err)
	}
	var hits []uint64
	err = scanResidentServicePattern(context.Background(), mem, resident, 0, 1<<48, []byte("serH"), func(a uint64) error { hits = append(hits, a); return nil })
	if err != nil || !reflect.DeepEqual(hits, []uint64{4094}) || mem.reads != 2 {
		t.Fatal(hits, mem.reads, err)
	}
	failure := errors.New("output failure")
	if err = scanResidentServicePattern(context.Background(), mem, resident, 0, 8192, []byte("serH"), func(uint64) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = scanResidentServicePattern(ctx, mem, resident, 0, 8192, []byte("serH"), func(uint64) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = scanResidentServicePattern(context.Background(), mem, resident, math.MaxUint64-1, 5, []byte("serH"), func(uint64) error { return nil }); err == nil {
		t.Fatal("wrapped scan accepted")
	}
	for _, spans := range [][]memory.Range{{{Start: math.MaxUint64, Length: 2}}, {{Length: 20}, {Start: 10, Length: 20}}} {
		mem.spans = spans
		if _, err = serviceResidentRanges(context.Background(), mem); err == nil {
			t.Fatal("invalid index accepted")
		}
	}
}
