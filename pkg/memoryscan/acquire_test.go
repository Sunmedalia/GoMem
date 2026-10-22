package memoryscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type testLayer struct {
	data  []byte
	reads []memory.Range
	read  func(context.Context, []byte, uint64) (int, error)
}

func (l *testLayer) Name() string           { return "original-physical" }
func (l *testLayer) Ranges() []memory.Range { return []memory.Range{{Length: uint64(len(l.data))}} }
func (l *testLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.reads = append(l.reads, memory.Range{Start: at, Length: uint64(len(p))})
	if len(p) > memory.MaxRead {
		return 0, errors.New("oversized read")
	}
	if l.read != nil {
		return l.read(ctx, p, at)
	}
	if at >= uint64(len(l.data)) {
		return 0, io.EOF
	}
	n := copy(p, l.data[at:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func TestAcquireBoundedLargePhysicalPart(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 2, 255, 4, 5, 6}, (memory.MaxRead+8192)/7+1)
	data = data[:memory.MaxRead+4096]
	layer := &testLayer{data: data}
	chunk := memory.ScanChunk{End: 0x10000 + uint64(len(data)), Parts: []memory.ScanPart{{Virtual: 0x10000, Physical: 0, Length: uint64(len(data))}}}
	got, err := Acquire(context.Background(), layer, chunk)
	if err != nil || !got.Complete || !bytes.Equal(got.Data, data) || got.Base != 0x10000 || len(got.Parts) != 1 || got.Parts[0].SHA256 != digest(data) {
		t.Fatal("large read correspondence", err)
	}
	want := []memory.Range{{Start: 0, Length: memory.MaxRead}, {Start: memory.MaxRead, Length: 4096}}
	if !reflect.DeepEqual(layer.reads, want) {
		t.Fatal(layer.reads)
	}
	sources, err := got.Sources(memory.MaxRead-2, memory.MaxRead+3)
	if err != nil || !reflect.DeepEqual(sources, []Source{{Virtual: 0x10000 + memory.MaxRead - 2, Physical: memory.MaxRead - 2, Length: 5}}) {
		t.Fatal(sources, err)
	}
}

func TestAcquireFailureKeepsActualSourceAndScannerCoordinatesDistinct(t *testing.T) {
	layer := &testLayer{data: []byte("AAAAbbbbCCCC")}
	fault := errors.New("missing acquisition page")
	layer.read = func(_ context.Context, p []byte, at uint64) (int, error) {
		if at == 4 {
			copy(p, layer.data[4:6])
			return 2, fault
		}
		return copy(p, layer.data[at:]), nil
	}
	chunk := memory.ScanChunk{End: 1012, Parts: []memory.ScanPart{{Virtual: 1000, Physical: 0, Length: 4}, {Virtual: 1004, Physical: 4, Length: 4}, {Virtual: 1008, Physical: 8, Length: 4}}}
	got, err := Acquire(context.Background(), layer, chunk)
	if !errors.Is(err, fault) || got.Complete || string(got.Data) != "AAAACCCC" || got.Base != 1004 || len(got.Parts) != 3 {
		t.Fatal(got, err)
	}
	failed := got.Parts[1]
	if failed.Complete || failed.Captured != 2 || failed.SHA256 != digest([]byte("bb")) || !errors.Is(failed.Error, fault) {
		t.Fatal(failed)
	}
	sources, err := got.Sources(2, 6)
	want := []Source{{Offset: 0, Virtual: 1002, Physical: 2, Length: 2}, {Offset: 2, Virtual: 1008, Physical: 8, Length: 2}}
	if err != nil || !reflect.DeepEqual(sources, want) {
		t.Fatal(sources, err)
	}
	if sources[0].Virtual == got.Base+2 {
		t.Fatal("inferred scanner coordinate presented as actual source")
	}
}

func TestAcquireFaultsAndCancellation(t *testing.T) {
	for _, name := range []string{"short-nil", "negative-count", "excess-count", "cancel", "second-read-fault"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			layer := &testLayer{}
			size := uint64(8)
			if name == "second-read-fault" {
				size = memory.MaxRead + 2
			}
			fault := errors.New("fault")
			layer.read = func(_ context.Context, p []byte, at uint64) (int, error) {
				switch name {
				case "short-nil":
					copy(p, []byte("prefix"))
					return 6, nil
				case "negative-count":
					return -1, nil
				case "excess-count":
					return len(p) + 1, nil
				case "cancel":
					cancel()
					return len(p), nil
				case "second-read-fault":
					if at > 0 {
						return 1, fault
					}
					for i := range p {
						p[i] = 0x5a
					}
					return len(p), nil
				}
				panic("unreachable")
			}
			got, err := Acquire(ctx, layer, memory.ScanChunk{End: size, Parts: []memory.ScanPart{{Length: size}}})
			if err == nil || got.Complete || len(got.Data) != 0 || len(got.Parts) != 1 || got.Parts[0].Complete {
				t.Fatal(got, err)
			}
			if name == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if name == "second-read-fault" && (got.Parts[0].Captured != memory.MaxRead+1 || !errors.Is(err, fault) || len(layer.reads) != 2) {
				t.Fatal(got.Parts, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	layer := &testLayer{}
	if _, err := Acquire(ctx, layer, memory.ScanChunk{}); !errors.Is(err, context.Canceled) || len(layer.reads) != 0 {
		t.Fatal("read after cancellation", err)
	}
}

func TestAcquireValidatesWholePlanBeforeRead(t *testing.T) {
	for _, chunk := range []memory.ScanChunk{
		{End: 1, Parts: []memory.ScanPart{{Length: 0}}},
		{End: 100, Parts: []memory.ScanPart{{Length: 1}, {Length: memory.MaxScanChunk}}},
		{End: 1, Parts: []memory.ScanPart{{Virtual: 1, Length: 1}}},
		{End: 1, Parts: []memory.ScanPart{{Length: 1}, {Length: 1}}},
		{End: 10, Parts: []memory.ScanPart{{Physical: ^uint64(0), Length: 1}}},
		{End: ^uint64(0), Parts: []memory.ScanPart{{Virtual: ^uint64(0), Length: 1}}},
		{Parts: make([]memory.ScanPart, 4097)},
	} {
		layer := &testLayer{}
		if _, err := Acquire(context.Background(), layer, chunk); err == nil || len(layer.reads) != 0 {
			t.Fatal("invalid plan read source", err)
		}
	}
	got, err := Acquire(context.Background(), &testLayer{}, memory.ScanChunk{})
	if err != nil || !got.Complete || len(got.Data) != 0 || len(got.Parts) != 0 || got.Base != 0 {
		t.Fatal(got, err)
	}
	if sources, err := got.Sources(0, 0); err != nil || sources == nil || len(sources) != 0 {
		t.Fatal("empty match invented bytes", sources, err)
	}
	for _, span := range [][2]int{{-1, 0}, {1, 0}, {0, 1}} {
		if _, err := got.Sources(span[0], span[1]); err == nil {
			t.Fatal("invalid span", span)
		}
	}
}

func FuzzAcquireCorrespondence(f *testing.F) {
	f.Add([]byte("source bytes"), uint8(3), uint8(6))
	f.Fuzz(func(t *testing.T, data []byte, start, size uint8) {
		if len(data) > 1024 {
			return
		}
		at, length := uint64(start), uint64(size)+1
		layer := &testLayer{data: data}
		got, err := Acquire(context.Background(), layer, memory.ScanChunk{End: 4096 + length, Parts: []memory.ScanPart{{Virtual: 4096, Physical: at, Length: length}}})
		available := uint64(0)
		if at < uint64(len(data)) {
			available = min(length, uint64(len(data))-at)
		}
		if len(got.Parts) != 1 || got.Parts[0].Captured != available {
			t.Fatal("capture length")
		}
		var original []byte
		if available > 0 {
			original = data[at : at+available]
		}
		if got.Parts[0].SHA256 != digest(original) {
			t.Fatal("digest mismatch")
		}
		if available < length {
			if err == nil || got.Complete || len(got.Data) != 0 {
				t.Fatal("failed read became clean bytes")
			}
			return
		}
		if err != nil || !got.Complete || !bytes.Equal(got.Data, original) {
			t.Fatal("lost successful bytes", err)
		}
		sources, err := got.Sources(0, len(got.Data))
		if err != nil || !reflect.DeepEqual(sources, []Source{{Virtual: 4096, Physical: at, Length: length}}) {
			t.Fatal(sources, err)
		}
	})
}
