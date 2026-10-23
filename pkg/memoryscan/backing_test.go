package memoryscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func backingScanFixture(t testing.TB, mode string) (*memory.Intel, []byte) {
	t.Helper()
	ram := make([]byte, 0x10000)
	width, levels, high := 8, 4, uint(32)
	if mode == "x86" {
		width, levels, high = 4, 2, 12
	} else if mode == "pae" {
		levels = 3
	}
	put := func(at int, value uint64) {
		if width == 4 {
			binary.LittleEndian.PutUint32(ram[at:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(ram[at:], value)
		}
	}
	for n := 1; n < levels; n++ {
		put(n*4096, uint64((n+1)*4096)|3)
	}
	put(levels*4096, 0x8003)
	put(levels*4096+width, uint64(2)<<high|128)
	put(levels*4096+2*width, 0x9003)
	file := make([]byte, 0x4000)
	for n := 0; n < 4096; n++ {
		ram[0x8000+n] = byte(n % 251)
		file[0x2000+n] = byte((n + 19) % 251)
		ram[0x9000+n] = byte((n + 41) % 251)
	}
	copy(ram[0x8ffe:], "AB")
	copy(file[0x2000:], "QZ")
	expected := append(append(append([]byte{}, ram[0x8000:0x9000]...), file[0x2000:0x3000]...), ram[0x9000:0xa000]...)
	physical, err := memory.WithPagefiles(&testLayer{data: ram}, map[uint8]memory.MemoryLayer{0: &testLayer{data: file}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := memory.NewIntelForOS(physical, 0x1000, mode, "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	return tr, expected
}

func TestBackingScanOverlapAcrossSourcesAndAttribution(t *testing.T) {
	for _, mode := range []string{"x64", "x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			tr, original := backingScanFixture(t, mode)
			for _, size := range []uint64{4096, 4097, 8192} {
				var starts []uint64
				var reconstructed []byte
				stats, err := VisitBackingChunks(context.Background(), tr, BackingScanOptions{Mappings: memory.BackingMapOptions{MaxTables: 10, MaxEntries: 10000}, ChunkSize: size, Overlap: 3, MaxChunks: 100}, func(chunk BackingChunk) error {
					buffer, err := AcquireBacking(context.Background(), chunk)
					if err != nil {
						return err
					}
					if !buffer.Complete || !bytes.Equal(buffer.Data, original[chunk.Start:chunk.Start+chunk.Length]) {
						t.Fatal("scan buffer differs from original virtual bytes", chunk)
					}
					reconstructed = append(reconstructed, buffer.Data[:chunk.PrimaryLength]...)
					for offset := 0; offset < len(buffer.Data); {
						n := bytes.Index(buffer.Data[offset:], []byte("ABQZ"))
						if n < 0 {
							break
						}
						at := uint64(offset + n)
						if buffer.Accepts(at, 4) {
							starts = append(starts, chunk.Start+at)
							sources, err := buffer.Sources(at, 4)
							if err != nil || len(sources) != 2 || sources[0].Pagefile != nil || sources[1].Pagefile == nil || *sources[1].Pagefile != 0 || sources[0].Offset != 0x8ffe || sources[1].Offset != 0x2000 || sources[0].Length != 2 || sources[1].Length != 2 {
								t.Fatal("lost cross-source correspondence", sources, err)
							}
						}
						offset += n + 1
					}
					for _, capture := range buffer.Captures {
						sum := sha256.Sum256(capture.Bytes)
						if capture.SHA256 != hex.EncodeToString(sum[:]) || !capture.Complete {
							t.Fatal(capture)
						}
					}
					return nil
				})
				if err != nil || stats.PrimaryBytes != uint64(len(original)) || !bytes.Equal(reconstructed, original) || len(starts) != 1 || starts[0] != 4094 {
					t.Fatal(mode, size, stats, starts, err)
				}
			}
		})
	}
}

func TestBackingAcquisitionFailsWithoutJoiningOrPadding(t *testing.T) {
	number := uint8(0)
	good := &testLayer{data: []byte("AB")}
	bad := &testLayer{data: []byte("CD"), read: func(_ context.Context, p []byte, _ uint64) (int, error) { p[0] = 'C'; return 1, io.ErrUnexpectedEOF }}
	chunk := BackingChunk{Start: 0x1000, Length: 4, PrimaryLength: 4, Parts: []memory.BackingMapping{{Virtual: 0x1000, Length: 2, Layer: good}, {Virtual: 0x1002, Length: 2, Pagefile: &number, Layer: bad}}}
	buffer, err := AcquireBacking(context.Background(), chunk)
	if !errors.Is(err, io.ErrUnexpectedEOF) || buffer.Complete || buffer.Data != nil || len(buffer.Captures) != 2 || string(buffer.Captures[0].Bytes) != "AB" || string(buffer.Captures[1].Bytes) != "C" || buffer.Captures[1].Captured != 1 || buffer.Captures[1].Complete || buffer.Accepts(0, 2) {
		t.Fatal(buffer, err)
	}
	if _, err := buffer.Sources(0, 1); err == nil {
		t.Fatal("failed buffer attributed as searchable")
	}
	// Header mutations after acquisition cannot change retained provenance.
	chunk.Parts[0].Offset = 999
	number = 15
	if buffer.Captures[0].Mapping.Offset != 0 || *buffer.Captures[1].Mapping.Pagefile != 0 || *buffer.Chunk.Parts[1].Pagefile != 0 {
		t.Fatal("caller changed retained capture identity")
	}
	for _, n := range []int{-1, 5} {
		layer := &testLayer{data: []byte("XX"), read: func(context.Context, []byte, uint64) (int, error) { return n, nil }}
		_, err := AcquireBacking(context.Background(), BackingChunk{Start: 0, Length: 2, PrimaryLength: 2, Parts: []memory.BackingMapping{{Length: 2, Layer: layer}}})
		if err == nil {
			t.Fatal("invalid reader count accepted", n)
		}
	}
}

func TestBackingScanGapsBudgetsAndCallbacks(t *testing.T) {
	tr, _ := backingScanFixture(t, "x64")
	options := BackingScanOptions{Mappings: memory.BackingMapOptions{MaxTables: 10, MaxEntries: 10000, Sections: []memory.Range{{Start: 0, Length: 4}, {Start: 8192, Length: 4}}}, ChunkSize: 4, Overlap: 1, MaxChunks: 10}
	var chunks []BackingChunk
	stats, err := VisitBackingChunks(context.Background(), tr, options, func(c BackingChunk) error { chunks = append(chunks, c); return nil })
	if err != nil || len(chunks) != 2 || chunks[0].Start != 0 || chunks[0].Length != 4 || chunks[1].Start != 8192 || stats.PrimaryBytes != 8 {
		t.Fatal(stats, chunks, err)
	}
	options.MaxChunks = 1
	if _, err := VisitBackingChunks(context.Background(), tr, options, func(BackingChunk) error { return nil }); err == nil {
		t.Fatal("chunk limit ignored")
	}
	options.MaxChunks = 10
	sentinel := errors.New("stop chunks")
	if _, err := VisitBackingChunks(context.Background(), tr, options, func(BackingChunk) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	count := 0
	_, err = VisitBackingChunks(ctx, tr, options, func(BackingChunk) error { count++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || count != 1 {
		t.Fatal(count, err)
	}
	// Retained mapping diagnostics cannot turn incomplete coverage into success.
	missing, _ := memory.NewIntelForOS(&testLayer{data: make([]byte, 4096)}, 0x1000, "x64", "windows", 4)
	options.Mappings.OnReadError = func(uint64, error) error { return nil }
	stats, err = VisitBackingChunks(context.Background(), missing, options, func(BackingChunk) error { t.Fatal("missing root scanned"); return nil })
	if !errors.Is(err, memory.ErrUnmapped) || stats.Mappings.Unavailable != 1 {
		t.Fatal(stats, err)
	}
}

func TestBackingAcquisitionCancellationAndPreflight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := &testLayer{data: []byte("AA"), read: func(_ context.Context, p []byte, _ uint64) (int, error) { copy(p, "AA"); cancel(); return len(p), nil }}
	second := &testLayer{data: []byte("BB")}
	chunk := BackingChunk{Length: 4, PrimaryLength: 4, Parts: []memory.BackingMapping{{Length: 2, Layer: first}, {Virtual: 2, Length: 2, Layer: second}}}
	buffer, err := AcquireBacking(ctx, chunk)
	if !errors.Is(err, context.Canceled) || buffer.Complete || buffer.Data != nil || len(second.reads) != 0 || len(buffer.Captures) != 1 || string(buffer.Captures[0].Bytes) != "AA" {
		t.Fatal(buffer, err)
	}
	for _, mode := range []string{"gap", "size", "source", "unknown", "overflow"} {
		layer := &testLayer{data: []byte("AA")}
		c := BackingChunk{Length: 2, PrimaryLength: 2, Parts: []memory.BackingMapping{{Length: 2, Layer: layer}}}
		switch mode {
		case "gap":
			c.Parts[0].Virtual = 1
		case "size":
			c.Parts[0].Length = 3
		case "source":
			c.Parts[0].Layer = nil
		case "unknown":
			c.Parts[0].Unresolved = true
		case "overflow":
			c.Parts[0].Offset = ^uint64(0)
		}
		if _, err := AcquireBacking(context.Background(), c); err == nil || len(layer.reads) != 0 {
			t.Fatal("invalid plan reached source I/O", mode, err)
		}
	}
}

func FuzzBackingScanSources(f *testing.F) {
	f.Add(uint16(4096), uint16(0), uint16(12287), uint8(0))
	f.Add(uint16(257), uint16(4090), uint16(100), uint8(1))
	f.Add(uint16(8191), uint16(0), uint16(12287), uint8(2))
	f.Fuzz(func(t *testing.T, size, start, length uint16, which uint8) {
		tr, original := backingScanFixture(t, []string{"x64", "x86", "pae"}[int(which)%3])
		lo := uint64(start) % uint64(len(original))
		count := 1 + uint64(length)%(uint64(len(original))-lo)
		var rebuilt []byte
		stats, err := VisitBackingChunks(context.Background(), tr, BackingScanOptions{Mappings: memory.BackingMapOptions{MaxTables: 10, MaxEntries: 100, Sections: []memory.Range{{Start: lo, Length: count}}}, ChunkSize: 256 + uint64(size)%8192, Overlap: 3, MaxChunks: 1000}, func(chunk BackingChunk) error {
			b, err := AcquireBacking(context.Background(), chunk)
			if err != nil {
				return err
			}
			if !bytes.Equal(b.Data, original[chunk.Start:chunk.Start+chunk.Length]) {
				t.Fatal("wrong virtual bytes")
			}
			rebuilt = append(rebuilt, b.Data[:chunk.PrimaryLength]...)
			sources, err := b.Sources(0, chunk.Length)
			if err != nil {
				return err
			}
			var sourceBytes []byte
			for _, source := range sources {
				data, err := memory.Read(context.Background(), source.Layer, source.Offset, int(source.Length))
				if err != nil {
					return err
				}
				sourceBytes = append(sourceBytes, data...)
			}
			if !bytes.Equal(sourceBytes, b.Data) {
				t.Fatal("wrong source correspondence")
			}
			return nil
		})
		if err != nil || stats.PrimaryBytes != count || !bytes.Equal(rebuilt, original[lo:lo+count]) {
			t.Fatal(stats, lo, count, err)
		}
	})
}
