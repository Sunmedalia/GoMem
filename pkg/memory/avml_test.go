package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestAVMLIndependentRustEncoderFixture(t *testing.T) {
	encoded, err := os.ReadFile("testdata/fixture-mixed.avml")
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(encoded); hex.EncodeToString(got[:]) != "adadf9f8ae23e4dfcb04de9b33555dfbc2b0dfd0dbe543b01cf59b455630a27d" {
		t.Fatal("reference fixture drift")
	}
	layer, err := openAVML(context.Background(), bufferSource(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(layer.frames) != 3 || !layer.frames[0].compressed || layer.frames[1].compressed || layer.frames[2].compressed {
		t.Fatal("reference fixture no longer covers compressed and stored frames")
	}
	decoded, err := Read(context.Background(), layer, 0, 131195)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(decoded); hex.EncodeToString(got[:]) != "550b51ac23c162cec4ff1b1a306551f6451558c07ce447bd9833d7638ecea80b" {
		t.Fatal("independent reference output differs")
	}
	for _, start := range []uint64{0, 65530, 65536, 131068, 131194} {
		length := min(131195-int(start), 123)
		got, err := Read(context.Background(), layer, start, length)
		if err != nil || !bytes.Equal(got, decoded[start:start+uint64(length)]) {
			t.Fatal(start, err)
		}
	}
}

func avmlTestChunk(kind byte, data []byte) []byte {
	chunk := make([]byte, 4, len(data)+4)
	binary.LittleEndian.PutUint32(chunk, uint32(len(data))<<8|uint32(kind))
	return append(chunk, data...)
}

func avmlTestData(decoded, compressed []byte) []byte {
	crc := crc32.Checksum(decoded, snappyCRC)
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body, (crc>>15|crc<<17)+0xa282ead8)
	if compressed != nil {
		return avmlTestChunk(0, append(body, compressed...))
	}
	return avmlTestChunk(1, append(body, decoded...))
}

func avmlTestRegion(start, size uint64, chunks ...[]byte) []byte {
	h := make([]byte, 32)
	copy(h, "AVML")
	binary.LittleEndian.PutUint32(h[4:], 2)
	binary.LittleEndian.PutUint64(h[8:], start)
	binary.LittleEndian.PutUint64(h[16:], start+size-1)
	stream := avmlTestChunk(255, []byte("sNaPpY"))
	for _, c := range chunks {
		stream = append(stream, c...)
	}
	h = append(h, stream...)
	footer := make([]byte, 8)
	binary.LittleEndian.PutUint64(footer, uint64(len(stream)))
	return append(h, footer...)
}

func snappyTestLiteral(data []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(len(data)))
	if len(data) == 0 {
		return b
	}
	n := len(data) - 1
	if n < 60 {
		b = append(b, byte(n<<2))
	} else {
		width := 1
		for n>>(width*8) != 0 {
			width++
		}
		b = append(b, byte((59+width)<<2))
		for i := 0; i < width; i++ {
			b = append(b, byte(n>>(8*i)))
		}
	}
	return append(b, data...)
}

func TestAVMLRandomAccessFramesHolesAndEncoding(t *testing.T) {
	ctx := context.Background()
	compressed := []byte{7, 8, 'x', 'a', 'b', 1, 2}
	first := avmlTestRegion(0x1000, 12, avmlTestData([]byte("xababab"), compressed), avmlTestChunk(128, []byte("ignored")), avmlTestChunk(254, []byte{1, 2}), avmlTestChunk(255, []byte("sNaPpY")), avmlTestData([]byte("after"), nil))
	second := avmlTestRegion(0x2000, 3, avmlTestData([]byte("end"), nil))
	// Acquisition records can be out of physical order; the exposed address
	// ranges are sorted while their stored stream locations remain exact.
	layer, format, err := Detect(ctx, bufferSource(append(second, first...)))
	if err != nil || format != "avml" {
		t.Fatal(format, err)
	}
	ranges := layer.Ranges()
	if len(ranges) != 2 || ranges[0].Start != 0x1000 || ranges[0].Length != 12 || ranges[0].Encoding != "snappy-framed" || ranges[0].StoredLength == 0 || ranges[0].FileOffset != uint64(len(second)+32) {
		t.Fatal(ranges)
	}
	ranges[0].Length = 999
	if layer.Ranges()[0].Length != 12 {
		t.Fatal("range index was externally mutated")
	}
	for _, tc := range []struct {
		address uint64
		size    int
		want    string
	}{{0x1000, 12, "xabababafter"}, {0x1005, 5, "abaft"}, {0x2001, 2, "nd"}, {0x1000, 1, "x"}} {
		data, err := Read(ctx, layer, tc.address, tc.size)
		if err != nil || string(data) != tc.want {
			t.Fatal(tc, string(data), err)
		}
	}
	p := bytes.Repeat([]byte{0xcc}, 6)
	if n, err := layer.ReadAt(ctx, p, 0x100a); n != 2 || !errors.Is(err, ErrUnmapped) || string(p[:2]) != "er" || p[2] != 0xcc {
		t.Fatal("hole was silently zero-filled", n, p, err)
	}
	if _, err := NewMapped(bufferSource(first), "invalid", layer.Ranges()); err == nil {
		t.Fatal("encoded regions accepted as linear mappings")
	}
}

func TestAVMLCorruptCRCAndRawSnappyAreReadErrors(t *testing.T) {
	for _, corrupt := range []string{"crc", "payload", "copy", "trailing"} {
		t.Run(corrupt, func(t *testing.T) {
			good := avmlTestData([]byte("good"), nil)
			bad := avmlTestData([]byte("data"), snappyTestLiteral([]byte("data")))
			switch corrupt {
			case "crc":
				bad[4] ^= 1
			case "payload":
				bad[len(bad)-1] ^= 1
			case "copy":
				bad = avmlTestData([]byte("data"), []byte{4, 1, 0})
			case "trailing":
				bad = avmlTestData([]byte("data"), append(snappyTestLiteral([]byte("data")), 0))
			}
			layer, _, err := Detect(context.Background(), bufferSource(avmlTestRegion(0, 8, good, bad)))
			if err != nil {
				t.Fatal("bounded indexing should defer data verification", err)
			}
			data := make([]byte, 8)
			n, err := layer.ReadAt(context.Background(), data, 0)
			if n != 4 || err == nil || string(data[:4]) != "good" {
				t.Fatal(n, data, err)
			}
			var readError *ReadError
			if !errors.As(err, &readError) || readError.Address != 4 || readError.Layer != "physical:avml-v2" {
				t.Fatal("lost physical read-error context", err)
			}
			if _, err = Read(context.Background(), layer, 4, 1); err == nil {
				t.Fatal("corrupt frame was cached as valid")
			}
		})
	}
}

func TestAVMLStructuralBoundsAndTruncation(t *testing.T) {
	base := avmlTestRegion(0, 1, avmlTestData([]byte{'a'}, nil))
	for n := 4; n < len(base); n++ {
		if _, _, err := Detect(context.Background(), bufferSource(base[:n])); err == nil {
			t.Fatal("accepted truncated AVML", n)
		}
	}
	for _, name := range []string{"version", "reserved", "range", "overflow", "stream-id", "first-chunk", "unskippable", "frame-overrun", "huge-output", "no-crc", "trailer", "overlap", "trailing-garbage"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			switch name {
			case "version":
				data[4] = 1
			case "reserved":
				data[24] = 1
			case "range":
				binary.LittleEndian.PutUint64(data[8:], 2)
			case "overflow":
				binary.LittleEndian.PutUint64(data[16:], ^uint64(0))
			case "stream-id":
				data[36] = 'x'
			case "first-chunk":
				data[32] = 128
			case "unskippable":
				data = avmlTestRegion(0, 1, avmlTestChunk(2, nil), avmlTestData([]byte{'a'}, nil))
			case "frame-overrun":
				data = avmlTestRegion(0, 1, avmlTestData([]byte("ab"), nil))
			case "huge-output":
				data = avmlTestRegion(0, 65537, avmlTestData([]byte{'a'}, binary.AppendUvarint(nil, 65537)))
			case "no-crc":
				data = avmlTestRegion(0, 1, avmlTestChunk(1, []byte{1}))
			case "trailer":
				data[len(data)-8] ^= 1
			case "overlap":
				data = append(data, base...)
			case "trailing-garbage":
				data = append(data, 0)
			}
			if _, _, err := Detect(context.Background(), bufferSource(data)); err == nil {
				t.Fatal("invalid AVML accepted", name)
			}
		})
	}
	badEmpty := avmlTestData(nil, []byte{0})
	badEmpty[4] ^= 1
	if _, _, err := Detect(context.Background(), bufferSource(avmlTestRegion(0, 1, badEmpty, avmlTestData([]byte{'a'}, nil)))); err == nil {
		t.Fatal("unaddressable empty frame bypassed checksum verification")
	}
}

func TestSnappyLiteralAndAllCopyForms(t *testing.T) {
	for _, data := range [][]byte{{}, {'a'}, bytes.Repeat([]byte("xyz"), 22), bytes.Repeat([]byte{'a'}, 65536)} {
		got, err := decodeSnappy(context.Background(), snappyTestLiteral(data))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal(len(data), err)
		}
	}
	for _, copy := range [][]byte{{1, 2}, {14, 2, 0}, {15, 2, 0, 0, 0}} {
		raw := append([]byte{7, 8, 'x', 'a', 'b'}, copy...)
		got, err := decodeSnappy(context.Background(), raw)
		if err != nil || string(got) != "xababab" {
			t.Fatal(raw, string(got), err)
		}
	}
	for _, raw := range [][]byte{{}, {128}, {255, 255, 255, 255, 255}, {4, 1, 0}, {4, 1, 1}, {1, 240}, {1, 0}, {0, 0, 'a'}, {1, 244, 255, 255, 'a'}, {1, 3, 0, 0}} {
		if _, err := decodeSnappy(context.Background(), raw); err == nil {
			t.Fatal("invalid Snappy block accepted", raw)
		}
	}
	if got := crc32.Checksum([]byte("123456789"), snappyCRC); got != 0xe3069283 {
		t.Fatal("CRC32C polynomial differs", got)
	}
}

func TestAVMLCacheConcurrentAccessAndCancellation(t *testing.T) {
	var chunks [][]byte
	for i := 0; i < avmlCacheSize+2; i++ {
		chunks = append(chunks, avmlTestData([]byte{byte(i)}, nil))
	}
	data := avmlTestRegion(0, uint64(len(chunks)), chunks...)
	layer, err := openAVML(context.Background(), bufferSource(data))
	if err != nil {
		t.Fatal(err)
	}
	for i := range chunks {
		if _, err := Read(context.Background(), layer, uint64(i), 1); err != nil {
			t.Fatal(err)
		}
	}
	if layer.lru.Len() != avmlCacheSize || layer.cache[0] != nil {
		t.Fatal("cache did not evict the least recently used frame")
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Go(func() {
			for i := len(chunks) - 1; i >= 0; i-- {
				got, err := Read(context.Background(), layer, uint64(i), 1)
				if err != nil || got[0] != byte(i) {
					t.Error(i, got, err)
					return
				}
			}
		})
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, layer, 1, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("cached reads ignored cancellation", err)
	}
	if _, _, err := Detect(ctx, bufferSource(data)); !errors.Is(err, context.Canceled) {
		t.Fatal("indexing ignored cancellation", err)
	}
	if _, err := decodeSnappy(ctx, snappyTestLiteral([]byte("test"))); !errors.Is(err, context.Canceled) {
		t.Fatal("decoder ignored cancellation", err)
	}
	if _, err := layer.ReadAt(context.Background(), make([]byte, MaxRead+1), 0); err == nil {
		t.Fatal("oversized read accepted")
	}
	if _, err := layer.ReadAt(context.Background(), make([]byte, 1), ^uint64(0)); err == nil {
		t.Fatal("overflowing read accepted")
	}
}

func FuzzAVML(f *testing.F) {
	f.Add(avmlTestRegion(0, 4, avmlTestData([]byte("test"), nil)))
	f.Add(avmlTestRegion(0x1000, 7, avmlTestData([]byte("xababab"), []byte{7, 8, 'x', 'a', 'b', 1, 2})))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		layer, err := openAVML(context.Background(), bufferSource(data))
		if err != nil {
			return
		}
		var end uint64
		for i, r := range layer.Ranges() {
			if r.Length == 0 || r.Start > ^uint64(0)-r.Length || i > 0 && r.Start < end || r.FileOffset > uint64(len(data)) || r.StoredLength > uint64(len(data))-r.FileOffset || r.Encoding != "snappy-framed" {
				t.Fatal("invalid indexed region")
			}
			end = r.Start + r.Length
			_, _ = Read(context.Background(), layer, r.Start, int(min(r.Length, 256)))
		}
	})
}

func FuzzSnappyBlock(f *testing.F) {
	for _, raw := range [][]byte{{0}, snappyTestLiteral([]byte("test")), {7, 8, 'x', 'a', 'b', 1, 2}, {4, 1, 0}} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		decoded, err := decodeSnappy(context.Background(), raw)
		if err == nil {
			size, _, headerErr := snappyLength(raw)
			if headerErr != nil || len(decoded) != size || len(decoded) > snappyFrameSize {
				t.Fatal("Snappy output escaped declared bounds")
			}
		} else if strings.Contains(err.Error(), "runtime") {
			t.Fatal(err)
		}
	})
}
