package memory

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type bufferSource []byte

func (b bufferSource) Name() string { return "fixture" }
func (b bufferSource) Size() uint64 { return uint64(len(b)) }
func (b bufferSource) Close() error { return nil }
func (b bufferSource) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	if a > uint64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[a:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func raw(t testing.TB, b []byte) *Mapped {
	t.Helper()
	m, e := NewMapped(bufferSource(b), "physical", []Range{{0, uint64(len(b)), 0}})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestMappedHolesAndBounds(t *testing.T) {
	b := bufferSource("abcdefghijklmnop")
	m, e := NewMapped(b, "sparse", []Range{{0x1000, 4, 0}, {0x1004, 4, 8}, {0x2000, 4, 4}})
	if e != nil {
		t.Fatal(e)
	}
	got, e := Read(context.Background(), m, 0x1002, 6)
	if e != nil || string(got) != "cdijkl" {
		t.Fatalf("%q %v", got, e)
	}
	p := make([]byte, 8)
	n, e := m.ReadAt(context.Background(), p, 0x1004)
	if n != 4 || !errors.Is(e, ErrUnmapped) {
		t.Fatalf("n=%d err=%v", n, e)
	}
	if _, e = NewMapped(b, "bad", []Range{{0, 10, 0}, {9, 2, 0}}); e == nil {
		t.Fatal("accepted overlap")
	}
	if _, e = NewMapped(b, "bad", []Range{{^uint64(0), 4, 0}}); e == nil {
		t.Fatal("accepted overflow")
	}
	if _, e = Read(context.Background(), m, 0, -1); e == nil {
		t.Fatal("accepted negative length")
	}
}
func TestPagingModes(t *testing.T) {
	for _, mode := range []string{"x64", "pae", "x86"} {
		t.Run(mode, func(t *testing.T) {
			b := make([]byte, 64<<10)
			put := func(a, v uint64) { binary.LittleEndian.PutUint64(b[a:], v) }
			root := uint64(0x1000)
			switch mode {
			case "x64":
				put(0x1000, 0x2003)
				put(0x2000, 0x3003)
				put(0x3000, 0x4003)
				put(0x4000, 0x8003)
				put(0x4008, 0x9003)
			case "pae":
				put(0x1000, 0x2001)
				put(0x2000, 0x3003)
				put(0x3000, 0x8003)
				put(0x3008, 0x9003)
			case "x86":
				binary.LittleEndian.PutUint32(b[0x1000:], 0x2003)
				binary.LittleEndian.PutUint32(b[0x2000:], 0x8003)
				binary.LittleEndian.PutUint32(b[0x2004:], 0x9003)
			}
			copy(b[0x8ffe:], "ABCD")
			p := raw(t, b)
			tr, e := NewIntel(p, root, mode, 2)
			if e != nil {
				t.Fatal(e)
			}
			v := &Virtual{Physical: p, Translator: tr, ID: mode}
			got, e := Read(context.Background(), v, 0xffe, 4)
			if e != nil || string(got) != "ABCD" {
				t.Fatalf("%q %v", got, e)
			}
			if _, e = tr.Translate(context.Background(), 0x2000); !errors.Is(e, ErrUnmapped) {
				t.Fatalf("missing page: %v", e)
			}
			if _, e = tr.Translate(context.Background(), 0x0001000000000000); e == nil {
				t.Fatal("accepted invalid address")
			}
		})
	}
}
func TestHugePagesAndPermissions(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		shift uint
		want  uint64
	}{{"x64", 30, 0x40001234}, {"x64", 21, 0x201234}, {"pae", 21, 0x201234}, {"x86", 22, 0x401234}} {
		t.Run(tc.mode+string(rune(tc.shift)), func(t *testing.T) {
			b := make([]byte, 0x5000)
			put := func(a, v uint64) { binary.LittleEndian.PutUint64(b[a:], v) }
			if tc.mode == "x86" {
				binary.LittleEndian.PutUint32(b[0x1000:], 0x400081)
			} else {
				put(0x1000, 0x2003)
				if tc.shift == 30 {
					put(0x2000, 0x40000081|(1<<63))
				} else {
					if tc.mode == "x64" {
						put(0x2000, 0x3003)
						put(0x3000, 0x200081|(1<<63))
					} else {
						put(0x2000, 0x200081|(1<<63))
					}
				}
			}
			tr, e := NewIntel(raw(t, b), 0x1000, tc.mode, 4)
			if e != nil {
				t.Fatal(e)
			}
			got, e := tr.Translate(context.Background(), 0x1234)
			if e != nil || got.Physical != tc.want || got.Writable {
				t.Fatalf("%+v %v", got, e)
			}
			if tc.mode != "x86" && got.Executable {
				t.Fatal("NX lost")
			}
		})
	}
}
func TestCanonicalHighAndCancellation(t *testing.T) {
	b := make([]byte, 0x5000)
	binary.LittleEndian.PutUint64(b[0x1000+511*8:], 0x2003)
	binary.LittleEndian.PutUint64(b[0x2000+510*8:], 0x83)
	tr, _ := NewIntel(raw(t, b), 0x1000, "x64", 4)
	v, e := tr.Translate(context.Background(), 0xffffffff80001234)
	if e != nil || v.Physical != 0x1234 {
		t.Fatalf("%+v %v", v, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = tr.Translate(ctx, 0); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestLimeAndCrash(t *testing.T) {
	b := make([]byte, 32+4096)
	binary.LittleEndian.PutUint32(b, 0x4c694d45)
	binary.LittleEndian.PutUint32(b[4:], 1)
	binary.LittleEndian.PutUint64(b[8:], 0x4000)
	binary.LittleEndian.PutUint64(b[16:], 0x4fff)
	copy(b[32:], "evidence")
	l, f, e := Detect(context.Background(), bufferSource(b))
	if e != nil || f != "lime" {
		t.Fatal(f, e)
	}
	got, e := Read(context.Background(), l, 0x4000, 8)
	if e != nil || string(got) != "evidence" {
		t.Fatalf("%q %v", got, e)
	}
	if _, _, e = Detect(context.Background(), bufferSource(b[:len(b)-1])); e == nil {
		t.Fatal("accepted truncated LiME")
	}
	for _, is64 := range []bool{false, true} {
		size, desc, at, stride := 4096, 100, 3976, 8
		if is64 {
			size, desc, at, stride = 8192, 136, 3992, 16
		}
		dump := make([]byte, size+4096)
		copy(dump, "PAGEDUMP")
		if is64 {
			copy(dump, "PAGEDU64")
		}
		binary.LittleEndian.PutUint32(dump[at:], 1)
		binary.LittleEndian.PutUint32(dump[desc:], 1)
		if stride == 8 {
			binary.LittleEndian.PutUint32(dump[desc+8:], 3)
			binary.LittleEndian.PutUint32(dump[desc+12:], 1)
		} else {
			binary.LittleEndian.PutUint64(dump[desc+16:], 3)
			binary.LittleEndian.PutUint64(dump[desc+24:], 1)
		}
		copy(dump[size:], "crash")
		if is64 {
			binary.LittleEndian.PutUint32(dump[48:], 0x8664)
			binary.LittleEndian.PutUint64(dump[16:], 0x12345000)
			binary.LittleEndian.PutUint64(dump[32:], 0xfffff80012345678)
		} else {
			binary.LittleEndian.PutUint32(dump[32:], 0x14c)
			binary.LittleEndian.PutUint32(dump[16:], 0x12345000)
			dump[92] = 1
		}
		l, f, e := Detect(context.Background(), bufferSource(dump))
		if e != nil || f != "crash" {
			t.Fatal(f, e)
		}
		header := l.(interface{ CrashHeader() CrashHeader }).CrashHeader()
		if header.DirectoryTableBase != 0x12345000 || is64 && header.Architecture != "x64" || !is64 && header.Architecture != "pae" {
			t.Fatal(header)
		}
		got, e := Read(context.Background(), l, 0x3000, 5)
		if e != nil || string(got) != "crash" {
			t.Fatal(string(got), e)
		}
	}
}
func TestBitmapCrash(t *testing.T) {
	b := make([]byte, 8192+4096+8192)
	copy(b, "PAGEDU64")
	binary.LittleEndian.PutUint32(b[3992:], 5)
	copy(b[8192:], "SDMPDUMP")
	binary.LittleEndian.PutUint64(b[8192+32:], 12288)
	binary.LittleEndian.PutUint64(b[8192+40:], 2)
	binary.LittleEndian.PutUint64(b[8192+48:], 8)
	b[8192+56] = 0b00001010
	copy(b[12288:], "one")
	copy(b[16384:], "three")
	l, _, e := Detect(context.Background(), bufferSource(b))
	if e != nil {
		t.Fatal(e)
	}
	got, e := Read(context.Background(), l, 0x3000, 5)
	if e != nil || string(got) != "three" {
		t.Fatal(string(got), e)
	}
	if _, e = Read(context.Background(), l, 0x2000, 1); !errors.Is(e, ErrUnmapped) {
		t.Fatal(e)
	}
}

func TestELFPhysicalCoreDoesNotInventZeroPages(t *testing.T) {
	b := make([]byte, 128)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(b[16:], 4)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	p := b[64:]
	binary.LittleEndian.PutUint32(p, 1)
	binary.LittleEndian.PutUint32(p[4:], 4)
	binary.LittleEndian.PutUint64(p[8:], 120)
	binary.LittleEndian.PutUint64(p[16:], 0x9000)
	binary.LittleEndian.PutUint64(p[24:], 0x9000)
	binary.LittleEndian.PutUint64(p[32:], 8)
	binary.LittleEndian.PutUint64(p[40:], 16)
	binary.LittleEndian.PutUint64(p[48:], 1)
	copy(b[120:], "evidence")
	l, format, err := Detect(context.Background(), bufferSource(b))
	if err != nil || format != "elf" {
		t.Fatal(format, err)
	}
	got, err := Read(context.Background(), l, 0x9000, 8)
	if err != nil || string(got) != "evidence" {
		t.Fatal(string(got), err)
	}
	if _, err = Read(context.Background(), l, 0x9008, 1); !errors.Is(err, ErrUnmapped) {
		t.Fatal("ELF missing bytes were invented", err)
	}
	if _, _, err = Detect(context.Background(), bufferSource(b[:127])); err == nil {
		t.Fatal("accepted truncated ELF")
	}
}
func FuzzDetect(f *testing.F) {
	f.Add([]byte("raw data"))
	f.Add([]byte("PAGEDU64"))
	f.Add([]byte{0x45, 0x4d, 0x69, 0x4c})
	lime := make([]byte, 48)
	binary.LittleEndian.PutUint32(lime, 0x4c694d45)
	binary.LittleEndian.PutUint32(lime[4:], 1)
	binary.LittleEndian.PutUint64(lime[16:], 15)
	f.Add(lime)
	dump := make([]byte, 8192)
	copy(dump, "PAGEDUMP")
	binary.LittleEndian.PutUint32(dump[3976:], 1)
	binary.LittleEndian.PutUint32(dump[100:], 1)
	binary.LittleEndian.PutUint32(dump[112:], 1)
	f.Add(dump)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) == 0 || len(b) > 1<<20 {
			return
		}
		l, _, e := Detect(context.Background(), bufferSource(b))
		if e == nil {
			p := make([]byte, 8)
			_, _ = l.ReadAt(context.Background(), p, 0)
		}
	})
}
func BenchmarkPhysicalRead(b *testing.B) {
	data := bytes.Repeat([]byte{0x41}, 16<<20)
	l := raw(b, data)
	out := make([]byte, 1<<20)
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for b.Loop() {
		if _, e := l.ReadAt(context.Background(), out, 0); e != nil {
			b.Fatal(e)
		}
	}
}
