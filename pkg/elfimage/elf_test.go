package elfimage

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type testLayer struct {
	data  []byte
	base  uint64
	calls int
}

func (l *testLayer) Name() string           { return "elf-test" }
func (l *testLayer) Ranges() []memory.Range { return nil }
func (l *testLayer) ReadAt(ctx context.Context, b []byte, a uint64) (int, error) {
	l.calls++
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if a < l.base || a-l.base >= uint64(len(l.data)) {
		return 0, io.EOF
	}
	n := copy(b, l.data[a-l.base:])
	if n < len(b) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func header(class byte, order binary.ByteOrder, typ uint16, anchor uint64) []byte {
	b := make([]byte, 4096)
	copy(b, "\x7fELF")
	b[4] = class
	b[5] = 1
	b[6] = 1
	if order == binary.BigEndian {
		b[5] = 2
	}
	order.PutUint16(b[16:], typ)
	order.PutUint16(b[18:], 62)
	order.PutUint32(b[20:], 1)
	if class == 2 {
		order.PutUint64(b[24:], anchor+0x100)
		order.PutUint64(b[32:], 64)
		order.PutUint16(b[52:], 64)
		order.PutUint16(b[54:], 56)
		order.PutUint16(b[56:], 2)
		for i := 0; i < 2; i++ {
			p := b[64+i*56:]
			order.PutUint32(p, 1)
			order.PutUint32(p[4:], 5)
			order.PutUint64(p[8:], uint64(i)*4096)
			order.PutUint64(p[16:], anchor+uint64(i)*0x3000)
			order.PutUint64(p[32:], 100)
			order.PutUint64(p[40:], uint64(0x1001+i))
			order.PutUint64(p[48:], 4096)
		}
	} else {
		order.PutUint32(b[24:], uint32(anchor+0x100))
		order.PutUint32(b[28:], 52)
		order.PutUint16(b[40:], 52)
		order.PutUint16(b[42:], 32)
		order.PutUint16(b[44:], 2)
		for i := 0; i < 2; i++ {
			p := b[52+i*32:]
			order.PutUint32(p, 1)
			order.PutUint32(p[4:], uint32(i)*4096)
			order.PutUint32(p[8:], uint32(anchor)+uint32(i)*0x3000)
			order.PutUint32(p[16:], 100)
			order.PutUint32(p[20:], uint32(0x1001+i))
			order.PutUint32(p[24:], 5)
			order.PutUint32(p[28:], 4096)
		}
	}
	return b
}

func TestELFPlansAgreeWithStandardParserAndActualLoadAddresses(t *testing.T) {
	for _, class := range []byte{1, 2} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			for _, typ := range []uint16{2, 3} {
				anchor := uint64(0x400000)
				base := anchor
				if typ == 3 {
					anchor = 0x2000
					base = 0x7f000000
				}
				data := header(class, order, typ, anchor)
				independent, err := elf.NewFile(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				layer := &testLayer{data: data, base: base}
				image, err := Parse(context.Background(), layer, base)
				if err != nil {
					t.Fatal(err)
				}
				if len(image.Segments) != len(independent.Progs) || uint16(independent.Type) != image.Type || independent.Entry != image.Entry {
					t.Fatal(image)
				}
				for i, s := range image.Segments {
					p := independent.Progs[i]
					if s.Vaddr != p.Vaddr || s.FileSize != p.Filesz || s.MemorySize != p.Memsz || s.Offset != p.Off || s.Align != p.Align || s.Flags != uint32(p.Flags) {
						t.Fatal("independent header interpretation differs", s, p)
					}
				}
				plan, err := image.Plan(Mapped, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				if len(plan.Spans) != 2 || plan.Size != 0x4000 || plan.Spans[0].Source != base || plan.Spans[1].Source != base+0x3000 || plan.Spans[1].Offset != 0x2000 {
					t.Fatal(plan)
				}
				ref, err := image.Plan(Reference, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				if ref.Spans[0].Source != base+anchor || ref.Spans[1].Source != base+anchor+0x3000 {
					t.Fatal("baseline address arithmetic changed", ref)
				}
				if _, err = image.Plan(Mapped, 0x3fff); err == nil {
					t.Fatal("total limit ignored")
				}
			}
		}
	}
}

func TestInvalidELFHeadersNeverCreatePlans(t *testing.T) {
	for _, fault := range []string{"magic", "class", "data", "ident-version", "type", "version", "ehsize", "entsize", "zero-count", "extended-count", "many-count", "phoff-small", "phoff-large", "filesz", "wrap", "align", "congruence", "no-load", "truncated-header", "truncated-table"} {
		t.Run(fault, func(t *testing.T) {
			b := header(2, binary.LittleEndian, 2, 0x400000)
			u16 := binary.LittleEndian.PutUint16
			u64 := binary.LittleEndian.PutUint64
			switch fault {
			case "magic":
				b[0] = 0
			case "class":
				b[4] = 3
			case "data":
				b[5] = 0
			case "ident-version":
				b[6] = 0
			case "type":
				u16(b[16:], 1)
			case "version":
				b[20] = 2
			case "ehsize":
				u16(b[52:], 63)
			case "entsize":
				u16(b[54:], 55)
			case "zero-count":
				u16(b[56:], 0)
			case "extended-count":
				u16(b[56:], 0xffff)
			case "many-count":
				u16(b[56:], 4097)
			case "phoff-small":
				u64(b[32:], 63)
			case "phoff-large":
				u64(b[32:], 16<<20+1)
			case "filesz":
				u64(b[64+32:], 0x2000)
			case "wrap":
				u64(b[64+16:], ^uint64(0)-10)
			case "align":
				u64(b[64+48:], 3)
			case "congruence":
				u64(b[64+8:], 1)
			case "no-load":
				b[64] = 0
				b[120] = 0
			case "truncated-header":
				b = b[:40]
			case "truncated-table":
				b = b[:130]
			}
			if _, err := Parse(context.Background(), &testLayer{data: b, base: 0x400000}, 0x400000); err == nil {
				t.Fatal("accepted invalid ELF", fault)
			}
		})
	}
}

func TestELFPlanDuplicateZeroAndOverflowSemantics(t *testing.T) {
	if _, err := Parse(context.Background(), &testLayer{data: header(2, binary.LittleEndian, 3, 0), base: ^uint64(0) - 7}, ^uint64(0)-7); err == nil {
		t.Fatal("overflowing header read accepted")
	}
	image, err := Parse(context.Background(), &testLayer{data: header(2, binary.LittleEndian, 3, 0), base: 0x1000}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	original := image.Segments[0]
	image.Segments = append(image.Segments, Segment{Index: 2, Vaddr: 0x200, MemorySize: 100, FileSize: 100})
	p, err := image.Plan(Mapped, 1<<20)
	if err != nil || len(p.Spans) != 2 || p.Spans[0].Segment.Index != 2 || p.Spans[0].Size != 4096 {
		t.Fatal(p, err)
	}
	image.Segments = []Segment{original, {Index: 3, Vaddr: 0x3001}}
	p, err = image.Plan(Mapped, 1<<20)
	if err != nil || len(p.Spans) != 1 {
		t.Fatal(p, err)
	}
	p, err = image.Plan(Reference, 1<<20)
	if err != nil || len(p.Spans) != 2 || p.Spans[1].Size != 4096 {
		t.Fatal(p, err)
	}
	image.Segments = []Segment{{Index: 4, Vaddr: 0x2000}}
	if _, err = image.Plan(Reference, 1<<20); err == nil {
		t.Fatal("empty output accepted")
	}
	image.Segments = []Segment{original, {Vaddr: ^uint64(0) - 4095, MemorySize: 1}}
	if _, err = image.Plan(Reference, 1<<20); err == nil {
		t.Fatal("overflow accepted")
	}
	image.Segments = []Segment{original}
	image.Base = 0x2000
	image.Type = 2
	if _, err = image.Plan(Mapped, 1<<20); err == nil {
		t.Fatal("mismatched ET_EXEC base accepted")
	}
	image.Segments = []Segment{original, original}
	image.Type = 3
	if _, err = image.Plan(Mapped, 1<<20); err == nil {
		t.Fatal("ambiguous header load accepted")
	}
	for _, args := range []struct {
		layout string
		max    uint64
	}{{"bad", 10}, {Mapped, 0}, {Mapped, MaxSize + 1}} {
		if _, err = image.Plan(args.layout, args.max); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Parse(ctx, &testLayer{data: header(2, binary.LittleEndian, 2, 0x400000)}, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzELFHeaders(f *testing.F) {
	f.Add(header(1, binary.LittleEndian, 2, 0x400000))
	f.Add(header(2, binary.LittleEndian, 3, 0))
	f.Add(header(2, binary.BigEndian, 3, 0x2000))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		l := &testLayer{data: b, base: 0x400000}
		image, err := Parse(context.Background(), l, l.base)
		if l.calls > 4 {
			t.Fatal("unbounded header reads", l.calls)
		}
		if err != nil {
			return
		}
		for _, layout := range []string{Mapped, Reference} {
			p, err := image.Plan(layout, 1<<20)
			if err != nil {
				continue
			}
			if p.Size == 0 || p.Size > 1<<20 || len(p.Spans) > MaxHeaders {
				t.Fatal(p)
			}
			var offset uint64
			for _, s := range p.Spans {
				if s.Offset != offset || s.Size == 0 || s.Size-1 > ^uint64(0)-s.Source {
					t.Fatal(s)
				}
				offset += s.Size
			}
			if offset != p.Size {
				t.Fatal(p)
			}
		}
	})
}
