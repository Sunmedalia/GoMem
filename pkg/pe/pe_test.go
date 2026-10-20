package pe

import (
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type testLayer struct {
	base uint64
	data []byte
}

func (l testLayer) Name() string { return "synthetic-mapped-pe" }
func (l testLayer) Ranges() []memory.Range {
	return []memory.Range{{Start: l.base, Length: uint64(len(l.data))}}
}
func (l testLayer) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > memory.MaxRead {
		return 0, fmt.Errorf("oversized read")
	}
	if a < l.base || a-l.base >= uint64(len(l.data)) {
		return 0, io.EOF
	}
	n := copy(p, l.data[a-l.base:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func mappedPE(is64 bool) []byte {
	b := make([]byte, 0x4000)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[60:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	machine, magic, optional := uint16(0x14c), uint16(0x10b), uint16(224)
	if is64 {
		machine, magic, optional = 0x8664, 0x20b, 240
	}
	binary.LittleEndian.PutUint16(b[0x84:], machine)
	binary.LittleEndian.PutUint16(b[0x86:], 1)
	binary.LittleEndian.PutUint16(b[0x94:], optional)
	binary.LittleEndian.PutUint16(b[0x98:], magic)
	binary.LittleEndian.PutUint32(b[0x98+32:], 0x1000)
	binary.LittleEndian.PutUint32(b[0x98+36:], 0x200)
	binary.LittleEndian.PutUint32(b[0x98+56:], 0x4000)
	binary.LittleEndian.PutUint32(b[0x98+60:], 0x400)
	directories := 0x98 + 92
	if is64 {
		directories = 0x98 + 108
	}
	binary.LittleEndian.PutUint32(b[directories:], 16)
	section := 0x98 + int(optional)
	copy(b[section:], ".text")
	binary.LittleEndian.PutUint32(b[section+8:], 0x1200)
	binary.LittleEndian.PutUint32(b[section+12:], 0x1000)
	binary.LittleEndian.PutUint32(b[section+16:], 0x800)
	binary.LittleEndian.PutUint32(b[section+20:], 0x400)
	copy(b[0x1000:], "mapped-content")
	copy(b[0x3500:], "slack-retained")
	return b
}

func TestMemoryLayoutReconstructionPatchesAndSlack(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprint(is64), func(t *testing.T) {
			b := mappedPE(is64)
			before := append([]byte(nil), b...)
			base := uint64(0x400000)
			if is64 {
				base = 0x7ff812340000
			}
			source := testLayer{base, b}
			image, err := Plan(context.Background(), source, base)
			if err != nil || image.Size != 0x4000 || len(image.Patches) != 4 {
				t.Fatal(image, err)
			}
			rebuilt, err := memory.Read(context.Background(), image.Overlay(source), base, len(b))
			if err != nil {
				t.Fatal(err)
			}
			file, err := pe.NewFile(bytes.NewReader(rebuilt))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var actual uint64
			switch optional := file.OptionalHeader.(type) {
			case *pe.OptionalHeader32:
				actual = uint64(optional.ImageBase)
			case *pe.OptionalHeader64:
				actual = optional.ImageBase
			default:
				t.Fatal("invalid reconstructed optional header")
			}
			if actual != base || file.Sections[0].Offset != 0x1000 || file.Sections[0].Size != 0x2000 || file.Sections[0].VirtualSize != 0x2000 {
				t.Fatal(actual, file.Sections[0])
			}
			if string(rebuilt[0x1000:0x1000+14]) != "mapped-content" || string(rebuilt[0x3500:0x3500+14]) != "slack-retained" {
				t.Fatal("mapped bytes/slack were changed")
			}
			if !bytes.Equal(b, before) {
				t.Fatal("input acquisition was modified")
			}
			for _, patch := range image.Patches {
				if !bytes.Equal(b[patch.offset:patch.offset+uint64(len(patch.Original))], patch.Original) || !bytes.Equal(rebuilt[patch.offset:patch.offset+uint64(len(patch.Replacement))], patch.Replacement) {
					t.Fatal("patch provenance differs", patch)
				}
			}
		})
	}
}

func TestMalformedPEHeadersAndCancellation(t *testing.T) {
	for _, scenario := range []string{"signature", "nt-signature", "nt-overflow", "machine", "magic", "optional", "alignment-zero", "alignment-nonpower", "image-large", "header-bound", "section-rva", "section-size", "section-rounded", "truncated", "base-overflow"} {
		t.Run(scenario, func(t *testing.T) {
			b := mappedPE(true)
			base := uint64(0x400000)
			put := func(o int, v uint32) { binary.LittleEndian.PutUint32(b[o:], v) }
			switch scenario {
			case "signature":
				b[0] = 'X'
			case "nt-signature":
				b[0x80] = 'X'
			case "nt-overflow":
				put(60, 0xffffffff)
			case "machine":
				binary.LittleEndian.PutUint16(b[0x84:], 0xaa64)
			case "magic":
				binary.LittleEndian.PutUint16(b[0x98:], 0x10b)
			case "optional":
				binary.LittleEndian.PutUint16(b[0x94:], 64)
			case "alignment-zero":
				put(0x98+32, 0)
			case "alignment-nonpower":
				put(0x98+32, 0x1001)
			case "image-large":
				put(0x98+56, MaxImageSize+1)
			case "header-bound":
				put(0x98+60, 0x100)
			case "section-rva":
				put(0x188+12, 0x5000)
			case "section-size":
				put(0x188+8, 0x4000)
			case "section-rounded":
				put(0x188+12, 0x2800)
			case "truncated":
				b = b[:0x190]
			case "base-overflow":
				base = ^uint64(0) - 100
			}
			if image, err := Plan(context.Background(), testLayer{base, b}, base); err == nil {
				t.Fatal("malformed PE accepted", image)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Plan(ctx, testLayer{0x400000, mappedPE(true)}, 0x400000); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzMappedPEReconstruction(f *testing.F) {
	f.Add(mappedPE(false))
	f.Add(mappedPE(true))
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		source := testLayer{0x400000, data}
		image, err := Plan(context.Background(), source, source.base)
		if err != nil {
			return
		}
		if image.Size == 0 || image.Size > MaxImageSize || len(image.Patches) > 12289 {
			t.Fatal("unbounded PE plan")
		}
		for _, patch := range image.Patches {
			if patch.offset+uint64(len(patch.Replacement)) > image.Size || len(patch.Original) != len(patch.Replacement) {
				t.Fatal("invalid patch bounds")
			}
		}
	})
}
