package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"testing"
)

type xenOracleCase struct {
	Name     string
	Raw      []byte
	SHA256   string
	Expected []struct {
		Address string
		Offset  uint64
		Size    uint64
		SHA256  string
	}
	Locations map[string]uint64
	Upstream  struct {
		Error         string
		SegmentsCount int `json:"segments_count"`
		Reads         []struct {
			Address string
			SHA256  string
		}
	}
}

func xenOracle(t testing.TB) []xenOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/xen-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Baseline string `json:"baseline_commit"`
		Cases    []xenOracleCase
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 11 {
		t.Fatal("oracle drift")
	}
	return fixture.Cases
}
func TestXenCoreActualBaselineAndPhysicalBytes(t *testing.T) {
	for _, test := range xenOracle(t) {
		t.Run(test.Name, func(t *testing.T) {
			hash := sha256.Sum256(test.Raw)
			if hex.EncodeToString(hash[:]) != test.SHA256 {
				t.Fatal("fixture digest")
			}
			layer, format, err := Detect(context.Background(), bufferSource(test.Raw))
			if err != nil || format != "xen" {
				t.Fatal(format, err)
			}
			header := layer.(*XenLayer).XenHeader()
			if header.MappedPages != uint64(len(test.Expected)) || header.Pages != header.MappedPages+header.InvalidPages {
				t.Fatal(header)
			}
			var mappedBytes uint64
			for _, r := range layer.Ranges() {
				mappedBytes += r.Length
			}
			if mappedBytes != header.MappedPages*header.PageSize {
				t.Fatal("extra mappings", mappedBytes, header)
			}
			for _, expected := range test.Expected {
				address, err := strconv.ParseUint(expected.Address, 0, 64)
				if err != nil {
					t.Fatal(err)
				}
				data, err := Read(context.Background(), layer, address, int(expected.Size))
				if err != nil {
					t.Fatal(err)
				}
				actual := sha256.Sum256(data)
				if hex.EncodeToString(actual[:]) != expected.SHA256 || !bytes.Equal(data, test.Raw[expected.Offset:expected.Offset+expected.Size]) {
					t.Fatal("physical bytes differ", expected.Address)
				}
				if test.Name == "pfn-basic" || test.Name == "pfn-invalid32" || test.Name == "notes-pfn" {
					found := false
					for _, reference := range test.Upstream.Reads {
						if reference.Address == expected.Address && reference.SHA256 == expected.SHA256 {
							found = true
						}
					}
					if !found || test.Upstream.Error != "" {
						t.Fatal("actual pinned reader differs", expected.Address, test.Upstream)
					}
				}
			}
			if test.Name == "p2m-basic" || test.Name == "p2m-zero-invalid" {
				if test.Upstream.Error != "AttributeError" {
					t.Fatal("upstream P2M behavior changed")
				}
			}
			if test.Name == "pfn-basic" {
				data, err := Read(context.Background(), layer, 0x1fff, 2)
				if err != nil || !bytes.Equal(data, []byte{'A', 'B'}) {
					t.Fatal(data, err)
				}
				if _, err = Read(context.Background(), layer, 0x3000, 1); !errors.Is(err, ErrUnmapped) {
					t.Fatal("invented hole bytes", err)
				}
				if len(layer.Ranges()) != 2 {
					t.Fatal("adjacent frames not coalesced")
				}
			}
		})
	}
}

func xenSectionHeader(t testing.TB, raw []byte, name string) []byte {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for i, section := range f.Sections {
		if section.Name == name {
			offset := f.ByteOrder.Uint64(raw[40:]) + uint64(i)*64
			return raw[offset : offset+64]
		}
	}
	t.Fatal("missing section", name)
	return nil
}
func TestXenMalformedMetadataNeverFallsBack(t *testing.T) {
	cases := xenOracle(t)
	base := cases[6]
	mutations := map[string]func([]byte) []byte{
		"index-length": func(b []byte) []byte {
			h := xenSectionHeader(t, b, ".xen_pfn")
			binary.LittleEndian.PutUint64(h[32:], 7)
			return b
		},
		"pages-truncated": func(b []byte) []byte {
			h := xenSectionHeader(t, b, ".xen_pages")
			binary.LittleEndian.PutUint64(h[32:], 4096)
			return b
		},
		"pages-offset-overflow": func(b []byte) []byte {
			h := xenSectionHeader(t, b, ".xen_pages")
			binary.LittleEndian.PutUint64(h[24:], math.MaxUint64)
			return b
		},
		"pages-nobits": func(b []byte) []byte {
			h := xenSectionHeader(t, b, ".xen_pages")
			binary.LittleEndian.PutUint32(h[4:], uint32(elf.SHT_NOBITS))
			return b
		},
		"compressed": func(b []byte) []byte {
			h := xenSectionHeader(t, b, ".xen_pages")
			binary.LittleEndian.PutUint64(h[8:], uint64(elf.SHF_COMPRESSED))
			return b
		},
		"duplicate-section": func(b []byte) []byte {
			a := xenSectionHeader(t, b, ".xen_pfn")
			h := xenSectionHeader(t, b, ".xen_pages")
			copy(h[:4], a[:4])
			return b
		},
		"page-count-mismatch": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[base.Locations[".note.Xen"]+48:], 9); return b },
		"unsupported-page-size": func(b []byte) []byte {
			binary.LittleEndian.PutUint64(b[base.Locations[".note.Xen"]+56:], 4097)
			return b
		},
		"unsupported-version": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[base.Locations[".note.Xen"]+80:], 2); return b },
		"bad-core-magic":      func(b []byte) []byte { binary.LittleEndian.PutUint64(b[base.Locations[".note.Xen"]+32:], 0); return b },
		"bad-note-size": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[base.Locations[".note.Xen"]+4:], 0xffffffff)
			return b
		},
		"missing-header-note": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[base.Locations[".note.Xen"]+16+8:], 0x2000004)
			return b
		},
		"overlapping-frames": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[base.Locations[".xen_pfn"]+8:], 1); return b },
		"frame-overflow": func(b []byte) []byte {
			binary.LittleEndian.PutUint64(b[base.Locations[".xen_pfn"]:], math.MaxUint64-1)
			return b
		},
		"duplicate-note": func(b []byte) []byte {
			h := xenSectionHeader(t, b, ".note.Xen")
			binary.LittleEndian.PutUint64(h[32:], 112)
			return append(b, bytes.Clone(b[len(b)-24:])...)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw := mutate(bytes.Clone(base.Raw))
			if _, format, err := Detect(context.Background(), bufferSource(raw)); err == nil || format == "raw" {
				t.Fatal("malformed Xen accepted", format, err)
			}
		})
	}
	p2m := cases[5]
	raw := bytes.Clone(p2m.Raw)
	binary.LittleEndian.PutUint64(raw[p2m.Locations[".xen_p2m"]+8:], math.MaxUint64)
	if _, _, err := Detect(context.Background(), bufferSource(raw)); err == nil {
		t.Fatal("inconsistent P2M pair")
	}
}

type xenFaultSource struct {
	bufferSource
	offset uint64
	cause  error
	cancel context.CancelFunc
}

func (s xenFaultSource) ReadAt(ctx context.Context, p []byte, a uint64) (int, error) {
	if len(p) > MaxRead {
		return 0, fmt.Errorf("unbounded read")
	}
	if a == s.offset {
		if s.cancel != nil {
			s.cancel()
			return 0, context.Canceled
		}
		return 0, &ReadError{a, len(p), s.Name(), s.cause}
	}
	return s.bufferSource.ReadAt(ctx, p, a)
}
func TestXenReadFailuresAndCancellation(t *testing.T) {
	sample := xenOracle(t)[0]
	sentinel := errors.New("acquisition hole")
	source := xenFaultSource{bufferSource: sample.Raw, offset: sample.Locations[".xen_pfn"], cause: sentinel}
	if _, _, err := Detect(context.Background(), source); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	source.offset = sample.Locations[".xen_pages"]
	layer, _, err := Detect(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Read(context.Background(), layer, 4096, 1); !errors.Is(err, sentinel) {
		t.Fatal("lost page fault", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source.offset = sample.Locations[".xen_pfn"]
	source.cancel = cancel
	if _, _, err = Detect(ctx, source); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestELFMetadataBudgets(t *testing.T) {
	base := xenOracle(t)[0].Raw
	for _, kind := range []string{"huge-extended-count", "section-size", "table-outside", "string-index", "huge-names", "compressed-names", "long-name", "extended-program-count"} {
		t.Run(kind, func(t *testing.T) {
			raw := bytes.Clone(base)
			switch kind {
			case "huge-extended-count":
				binary.LittleEndian.PutUint16(raw[60:], 0)
				binary.LittleEndian.PutUint64(raw[64+32:], 1<<40)
			case "section-size":
				binary.LittleEndian.PutUint16(raw[58:], 0)
			case "table-outside":
				binary.LittleEndian.PutUint64(raw[40:], math.MaxUint64)
			case "string-index":
				binary.LittleEndian.PutUint16(raw[62:], 99)
			case "extended-program-count":
				binary.LittleEndian.PutUint16(raw[56:], 0xffff)
			case "long-name":
				header := xenSectionHeader(t, raw, ".shstrtab")
				offset := binary.LittleEndian.Uint64(header[24:])
				binary.LittleEndian.PutUint64(header[32:], 5000)
				for i := offset + 1; i < offset+5000; i++ {
					raw[i] = 'A'
				}
			case "compressed-names":
				binary.LittleEndian.PutUint64(xenSectionHeader(t, raw, ".shstrtab")[8:], uint64(elf.SHF_COMPRESSED))
			case "huge-names":
				binary.LittleEndian.PutUint64(xenSectionHeader(t, raw, ".shstrtab")[32:], math.MaxUint64)
			}
			if _, _, err := Detect(context.Background(), bufferSource(raw)); err == nil {
				t.Fatal("unbounded metadata accepted")
			}
		})
	}
}
func FuzzXenCore(f *testing.F) {
	for _, test := range xenOracle(f) {
		f.Add(test.Raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 256<<10 {
			return
		}
		layer, format, err := Detect(context.Background(), bufferSource(raw))
		if err != nil || format != "xen" {
			return
		}
		header := layer.(*XenLayer).XenHeader()
		if header.MappedPages == 0 || header.Pages < header.MappedPages {
			t.Fatal(header)
		}
		for _, r := range layer.Ranges() {
			if _, err := Read(context.Background(), layer, r.Start, 1); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestXenExtendedSectionCountAndNameIndex(t *testing.T) {
	original := xenOracle(t)[0].Raw
	const count = 65536
	position := (len(original) + 63) &^ 63
	raw := make([]byte, position+count*64)
	copy(raw, original)
	old := binary.LittleEndian.Uint64(original[40:])
	existing := int(binary.LittleEndian.Uint16(original[60:]))
	copy(raw[position:], original[old:old+uint64(existing*64)])
	// Move the names section to a reserved-range index, exercising SHN_XINDEX.
	copy(raw[position+65281*64:], raw[position+64:position+128])
	clear(raw[position+64 : position+128])
	binary.LittleEndian.PutUint64(raw[40:], uint64(position))
	binary.LittleEndian.PutUint16(raw[60:], 0)
	binary.LittleEndian.PutUint16(raw[62:], 0xffff)
	binary.LittleEndian.PutUint64(raw[position+32:], count)
	binary.LittleEndian.PutUint32(raw[position+40:], 65281)
	layer, format, err := Detect(context.Background(), bufferSource(raw))
	if err != nil || format != "xen" {
		t.Fatal(format, err)
	}
	data, err := Read(context.Background(), layer, 4096, 1)
	if err != nil || string(data) != "A" {
		t.Fatal(data, err)
	}
}
