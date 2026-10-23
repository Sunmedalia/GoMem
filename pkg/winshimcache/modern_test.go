package winshimcache

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type modernLayer struct {
	data  []byte
	base  uint64
	holes []memory.Range
	reads int
}

func (l *modernLayer) Name() string { return "modern-fixture" }
func (l *modernLayer) Ranges() []memory.Range {
	return []memory.Range{{Start: l.base, Length: uint64(len(l.data))}}
}
func (l *modernLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.reads++
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at < l.base || at >= l.base+uint64(len(l.data)) {
		return 0, memory.ErrUnmapped
	}
	end := at + uint64(len(p))
	if end > l.base+uint64(len(l.data)) {
		end = l.base + uint64(len(l.data))
	}
	if end <= at {
		return 0, io.EOF
	}
	for _, hole := range l.holes {
		holeEnd := hole.Start + hole.Length
		if at < holeEnd && hole.Start < end {
			if hole.Start <= at {
				return 0, &memory.ReadError{Address: at, Length: len(p), Layer: l.Name(), Cause: memory.ErrUnmapped}
			}
			n := copy(p, l.data[at-l.base:hole.Start-l.base])
			return n, &memory.ReadError{Address: at, Length: len(p), Layer: l.Name(), Cause: memory.ErrUnmapped}
		}
	}
	n := copy(p, l.data[at-l.base:end-l.base])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func modernFixture(t testing.TB, width int, sectionName string, handles int) (*modernLayer, LoadedModule, ModuleSection, ModuleSection) {
	t.Helper()
	const (
		base       = uint64(0x100000)
		dataRVA    = uint64(0x1000)
		pageRVA    = uint64(0x3000)
		dataSize   = uint64(0x2000)
		pageSize   = uint64(0x1000)
		handleBase = uint64(0x400000)
	)
	data := make([]byte, 0x10000)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(data[0x86:], 2)
	binary.LittleEndian.PutUint16(data[0x88:], 0xe0)
	binary.LittleEndian.PutUint16(data[0x94:], 0x00e0)
	magic := uint16(0x20b)
	if width == 4 {
		magic = 0x10b
	}
	binary.LittleEndian.PutUint16(data[0x80+24:], magic)
	binary.LittleEndian.PutUint32(data[0x80+24+56:], 0x6000)
	table := 0x80 + 24 + 0xe0
	copy(data[table:table+8], ".data")
	binary.LittleEndian.PutUint32(data[table+8:], uint32(dataSize))
	binary.LittleEndian.PutUint32(data[table+12:], uint32(dataRVA))
	copy(data[table+40:table+48], "page")
	binary.LittleEndian.PutUint32(data[table+40+8:], uint32(pageSize))
	binary.LittleEndian.PutUint32(data[table+40+12:], uint32(pageRVA))
	put := func(offset, value uint64) {
		if width == 4 {
			binary.LittleEndian.PutUint32(data[offset:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(data[offset:], value)
		}
	}
	for i := 0; i < handles; i++ {
		put(dataRVA+0x100+uint64(i*width), handleBase+uint64(i)*0x1000)
	}
	layer := &modernLayer{data: data, base: base}
	module := LoadedModule{Offset: 0x2000, Base: base, Size: 0x6000, Name: "ahcache.sys"}
	dataSection := ModuleSection{ModuleOffset: module.Offset, ModuleBase: module.Base, Address: base + dataRVA, VirtualSize: dataSize, Name: ".data"}
	pageSection := ModuleSection{ModuleOffset: module.Offset, ModuleBase: module.Base, Address: base + pageRVA, VirtualSize: pageSize, Name: "PAGE"}
	if sectionName != "" {
		dataSection.Name = sectionName
	}
	return layer, module, dataSection, pageSection
}

func modernReader(t *testing.T, layer memory.MemoryLayer, width int, layout string) *HandleReader {
	t.Helper()
	raw, err := LayoutData(layout)
	if err != nil {
		t.Fatal(err)
	}
	kernelRaw, err := layoutKernel(width)
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := symbols.Parse(kernelRaw)
	if err != nil {
		t.Fatal(err)
	}
	mask := uint64(0xffffffffffff)
	if width == 4 {
		mask = 0xffffffff
	}
	reader, err := NewHandleReader(layer, raw, kernel, mask)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func modernMapped(layer memory.MemoryLayer) []memory.Range {
	if concrete, ok := layer.(*modernLayer); ok {
		return []memory.Range{{Start: concrete.base, Length: uint64(len(concrete.data))}}
	}
	return layer.Ranges()
}

func layoutKernel(width int) ([]byte, error) {
	raw, err := LayoutData("shimcache-win10-x64")
	if width == 4 {
		raw, err = LayoutData("shimcache-win10-x86")
	}
	if err != nil {
		return nil, err
	}
	var layout struct {
		Bases map[string]symbols.Type `json:"base_types"`
	}
	if err := json.Unmarshal(raw, &layout); err != nil {
		return nil, err
	}
	pointer := layout.Bases["pointer"]
	field := func(offset uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Offset: offset, Type: typ}
	}
	ptr := func(name string) symbols.TypeRef {
		return symbols.TypeRef{Kind: "pointer", Subtype: &symbols.TypeRef{Kind: "struct", Name: name}}
	}
	doc := map[string]any{
		"metadata":   map[string]any{"format": "6.2.0"},
		"base_types": map[string]any{"pointer": pointer, "unsigned int": map[string]any{"kind": "int", "size": 4, "endian": "little", "signed": false}},
		"user_types": map[string]any{
			"_ERESOURCE": map[string]any{"kind": "struct", "size": 128, "fields": map[string]any{
				"SystemResourcesList":   field(0, symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}),
				"SharedWaiters":         field(64, ptr("_KSEMAPHORE")),
				"NumberOfSharedWaiters": field(112, symbols.TypeRef{Kind: "base", Name: "unsigned int"}),
			}},
			"_LIST_ENTRY": map[string]any{"kind": "struct", "size": uint64(width * 2), "fields": map[string]any{"Flink": field(0, ptr("_LIST_ENTRY")), "Blink": field(uint64(width), ptr("_LIST_ENTRY"))}},
			"_KSEMAPHORE": map[string]any{"kind": "struct", "size": 32, "fields": map[string]any{}},
		},
		"symbols": map[string]any{},
		"enums":   map[string]any{},
	}
	return json.Marshal(doc)
}

func TestShimcacheReadModuleSectionCaseAndBounds(t *testing.T) {
	layer, module, _, _ := modernFixture(t, 8, "", 0)
	got, err := ReadModuleSection(context.Background(), layer, module, "PAGE")
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != module.Base+0x3000 || got.VirtualSize != 0x1000 {
		t.Fatalf("section = %+v", got)
	}
	if _, err := ReadModuleSection(context.Background(), layer, module, ".missing"); err == nil {
		t.Fatal("missing section accepted")
	}
	bad := module
	bad.Size = 0x1000
	if _, err := ReadModuleSection(context.Background(), layer, bad, ".data"); err == nil {
		t.Fatal("section outside module accepted")
	}
}

func TestShimcacheModernScannerRequiresExactSectionOwnership(t *testing.T) {
	layer, module, data, page := modernFixture(t, 8, "", 0)
	reader := modernReader(t, layer, 8, "shimcache-win10-x64")
	page.ModuleBase++
	_, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: 4}).Scan(context.Background())
	if err == nil {
		t.Fatal("section from another module accepted")
	}
}

func TestShimcacheModernScannerCountsAndEvidence(t *testing.T) {
	layer, module, data, page := modernFixture(t, 8, "", 1)
	reader := modernReader(t, layer, 8, "shimcache-win10-x64")
	// A canonical but unmapped non-null target is rejected without an object
	// probe. The remaining slots are zero and aggregate without evidence.
	binary.LittleEndian.PutUint64(layer.data[0x1100:], 0xfffff80400000000)
	data.Address += 0x100
	data.VirtualSize = 16 * 8
	got, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: 16, MaxEvidence: 16}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Scanned != 16 || got.NullPointers != 15 || got.Unmapped != 1 || len(got.Heads) != 0 || len(got.Evidence) != 0 {
		t.Fatalf("scan = %+v", got)
	}
}

func TestShimcacheModernScannerPrefiltersUnmappedCandidates(t *testing.T) {
	layer, module, data, page := modernFixture(t, 8, "", 0)
	reader := modernReader(t, layer, 8, "shimcache-win10-x64")
	// 0x1000 is canonical but outside the supplied mapped virtual run. It must
	// be counted as a prefilter rejection, with no object-read evidence.
	binary.LittleEndian.PutUint64(layer.data[0x1100:], 0x1000)
	data.Address += 0x100
	data.VirtualSize = 2 * 8
	got, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: 2, MaxEvidence: 2}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Scanned != 2 || got.Unmapped != 1 || got.NullPointers != 1 || len(got.Evidence) != 0 || got.ReadFailures != 0 {
		t.Fatalf("scan = %+v", got)
	}
}

type modernProbeLayer struct {
	memory.MemoryLayer
	reads int
}

func (l *modernProbeLayer) Name() string { return "modern-probe" }
func (l *modernProbeLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	l.reads++
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

func TestShimcacheModernScannerUsesUntracedProbe(t *testing.T) {
	layer, module, data, page := modernFixture(t, 8, "", 0)
	reader := modernReader(t, layer, 8, "shimcache-win10-x64")
	binary.LittleEndian.PutUint64(layer.data[0x1100:], 0x1000)
	data.Address += 0x100
	data.VirtualSize = 8
	traced := &modernProbeLayer{MemoryLayer: layer}
	probe := &modernProbeLayer{MemoryLayer: layer}
	got, err := (ModernScanner{
		Layer: traced, Probe: probe, Reader: reader, Module: module,
		Data: data, Page: page, MaxPointers: 1, MaxEvidence: 1,
	}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Unmapped != 1 || got.ReadFailures != 0 || probe.reads != 1 || traced.reads != 1 {
		t.Fatalf("scan=%+v probe=%d traced=%d", got, probe.reads, traced.reads)
	}
}

func TestShimcacheModernScannerCanonicalizesMaskedKernelPointer(t *testing.T) {
	layer, _, _, _ := modernFixture(t, 8, "", 0)
	reader := modernReader(t, layer, 8, "shimcache-win10-x64")
	const target = uint64(0xfffff80400000000)
	if canonicalizePointer(target&reader.mask, 8) != target {
		t.Fatalf("canonical pointer = %#x", canonicalizePointer(target&reader.mask, 8))
	}
}

func TestShimcacheModernScannerCancelBudgetAndReadFault(t *testing.T) {
	layer, module, data, page := modernFixture(t, 8, "", 0)
	reader := modernReader(t, layer, 8, "shimcache-win10-x64")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: 4}).Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: 1}).Scan(context.Background()); err == nil {
		t.Fatal("pointer budget accepted")
	}
	layer.holes = []memory.Range{{Start: data.Address + 8, Length: 8}}
	got, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: 8}).Scan(context.Background())
	if err == nil || got.ReadFailures == 0 || got.Scanned == 0 {
		t.Fatalf("read fault = %+v, %v", got, err)
	}
}

func TestShimcacheModernScannerChunkBoundary(t *testing.T) {
	layer, module, data, page := modernFixture(t, 8, "", 0)
	data.VirtualSize = 1<<20 + 0x20
	module.Size = 0x1000 + data.VirtualSize
	layer.data = make([]byte, module.Size)
	binary.LittleEndian.PutUint64(layer.data[0x1000+1<<20:], 0xfffff80400000000)
	reader := modernReader(t, layer, 8, "shimcache-win10-x64")
	got, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: (1<<20)/8 + 4}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Scanned != (1<<20)/8+4 || got.Unmapped != 1 || len(got.Evidence) != 0 {
		t.Fatalf("scan = %+v", got)
	}
}

func FuzzShimcacheModuleSection(f *testing.F) {
	layer, module, _, _ := modernFixture(f, 8, "", 0)
	f.Add(layer.data[:0x200])
	f.Fuzz(func(t *testing.T, mutation []byte) {
		data := append([]byte(nil), layer.data[:0x200]...)
		copy(data, mutation)
		broken := &modernLayer{data: data, base: layer.base}
		section, err := ReadModuleSection(context.Background(), broken, module, "PAGE")
		if err == nil && (section.VirtualSize == 0 || section.Address < module.Base || section.Address+section.VirtualSize > module.Base+module.Size) {
			t.Fatalf("accepted invalid section %+v", section)
		}
	})
}

func FuzzShimcacheModernScanner(f *testing.F) {
	layer, module, data, page := modernFixture(f, 8, "", 0)
	f.Add(layer.data[0x1000:0x1040], uint8(4))
	f.Fuzz(func(t *testing.T, mutation []byte, count uint8) {
		copy(layer.data[0x1000:0x1040], mutation)
		reader := modernReader(t, layer, 8, "shimcache-win10-x64")
		got, err := (ModernScanner{Layer: layer, Reader: reader, Module: module, Data: data, Page: page, MaxPointers: uint64(count%16 + 1)}).Scan(context.Background())
		if err == nil && got.Scanned == 0 {
			t.Fatal("successful scan examined no pointers")
		}
	})
}
