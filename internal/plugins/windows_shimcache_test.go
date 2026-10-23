package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/winshimcache"
)

const (
	shimFixtureBase       = uint64(0x100000)
	shimFixtureModule     = uint64(0x2000)
	shimFixtureData       = uint64(0x1000)
	shimFixturePage       = uint64(0x3000)
	shimFixtureDataSize   = uint64(0x2000)
	shimFixturePageSize   = uint64(0x1000)
	shimFixtureHandleOne  = uint64(0x400000)
	shimFixtureHandleTwo  = uint64(0x500000)
	shimFixtureResource   = uint64(0x600000)
	shimFixtureAVLOne     = uint64(0x610000)
	shimFixtureAVLTwo     = uint64(0x620000)
	shimFixtureEntryOne   = uint64(0x630000)
	shimFixtureEntryTwo   = uint64(0x640000)
	shimFixtureEntryThree = uint64(0x650000)
)

func shimFixtureSymbols() *symbols.ISF {
	pointer := symbols.TypeRef{Kind: "pointer", Subtype: &symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}}
	genericPointer := symbols.TypeRef{Kind: "pointer", Subtype: &symbols.TypeRef{Kind: "base", Name: "void"}}
	u16 := symbols.TypeRef{Kind: "base", Name: "unsigned short"}
	u32 := symbols.TypeRef{Kind: "base", Name: "unsigned long"}
	u64 := symbols.TypeRef{Kind: "base", Name: "unsigned long long"}
	u8 := symbols.TypeRef{Kind: "base", Name: "unsigned char"}
	list := symbols.TypeRef{Kind: "struct", Name: "_LIST_ENTRY"}
	unicode := symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}
	large := symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}
	table := &symbols.ISF{
		Meta: map[string]json.RawMessage{
			"windows": json.RawMessage(`{"pe":{"major":10,"minor":0,"revision":19041,"build":1}}`),
		},
		Bases: map[string]symbols.Type{
			"pointer":            {Kind: "int", Size: 8, Endian: "little"},
			"unsigned char":      {Kind: "char", Size: 1, Endian: "little"},
			"unsigned short":     {Kind: "int", Size: 2, Endian: "little"},
			"unsigned long":      {Kind: "int", Size: 4, Endian: "little"},
			"unsigned long long": {Kind: "int", Size: 8, Endian: "little"},
			"unsigned int":       {Kind: "int", Size: 4, Endian: "little"},
			"long":               {Kind: "int", Size: 4, Endian: "little"},
			"long long":          {Kind: "int", Size: 8, Endian: "little", Signed: true},
			"void":               {Kind: "void", Size: 0, Endian: "little"},
		},
		Types: map[string]symbols.Type{
			"_LIST_ENTRY": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
				"Flink": {Type: pointer}, "Blink": {Offset: 8, Type: pointer},
			}},
			"_UNICODE_STRING": {Kind: "struct", Size: 16, Fields: map[string]symbols.Field{
				"Length": {Type: u16}, "MaximumLength": {Offset: 2, Type: u16}, "Buffer": {Offset: 8, Type: genericPointer},
			}},
			"_ERESOURCE": {Kind: "struct", Size: 128, Fields: map[string]symbols.Field{
				"SystemResourcesList":   {Type: list},
				"SharedWaiters":         {Offset: 64, Type: symbols.TypeRef{Kind: "pointer", Subtype: &symbols.TypeRef{Kind: "base", Name: "void"}}},
				"NumberOfSharedWaiters": {Offset: 112, Type: u32},
			}},
			"_KSEMAPHORE": {Kind: "struct", Size: 32, Fields: map[string]symbols.Field{}},
			"_LARGE_INTEGER": {Kind: "union", Size: 8, Fields: map[string]symbols.Field{
				"QuadPart": {Type: u64},
			}},
			"_KLDR_DATA_TABLE_ENTRY": {Kind: "struct", Size: 0x60, Fields: map[string]symbols.Field{
				"InLoadOrderLinks": {Type: list},
				"BaseDllName":      {Offset: 0x20, Type: unicode},
				"DllBase":          {Offset: 0x40, Type: genericPointer},
				"SizeOfImage":      {Offset: 0x48, Type: u32},
			}},
		},
		Symbols: map[string]symbols.Symbol{"PsLoadedModuleList": {Address: 0x80}},
	}
	_ = u8
	_ = large
	return table
}

func shimFixtureMemory() flatMemory {
	mem := make(flatMemory, 0x700000)
	copy(mem[shimFixtureBase:], "MZ")
	putU32(mem, shimFixtureBase+0x3c, 0x80)
	pe := shimFixtureBase + 0x80
	copy(mem[pe:], "PE\x00\x00")
	putU16(mem, pe+4, 0x8664)
	putU16(mem, pe+6, 2)
	putU16(mem, pe+20, 0xe0)
	putU16(mem, pe+24, 0x20b)
	putU32(mem, pe+24+56, 0x6000)
	sections := pe + 24 + 0xe0
	copy(mem[sections:], ".data")
	putU32(mem, sections+8, uint32(shimFixtureDataSize))
	putU32(mem, sections+12, uint32(shimFixtureData))
	copy(mem[sections+40:], "PAGE")
	putU32(mem, sections+40+8, uint32(shimFixturePageSize))
	putU32(mem, sections+40+12, uint32(shimFixturePage))
	putU64(mem, shimFixtureBase+shimFixtureData+0x100, shimFixtureHandleOne)
	putU64(mem, shimFixtureBase+shimFixtureData+0x108, shimFixtureHandleTwo)
	putU64(mem, shimFixtureHandleOne, shimFixtureResource)
	putU64(mem, shimFixtureHandleOne+8, shimFixtureAVLOne)
	putU64(mem, shimFixtureHandleTwo, shimFixtureResource)
	putU64(mem, shimFixtureHandleTwo+8, shimFixtureAVLTwo)
	for _, resource := range []uint64{shimFixtureResource} {
		putU64(mem, resource, shimFixtureBase+shimFixturePage)
		putU64(mem, resource+8, shimFixtureBase+shimFixturePage+8)
		putU64(mem, shimFixtureBase+shimFixturePage+8, resource)
		putU64(mem, shimFixtureBase+shimFixturePage, resource)
	}
	putU64(mem, shimFixtureAVLOne, shimFixtureAVLOne)
	putU64(mem, shimFixtureAVLOne+72, shimFixtureBase+shimFixturePage+8)
	putU64(mem, shimFixtureAVLOne+80, shimFixtureBase+shimFixturePage)
	putU64(mem, shimFixtureAVLOne+88, 0)
	putU64(mem, shimFixtureAVLTwo, shimFixtureAVLTwo)
	putU64(mem, shimFixtureAVLTwo+72, shimFixtureBase+shimFixturePage+8)
	putU64(mem, shimFixtureAVLTwo+80, shimFixtureBase+shimFixturePage)
	putU64(mem, shimFixtureAVLTwo+88, 0)
	// The scanner requires two valid handles. Link the first handle's head to
	// the same entries; Win10's layout choice still selects the second head.
	firstHead := shimFixtureAVLOne + 104
	putU64(mem, firstHead, shimFixtureEntryOne)
	putU64(mem, firstHead+8, shimFixtureEntryTwo)
	// Win10 selects the second head; its AVL size is 104, so the list sentinel
	// is at AVL+104. Two valid entries are linked before the sentinel.
	head := shimFixtureAVLTwo + 104
	putU64(mem, head, shimFixtureEntryOne)
	putU64(mem, head+8, shimFixtureEntryTwo)
	putU64(mem, shimFixtureEntryOne, shimFixtureEntryTwo)
	putU64(mem, shimFixtureEntryOne+8, head)
	putU64(mem, shimFixtureEntryTwo, head)
	putU64(mem, shimFixtureEntryTwo+8, shimFixtureEntryOne)
	// Detail records live inside a mapped fixture. LastModified uses Win10's
	// FILETIME ticks, and the BlobSize=0 case intentionally maps to N/A.
	for i, entry := range []uint64{shimFixtureEntryOne, shimFixtureEntryTwo} {
		detail := shimFixtureAVLTwo + 0x1000 + uint64(i)*0x100
		path := fileUTF16Bytes("C:\\Temp\\sample")
		putU64(mem, entry+40, detail)
		putU64(mem, detail+8, 116444736000000000)
		putU32(mem, detail+16, 0)
		putU32(mem, detail+24, uint32(0x1234+i))
		putU16(mem, entry+24, uint16(len(path)))
		putU16(mem, entry+26, uint16(len(path)))
		putU64(mem, entry+32, 0x680000+uint64(i)*0x100)
		copy(mem[0x680000+uint64(i)*0x100:], path)
	}
	putSSDTModule(mem, shimFixtureModule, shimFixtureBase, 0x6000, "ahcache.sys", 0x1000)
	linkSSDT(mem, 0x80, []uint64{shimFixtureModule}, 8)
	return mem
}

func shimFixtureEnvironment(mem flatMemory) plugin.Environment {
	table := shimFixtureSymbols()
	return plugin.Environment{
		Physical: mem, Kernel: mem, Symbols: table,
		Objects: &object.Reader{Layer: mem, Symbols: table}, OS: "windows",
		Architecture: "x64", PointerMask: 0x0000ffffffffffff,
		ImageHash: "fixture-image",
	}
}

func TestWindowsShimcacheModernEndToEnd(t *testing.T) {
	mem := shimFixtureMemory()
	env := shimFixtureEnvironment(mem)
	layout, _ := winshimcache.LayoutData("shimcache-win10-x64")
	handle, err := winshimcache.NewHandleReader(mem, layout, env.Symbols.(*symbols.ISF), env.PointerMask)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := handle.Valid(context.Background(), shimFixtureHandleTwo, shimFixtureBase+shimFixturePage, shimFixtureBase+shimFixturePage+shimFixturePageSize)
	if err != nil || !valid {
		t.Fatalf("fixture handle valid=%t err=%v", valid, err)
	}
	var rows []evidence.Row
	err = windowsShimcache(context.Background(), env, map[string]string{
		"max-nodes": "32", "max-pointers": "4096", "max-entries": "16", "max-evidence": "16",
	}, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var entries, reads int
	var coverage map[string]any
	for _, row := range rows {
		switch row.Cells["RecordType"].String() {
		case "entry":
			entries++
			if row.Cells["File Path"].String() != "C:\\Temp\\sample" {
				t.Fatalf("path = %#v", row.Cells["File Path"])
			}
			if row.Cells["Last Modified"].String() != "1970-01-01T00:00:00+00:00" {
				t.Fatalf("modified = %#v", row.Cells["Last Modified"])
			}
		case "memory_read":
			reads++
			raw := row.Cells["Raw"].Data.([]byte)
			at, _ := row.Cells["Offset"].Uint()
			if !bytes.Equal(raw, mem[at:at+uint64(len(raw))]) {
				t.Fatal("read evidence differs from source")
			}
		case "summary":
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
		}
	}
	if entries != 2 || reads == 0 || coverage == nil || coverage["completed"] != true || coverage["entries_emitted"] != uint64(2) {
		t.Fatalf("entries=%d reads=%d coverage=%#v", entries, reads, coverage)
	}
}

func TestWindowsShimcachePrefilterDoesNotEmitReadEvidence(t *testing.T) {
	mem := shimFixtureMemory()
	const unmapped = uint64(0xfffff80400000000)
	putU64(mem, shimFixtureBase+shimFixtureData, unmapped)
	env := shimFixtureEnvironment(mem)
	var rows []evidence.Row
	err := windowsShimcache(context.Background(), env, map[string]string{
		"max-nodes": "32", "max-pointers": "4096", "max-entries": "16", "max-evidence": "16",
	}, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var coverage map[string]any
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "memory_read" {
			if at, _ := row.Cells["Offset"].Uint(); at == unmapped {
				t.Fatal("mapping probe was recorded as an object read")
			}
		}
		if row.Cells["RecordType"].String() == "summary" {
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
		}
	}
	if coverage == nil || coverage["unmapped_rejected"] != uint64(1) || coverage["read_failures"] != uint64(0) {
		t.Fatalf("coverage = %#v", coverage)
	}
}

func TestWindowsShimcacheFailuresRemainExplicit(t *testing.T) {
	mem := shimFixtureMemory()
	env := shimFixtureEnvironment(mem)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := windowsShimcache(ctx, env, map[string]string{"max-nodes": "16", "max-pointers": "64", "max-entries": "16", "max-evidence": "16"}, func(evidence.Row) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
	stop := errors.New("stop")
	emitted := 0
	if err := windowsShimcache(context.Background(), env, map[string]string{"max-nodes": "16", "max-pointers": "64", "max-entries": "16", "max-evidence": "16"}, func(evidence.Row) error {
		emitted++
		if emitted == 1 {
			return stop
		}
		return nil
	}); !errors.Is(err, stop) {
		t.Fatalf("emitter error = %v", err)
	}
	if err := windowsShimcache(context.Background(), env, map[string]string{"max-nodes": "0", "max-pointers": "64", "max-entries": "16", "max-evidence": "16"}, func(evidence.Row) error { return nil }); err == nil {
		t.Fatal("invalid bound accepted")
	}
}

func TestWindowsShimcacheUnsupportedRouteAndMissingDiscovery(t *testing.T) {
	mem := shimFixtureMemory()
	env := shimFixtureEnvironment(mem)
	table := env.Symbols.(*symbols.ISF)
	table.Meta["windows"] = json.RawMessage(`{"pe":{"major":6,"minor":1,"revision":7601,"build":1}}`)
	var rows []evidence.Row
	err := windowsShimcache(context.Background(), env, map[string]string{
		"max-nodes": "32", "max-pointers": "4096", "max-entries": "16", "max-evidence": "16",
	}, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	})
	if err == nil || len(rows) != 1 || rows[0].Cells["RecordType"].String() != "summary" {
		t.Fatalf("unsupported route rows=%#v err=%v", rows, err)
	}
	coverage, _ := rows[0].Cells["Coverage"].Data.(map[string]any)
	if coverage["unsupported_route"] != true || coverage["status"] != "failed" {
		t.Fatalf("coverage = %#v", coverage)
	}

	table.Meta["windows"] = json.RawMessage(`{"pe":{"major":10,"minor":0,"revision":19041,"build":1}}`)
	delete(table.Symbols, "PsLoadedModuleList")
	rows = nil
	if err := windowsShimcache(context.Background(), env, map[string]string{
		"max-nodes": "32", "max-pointers": "4096", "max-entries": "16", "max-evidence": "16",
	}, func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}); err == nil || len(rows) != 1 {
		t.Fatalf("missing discovery rows=%#v err=%v", rows, err)
	}
}

func TestWindowsShimcacheFieldAndTraversalFailures(t *testing.T) {
	for _, scenario := range []string{"path-hole", "cycle"} {
		t.Run(scenario, func(t *testing.T) {
			mem := shimFixtureMemory()
			env := shimFixtureEnvironment(mem)
			if scenario == "path-hole" {
				putU16(mem, shimFixtureEntryOne+24, 0x100)
				putU64(mem, shimFixtureEntryOne+32, uint64(len(mem)))
			} else {
				putU64(mem, shimFixtureEntryTwo, shimFixtureEntryOne)
			}
			var rows []evidence.Row
			err := windowsShimcache(context.Background(), env, map[string]string{
				"max-nodes": "32", "max-pointers": "4096", "max-entries": "16", "max-evidence": "16",
			}, func(row evidence.Row) error {
				rows = append(rows, row)
				return nil
			})
			if err == nil {
				t.Fatal("fault completed cleanly")
			}
			var entries int
			var coverage map[string]any
			for _, row := range rows {
				switch row.Cells["RecordType"].String() {
				case "entry":
					entries++
				case "summary":
					coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
				}
			}
			if coverage == nil || coverage["completed"] != false || coverage["status"] != "failed" {
				t.Fatalf("coverage = %#v", coverage)
			}
			if scenario == "path-hole" && (entries != 2 || coverage["read_failures"] == uint64(0)) {
				t.Fatalf("entries=%d coverage=%#v", entries, coverage)
			}
			if scenario == "cycle" && entries != 2 {
				t.Fatalf("entries=%d coverage=%#v", entries, coverage)
			}
		})
	}
}

func TestShimcacheReadLayerDoesNotFabricateSuccess(t *testing.T) {
	mem := shimFixtureMemory()
	var failures pluginFailures
	var rows []evidence.Row
	layer := &shimcacheReadLayer{layer: mem, failures: &failures, out: func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}}
	p := make([]byte, 8)
	if n, err := layer.ReadAt(context.Background(), p, uint64(len(mem))-4); n != 4 || err == nil {
		t.Fatalf("short read = %d %v", n, err)
	}
	if len(rows) != 1 || rows[0].Cells["ReadComplete"].Data != false || failures.count != 1 {
		t.Fatalf("read evidence = %#v failures=%d", rows, failures.count)
	}
}

func FuzzWindowsShimcacheReadLayer(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3}, uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, address uint8) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		mem := flatMemory(append([]byte(nil), raw...))
		var failures pluginFailures
		layer := &shimcacheReadLayer{layer: mem, failures: &failures, out: func(evidence.Row) error { return nil }}
		buf := make([]byte, int(address)%33)
		_, _ = layer.ReadAt(context.Background(), buf, uint64(address))
		if failures.count > 1 || layer.reads > 1 {
			t.Fatal("unbounded read accounting")
		}
	})
}

var _ = sha256.Sum256
var _ = binary.LittleEndian
var _ = winshimcache.Family8OrLater
