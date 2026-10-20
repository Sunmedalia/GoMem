package plugins

import (
	"context"
	"io"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func symlinkScanSymbols() *symbols.ISF {
	table := mutantScanSymbols()
	i64 := symbols.TypeRef{Kind: "base", Name: "long long"}
	unicode := symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}
	table.Types["_OBJECT_SYMBOLIC_LINK"] = symbols.Type{Kind: "struct", Size: 40, Fields: map[string]symbols.Field{
		"CreationTime": {Type: symbols.TypeRef{Kind: "union", Name: "_LARGE_INTEGER"}},
		"LinkTarget":   {Offset: 8, Type: unicode},
	}}
	if _, ok := table.Types["_LARGE_INTEGER"]; !ok {
		table.Types["_LARGE_INTEGER"] = symbols.Type{Kind: "union", Size: 8, Fields: map[string]symbols.Field{"QuadPart": {Type: i64}}}
	}
	return table
}

func putSymlinkHeader(buf flatMemory, header uint64, poolType, infoMask byte, symbolic bool) uint64 {
	buf[header+2] = 16
	buf[header+3] = poolType
	copy(buf[header+4:], []byte("Symb"))
	start := header + 16
	putU64(buf, start, 1)
	// Win10 folds the object-header address into TypeIndex. Cookie is zero here.
	typeIndex := byte((start >> 8) ^ 1)
	if !symbolic {
		typeIndex ^= 0x10
	}
	buf[start+24] = typeIndex
	buf[start+26] = infoMask
	return start + 48
}

func TestWindowsSymlinkScanPagedNamesAndEmptyTarget(t *testing.T) {
	buf := make(flatMemory, 0x1600)
	for i := range buf {
		buf[i] = 0xff
	}
	created := uint64(132223104000000000)
	named := putSymlinkHeader(buf, 0x200, 1, 1, true)
	putU64(buf, named, created)
	putUnicode(buf, named+8, 0x1100, `\Device\HarddiskVolume1`)
	putUnicode(buf, 0x1e8, 0x1000, `\DosDevices\C:`)

	emptyTarget := putSymlinkHeader(buf, 0x600, 1, 1, true)
	putU64(buf, emptyTarget, created)
	putU16(buf, emptyTarget+8, 0)
	putU16(buf, emptyTarget+10, 0)
	putU64(buf, emptyTarget+16, 0)
	putUnicode(buf, 0x5e8, 0x1200, "EmptyTarget")

	emptyFrom := putSymlinkHeader(buf, 0x800, 1, 1, true)
	putU64(buf, emptyFrom, created)
	putUnicode(buf, emptyFrom+8, 0x1280, `Somewhere`)
	putU16(buf, 0x7e8, 0)
	putU16(buf, 0x7ea, 0)
	putU64(buf, 0x7f0, 0)

	putSymlinkHeader(buf, 0xa00, 1, 0, true)
	putU64(buf, 0xa40, created)
	putUnicode(buf, 0xa48, 0x1400, `\Device\Dropped`)

	badTarget := putSymlinkHeader(buf, 0xc00, 1, 1, true)
	putU64(buf, badTarget, created)
	putU16(buf, badTarget+8, 4)
	putU16(buf, badTarget+10, 4)
	putU64(buf, badTarget+16, 0xffffffffffffffff)
	putUnicode(buf, 0xbe8, 0x1480, "BadTarget")

	putSymlinkHeader(buf, 0xe00, 2, 1, true)
	putU64(buf, 0xe40, created)
	putUnicode(buf, 0xe48, 0x1500, `\Device\NonPaged`)
	putUnicode(buf, 0xde8, 0x1580, "NonPaged")

	putSymlinkHeader(buf, 0x400, 1, 1, false)
	buf[0x100] = 0
	buf[0x101] = 0x30
	putU64(buf, 0x188, 0x1300)
	putUnicode(buf, 0x1310, 0x1380, "SymbolicLink")

	table := symlinkScanSymbols()
	env := plugin.Environment{Physical: buf, Kernel: buf, Symbols: table, Objects: &object.Reader{Layer: buf, Symbols: table}, OS: "windows"}
	var links []evidence.Row
	var summary evidence.Row
	if err := windowsSymlinkScan(context.Background(), env, nil, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "symlink":
			links = append(links, row)
		case "summary":
			summary = row
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(links) != 3 {
		for _, row := range links {
			t.Log(row.Cells["Offset"], row.Cells["FromName"], row.Cells["ToName"])
		}
		t.Fatalf("symlinks %d", len(links))
	}
	if links[0].Cells["Offset"].String() != "0x0000000000000240" || links[0].Cells["FromName"].String() != `\DosDevices\C:` || links[0].Cells["ToName"].String() != `\Device\HarddiskVolume1` || links[0].Cells["CreateTime"].String() != "2020-01-01T00:00:00Z" {
		t.Fatalf("named %+v", links[0].Cells)
	}
	if links[1].Cells["Offset"].String() != "0x0000000000000640" || links[1].Cells["FromName"].String() != "EmptyTarget" || links[1].Cells["ToName"].Kind != "string" || links[1].Cells["ToName"].Data != "" {
		t.Fatalf("empty target %+v", links[1].Cells)
	}
	if links[2].Cells["Offset"].String() != "0x0000000000000840" || links[2].Cells["FromName"].Kind != "string" || links[2].Cells["FromName"].Data != "" || links[2].Cells["ToName"].String() != "Somewhere" {
		t.Fatalf("empty source %+v", links[2].Cells)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["symlinks"] != "3" || coverage["skipped_type"] != "1" || coverage["skipped_name"] != "1" || coverage["top_down"] != "true" || coverage["windows10"] != "true" {
		t.Fatal(coverage)
	}
}

type failSmallRead struct {
	flatMemory
	addr uint64
}

func (m failSmallRead) ReadAt(ctx context.Context, p []byte, addr uint64) (int, error) {
	if len(p) > 0 && len(p) <= 16 && addr <= m.addr && m.addr < addr+uint64(len(p)) {
		return 0, io.ErrUnexpectedEOF
	}
	return m.flatMemory.ReadAt(ctx, p, addr)
}

func TestWindowsSymlinkScanCreateTimeReadFailsTheTask(t *testing.T) {
	buf := make(flatMemory, 0x900)
	for i := range buf {
		buf[i] = 0xff
	}
	link := putSymlinkHeader(buf, 0x200, 1, 1, true)
	putU64(buf, link, 132223104000000000)
	putUnicode(buf, link+8, 0x600, `\Device\HarddiskVolume1`)
	putUnicode(buf, 0x1e8, 0x500, `\DosDevices\C:`)
	buf[0x100] = 0
	buf[0x101] = 0x30
	putU64(buf, 0x188, 0x700)
	putUnicode(buf, 0x710, 0x780, "SymbolicLink")
	layer := failSmallRead{flatMemory: buf, addr: link}
	table := symlinkScanSymbols()
	env := plugin.Environment{Physical: layer, Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows"}
	err := windowsSymlinkScan(context.Background(), env, nil, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "symlink" {
			t.Fatal("creation-time read failure emitted a row")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected creation-time failure")
	}
}
