package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func mutantScanSymbols() *symbols.ISF {
	table := threadScanSymbols(true)
	u64 := symbols.TypeRef{Kind: "base", Name: "unsigned long long"}
	table.Types["_KMUTANT"] = symbols.Type{Kind: "struct", Size: 56, Fields: map[string]symbols.Field{
		"Header": {Type: u64},
	}}
	table.Types["_OBJECT_HEADER_NAME_INFO"] = symbols.Type{Kind: "struct", Size: 32, Fields: map[string]symbols.Field{
		"Name": {Offset: 8, Type: symbols.TypeRef{Kind: "struct", Name: "_UNICODE_STRING"}},
	}}
	table.Symbols["ObpInfoMaskToOffset"] = symbols.Symbol{Address: 0x100}
	return table
}

func TestWindowsMutantScanTopDownNameAndMissingName(t *testing.T) {
	buf := make(flatMemory, 0xb00)
	for i := range buf {
		buf[i] = 0xff
	}
	putHeader := func(header uint64, typeIndex, infoMask byte) {
		buf[header+2] = 16
		buf[header+3] = 2
		copy(buf[header+4:], []byte("Muta"))
		start := header + 16
		putU64(buf, start, 1)
		buf[start+24] = typeIndex
		buf[start+26] = infoMask
	}
	putHeader(0x200, 3, 1)
	putHeader(0x500, 0, 0)
	putHeader(0x900, 8, 0)
	buf[0x100] = 0
	buf[0x101] = 0x30
	putUnicode(buf, 0x1e8, 0x400, `\BaseNamedObjects\Foo`)
	putU64(buf, 0x188, 0x700)
	putUnicode(buf, 0x710, 0x780, "Mutant")
	table := mutantScanSymbols()
	env := plugin.Environment{Physical: buf, Kernel: buf, Symbols: table, Objects: &object.Reader{Layer: buf, Symbols: table}, OS: "windows"}
	var mutants []evidence.Row
	var summary evidence.Row
	if err := windowsMutantScan(context.Background(), env, nil, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "mutant":
			mutants = append(mutants, row)
		case "summary":
			summary = row
		default:
			t.Fatal(row.Cells["RecordType"], row.Cells["Error"])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(mutants) != 2 {
		for _, row := range mutants {
			t.Log(row.Cells["Offset"], row.Cells["Name"])
		}
		t.Fatalf("mutants %d", len(mutants))
	}
	if mutants[0].Cells["Offset"].String() != "0x0000000000000240" || mutants[0].Cells["Name"].String() != `\BaseNamedObjects\Foo` {
		t.Fatalf("named %+v", mutants[0].Cells)
	}
	if mutants[1].Cells["Offset"].String() != "0x0000000000000940" || mutants[1].Cells["Name"].String() != "<name_unavailable>" {
		t.Fatalf("unnamed %+v", mutants[1].Cells)
	}
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["mutants"] != "2" || coverage["skipped_type"] != "1" || coverage["top_down"] != "true" {
		t.Fatal(coverage)
	}
}
