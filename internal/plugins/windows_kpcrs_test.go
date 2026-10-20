package plugins

import (
	"context"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsKPCRCurrentAndEmbedded(t *testing.T) {
	mem := make(flatMemory, 0x1100)
	putU64(mem, 0x100, 2)
	putU64(mem, 0x200, 0x1000)
	putU64(mem, 0x208, 0x3000)
	// KPCR base is 0x1000-0x180. CurrentPrcb at +0x20 stores the PRCB address.
	putU64(mem, 0xe80+0x20, 0x1000)

	rows, err := runKPCRs(t, mem, kpcrSymbols(true))
	if err != nil {
		t.Fatal(err)
	}
	got := filterKPCR(rows, "kpcr")
	if len(got) != 1 || got[0].Cells["Offset"].String() != "0x0000000000000e80" || got[0].Cells["PRCB"].String() != "0x0000000000001000" {
		t.Fatal(len(got), got[0].Cells)
	}
	summary := filterKPCR(rows, "summary")
	if len(summary) != 1 || summary[0].Cells["Coverage"].Data.(map[string]any)["skipped"] != "1" {
		t.Fatal(summary[0].Cells["Coverage"].Data)
	}

	mem[0x100] = 0
	rows, err = runKPCRs(t, mem, kpcrSymbols(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(filterKPCR(rows, "kpcr")) != 0 {
		t.Fatal("zero processors emitted a KPCR")
	}

	mem[0x100] = 1
	rows, err = runKPCRs(t, mem, kpcrSymbols(false))
	if err != nil {
		t.Fatal(err)
	}
	got = filterKPCR(rows, "kpcr")
	if len(got) != 1 || got[0].Cells["Offset"].String() != "0x0000000000000e80" || got[0].Cells["PRCB"].String() != "0x0000000000001000" {
		t.Fatal(got[0].Cells)
	}
}

func kpcrSymbols(current bool) *symbols.ISF {
	ptr := symbols.TypeRef{Kind: "pointer"}
	prcb := symbols.TypeRef{Kind: "struct", Name: "_KPRCB"}
	fields := map[string]symbols.Field{
		"Prcb": {Offset: 0x180, Type: prcb},
	}
	if current {
		fields["CurrentPrcb"] = symbols.Field{Offset: 0x20, Type: ptr}
	}
	return &symbols.ISF{
		Bases: map[string]symbols.Type{
			"pointer":      {Size: 8, Endian: "little"},
			"unsigned int": {Size: 4, Endian: "little"},
		},
		Types: map[string]symbols.Type{
			"_KPRCB": {Kind: "struct", Size: 0x40},
			"_KPCR":  {Kind: "struct", Size: 0x200, Fields: fields},
		},
		Symbols: map[string]symbols.Symbol{
			"KeNumberProcessors": {Address: 0x100},
			"KiProcessorBlock":   {Address: 0x200},
		},
	}
}

func runKPCRs(t *testing.T, layer memory.MemoryLayer, table *symbols.ISF) ([]evidence.Row, error) {
	t.Helper()
	env := plugin.Environment{Kernel: layer, Symbols: table, Objects: &object.Reader{Layer: layer, Symbols: table}, OS: "windows", ImageHash: "img"}
	var rows []evidence.Row
	err := windowsKPCRs(context.Background(), env, nil, func(row evidence.Row) error {
		row.Seal()
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	})
	return rows, err
}

func filterKPCR(rows []evidence.Row, kind string) []evidence.Row {
	var out []evidence.Row
	for _, row := range rows {
		if row.Cells["RecordType"].String() == kind {
			out = append(out, row)
		}
	}
	return out
}
