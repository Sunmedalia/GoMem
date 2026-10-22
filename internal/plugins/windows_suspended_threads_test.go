package plugins

import (
	"context"
	"errors"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestSuspendedPathCandidatesAndFailureBounds(t *testing.T) {
	regions := []windowsVADPath{{start: 0x1000, end: 0x1fff, file: evidence.Text(`C:\x.dll`)}, {start: 0x1800, end: 0x2fff, file: evidence.Text(`C:\y.dll`)}}
	if suspendedFileAt(regions, 0x1900).String() != `C:\x.dll` || suspendedFileAt(regions, 0).Kind != "missing" || suspendedFileAt(regions, 0x3000).Kind != "missing" {
		t.Fatal("preorder/inclusive lookup")
	}
	if windowsModuleName(`C:\Windows/sys/FiXtUrE.DLL`) != "fixture.dll" {
		t.Fatal("Windows mixed separators")
	}
	regions[0].file = evidence.Missing("read_failure", errors.New("hole"))
	if _, err := windowsFileVADs(regions); err == nil {
		t.Fatal("file read error disappeared")
	}
	a := &windowsSymbolAnalysis{}
	for range 10000 {
		a.failure(errors.New("hole"))
	}
	if a.coverage.Errors != 10000 || len(a.failures) != 65 {
		t.Fatal("unbounded failure summary")
	}
	b := windowsSuspendedThreadPlugins()[0]
	for _, key := range []string{"max-nodes", "max-threads", "max-regions", "max-read-bytes", "max-symbols"} {
		for _, value := range []string{"0", "-1", "not-a-number", "18446744073709551615"} {
			p, err := plugin.Parameters(b.Spec(), map[string]string{key: value})
			if err == nil {
				err = b.Run(context.Background(), plugin.Environment{}, p, func(evidence.Row) error { return nil })
			}
			if err == nil {
				t.Fatal(key, value)
			}
		}
	}
}
func FuzzSuspendedThreadPipeline(f *testing.F) {
	f.Add(uint8(2), uint8(2), uint64(0x100100), false)
	f.Add(uint8(0), uint8(4), uint64(0), true)
	f.Fuzz(func(t *testing.T, suspend, state uint8, address uint64, fail bool) {
		e, mem := suspiciousThreadFixture(t)
		table := e.Symbols.(*symbols.ISF)
		kt := table.Types["_KTHREAD"]
		kt.Size = 16
		kt.Fields["SuspendCount"] = symbols.Field{Offset: 4, Type: symbols.TypeRef{Kind: "base", Name: "u8"}}
		kt.Fields["Process"] = symbols.Field{Offset: 8, Type: symbols.TypeRef{Kind: "pointer"}}
		table.Types["_KTHREAD"] = kt
		et := table.Types["_ETHREAD"]
		et.Size = 80
		table.Types["_ETHREAD"] = et
		table.Types["_KPROCESS"] = symbols.Type{Kind: "struct", Size: 8, Fields: map[string]symbols.Field{"DirectoryTableBase": {Offset: 0, Type: symbols.TypeRef{Kind: "base", Name: "u64"}}}}
		pt := table.Types["_EPROCESS"]
		pt.Size = 88
		pt.Fields["Pcb"] = symbols.Field{Offset: 80, Type: symbols.TypeRef{Kind: "struct", Name: "_KPROCESS"}}
		table.Types["_EPROCESS"] = pt
		putU64(mem, 0x450, 0x8000)
		putU64(mem, 0x8000, 0x9003)
		putU64(mem, 0x9000, 0xa003)
		putU64(mem, 0xa000, 0x83)
		mem[0x644] = suspend
		putU32(mem, 0x640, uint32(state))
		putU64(mem, 0x648, 0x400)
		putU64(mem, 0x620, address)
		putU64(mem, 0x628, address)
		e.Physical = mem
		e.Architecture = "x64"
		e.ModulePDB = func(context.Context, pesymbols.Module) (pesymbols.PDB, error) {
			return pesymbols.PDB{}, pesymbols.ErrUnavailable
		}
		b := windowsSuspendedThreadPlugins()[0]
		p, err := plugin.Parameters(b.Spec(), map[string]string{"max-nodes": "16", "max-threads": "8", "max-regions": "16", "max-read-bytes": "65536", "max-symbols": "8"})
		if err != nil {
			t.Fatal(err)
		}
		emitted := 0
		sentinel := errors.New("output stopped")
		err = b.Run(context.Background(), e, p, func(row evidence.Row) error {
			emitted++
			if emitted > 4096 {
				t.Fatal("unbounded rows")
			}
			if fail {
				return sentinel
			}
			return nil
		})
		if fail && (!errors.Is(err, sentinel) || emitted != 1) {
			t.Fatal("output failure not propagated", err, emitted)
		}
	})
}
