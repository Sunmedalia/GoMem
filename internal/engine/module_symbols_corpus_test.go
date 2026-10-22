package engine_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
)

func TestOfficialWindowsKernelModuleSymbols(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("requires official Windows corpus; selected PDB-first control only")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" || e.Env.ModulePDB == nil {
		t.Fatal("corpus identity/provider")
	}
	image, err := pe.Plan(ctx, e.Env.Kernel, e.Config.KernelBase)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"PsActiveProcessHead", "PsLoadedModuleList", "NtBuildLab"}
	reads, captured := 0, 0
	opts := pesymbols.Options{PDB: e.Env.ModulePDB, Limits: pe.DefaultExportLimits(), MaxSymbols: 1000000}
	opts.Observe = func(r pesymbols.Read) error {
		reads++
		captured += len(r.Raw)
		raw, err := memory.Read(ctx, e.Env.Kernel, r.Address, r.Requested)
		if err != nil || r.Err != nil || !bytes.Equal(raw, r.Raw) {
			t.Fatal("independent capture reread", err, r.Err)
		}
		return nil
	}
	resolver, err := pesymbols.New([]pesymbols.Module{{Layer: e.Env.Kernel, Base: image.Base, Size: image.Size}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(ctx, pesymbols.Request{Names: names})
	if err != nil || len(result.Found) != len(names) || len(result.Attempts) != 1 {
		t.Fatal(result, err)
	}
	for i, name := range names {
		symbol, err := e.Env.Symbols.Lookup(name)
		got := result.Found[i]
		if err != nil || got.Name != name || got.Address != image.Base+symbol.Address || got.Method != "pdb" || got.SymbolsSHA256 != e.Env.Symbols.Digest() {
			t.Fatal(name, got, err)
		}
	}
	if reads == 0 {
		t.Fatal("missing PDB identity acquisition evidence")
	}
	t.Logf("%d exact resident-kernel PDB symbols; %d reads/%d bytes independently reread", len(names), reads, captured)
}
