package engine

import (
	"context"
	debugpe "debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type moduleTestLayer struct {
	base uint64
	data []byte
}

func (l moduleTestLayer) Name() string { return "native-module" }
func (l moduleTestLayer) Ranges() []memory.Range {
	return []memory.Range{{Start: l.base, Length: uint64(len(l.data))}}
}
func (l moduleTestLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if at < l.base || at-l.base >= uint64(len(l.data)) {
		return 0, io.EOF
	}
	n := copy(p, l.data[at-l.base:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
func nativeModuleFixture(t *testing.T, arch string) (pesymbols.Module, *symbols.ISF, string) {
	t.Helper()
	root := "../../pkg/symbols/testdata/native-" + arch
	file, err := debugpe.Open(root + ".exe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var base uint64
	var headers, size uint32
	switch h := file.OptionalHeader.(type) {
	case *debugpe.OptionalHeader32:
		base, headers, size = uint64(h.ImageBase), h.SizeOfHeaders, h.SizeOfImage
	case *debugpe.OptionalHeader64:
		base, headers, size = h.ImageBase, h.SizeOfHeaders, h.SizeOfImage
	}
	raw, err := os.ReadFile(root + ".exe")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	copy(data, raw[:headers])
	for _, section := range file.Sections {
		if section.Size != 0 {
			raw, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}
			copy(data[section.VirtualAddress:], raw)
		}
	}
	table, _, err := symbols.ConvertPDB(context.Background(), root+".pdb", symbols.PDBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return pesymbols.Module{Layer: moduleTestLayer{base, data}, Base: base, Size: uint64(size)}, table, root + ".pdb"
}
func seedModulePDB(t *testing.T, cache string, table *symbols.ISF, path string) {
	t.Helper()
	id, err := table.PDBIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(cache, strings.ToLower(id.Database), fmt.Sprintf("%s%X", id.GUID, id.Age))
	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, strings.ToLower(id.Database)), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestModulePDBNativeOfflineConversionAndConcurrency(t *testing.T) {
	for _, arch := range []string{"x86", "x64"} {
		t.Run(arch, func(t *testing.T) {
			m, table, path := nativeModuleFixture(t, arch)
			cache := t.TempDir()
			seedModulePDB(t, cache, table, path)
			e := &Engine{Config: Config{Offline: true, SymbolCache: cache}, Build: strings.Repeat("ab", 32)}
			provider := e.modulePDBProvider()
			ctx := context.Background()
			original := e.Config
			opts := pesymbols.Options{PDB: provider, Limits: pe.DefaultExportLimits(), MaxSymbols: 1000000}
			captures := 0
			opts.Observe = func(r pesymbols.Read) error {
				captures++
				raw, err := memory.Read(ctx, m.Layer, r.Address, r.Requested)
				if err != nil || string(raw) != string(r.Raw) || r.Err != nil {
					t.Fatal(r, err)
				}
				return nil
			}
			resolver, err := pesymbols.New([]pesymbols.Module{m}, opts)
			if err != nil {
				t.Fatal(err)
			}
			result, err := resolver.Resolve(ctx, pesymbols.Request{Names: []string{"entry"}})
			expected, err2 := table.Lookup("entry")
			if err != nil || err2 != nil || len(result.Found) != 1 || result.Found[0].Address != m.Base+expected.Address || result.Found[0].Method != "pdb" || result.Found[0].SourceSHA256 == "" || captures == 0 {
				t.Fatal(result, err, err2, captures)
			}
			var wg sync.WaitGroup
			errs := make(chan error, 4)
			for i := 0; i < 4; i++ {
				wg.Go(func() {
					got, err := provider(ctx, m)
					if err != nil {
						errs <- err
						return
					}
					if got.Table.Digest() != table.Digest() {
						errs <- errors.New("converted table drift")
					}
				})
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
			if e.Config != original {
				t.Fatal("module acquisition mutated engine configuration")
			}
		})
	}
}
func TestModulePDBUnavailableIdentityAndIndexFailures(t *testing.T) {
	m, table, path := nativeModuleFixture(t, "x64")
	e := &Engine{Config: Config{Offline: true, SymbolCache: t.TempDir()}, Build: strings.Repeat("ab", 32)}
	if _, err := e.modulePDBProvider()(context.Background(), m); !errors.Is(err, pesymbols.ErrUnavailable) {
		t.Fatal(err)
	}
	// The kernel table is reusable only for this exact resident identity.
	e.Env.Symbols = table
	got, err := e.modulePDBProvider()(context.Background(), m)
	if err != nil || got.Table.Digest() != table.Digest() {
		t.Fatal(got, err)
	}
	short := m
	short.Size = 64
	if _, err := e.modulePDBProvider()(context.Background(), short); err == nil {
		t.Fatal("short module accepted")
	}
	bad := m
	bad.Layer = moduleTestLayer{m.Base, []byte("MZ")}
	if _, err := e.modulePDBProvider()(context.Background(), bad); err == nil || errors.Is(err, pesymbols.ErrUnavailable) {
		t.Fatal("read error became missing PDB", err)
	}
	e.Env.Symbols = nil
	index, err := symbols.BuildIndex(context.Background(), []string{path})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := index.Encode()
	if err != nil {
		t.Fatal(err)
	}
	e.Config.SymbolIndex = filepath.Join(t.TempDir(), "index.json")
	if err = os.WriteFile(e.Config.SymbolIndex, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = e.modulePDBProvider()(context.Background(), m)
	if err != nil || got.Table.Digest() != table.Digest() {
		t.Fatal(got, err)
	}
	if err = os.WriteFile(e.Config.SymbolIndex, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.modulePDBProvider()(context.Background(), m); err == nil || errors.Is(err, pesymbols.ErrUnavailable) {
		t.Fatal("broken index became unavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.modulePDBProvider()(ctx, m); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestModulePDBNameCandidatesPrecedeAcquisition(t *testing.T) {
	m, table, _ := nativeModuleFixture(t, "x64")
	e := &Engine{Config: Config{Offline: true, SymbolCache: t.TempDir()}}
	e.Env.Symbols = table
	m.PDBNames = []string{"unrelated.pdb"}
	if _, err := e.modulePDBProvider()(context.Background(), m); !errors.Is(err, pesymbols.ErrUnavailable) {
		t.Fatal("unrequested resident identity accepted", err)
	}
	id, err := table.PDBIdentity()
	if err != nil {
		t.Fatal(err)
	}
	m.PDBNames = []string{id.Database}
	if _, err = e.modulePDBProvider()(context.Background(), m); err != nil {
		t.Fatal(err)
	}
}
