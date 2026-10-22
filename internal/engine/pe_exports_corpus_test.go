package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/pe"
)

func TestOfficialWindowsKernelPEExports(t *testing.T) {
	dir, reference, mapped := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_PE_EXPORT_REFERENCE"), os.Getenv("GOMEM_PE_EXPORT_MAPPED")
	if dir == "" || reference == "" || mapped == "" {
		t.Skip("requires official Windows corpus, pinned PE-export reference and mapped reconstruction; not full acceptance")
	}
	raw, err := os.ReadFile(reference)
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Commit    string
		ImageHash string `json:"image_sha256"`
		Base      uint64
		Rows      []pe.Export
		Lookups   []struct {
			Address uint64
			Name    *string
		}
	}
	if err = json.Unmarshal(raw, &ref); err != nil {
		t.Fatal(err)
	}
	if ref.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || ref.Base != 0xfffff8043601f000 || len(ref.Rows) != 3093 {
		t.Fatal("reference drift")
	}
	artifact, err := os.ReadFile(mapped)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)
	if hex.EncodeToString(digest[:]) != ref.ImageHash {
		t.Fatal("reference mapped artifact digest")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" || e.Config.KernelBase != ref.Base {
		t.Fatal("corpus/kernel identity")
	}
	limits := pe.DefaultExportLimits()
	reads := 0
	limits.Observe = func(r pe.ExportRead) error {
		reads++
		if r.Err != nil || len(r.Raw) != r.Requested {
			t.Fatalf("incomplete export acquisition at %#x: %v", r.Address, r.Err)
		}
		raw, err := memory.Read(ctx, e.Env.Kernel, r.Address, r.Requested)
		if err != nil || !bytes.Equal(raw, r.Raw) {
			t.Fatal("independent capture reread", err)
		}
		return nil
	}
	table, err := pe.ReadExports(ctx, e.Env.Kernel, ref.Base, limits)
	if err != nil || !table.Complete || len(table.Entries) != len(ref.Rows) {
		t.Fatal(err, table.Complete, len(table.Entries))
	}
	if !reflect.DeepEqual(table.Entries, ref.Rows) {
		for i, entry := range table.Entries {
			if !reflect.DeepEqual(entry, ref.Rows[i]) {
				t.Fatal(i, entry, ref.Rows[i])
			}
		}
	}
	for _, lookup := range ref.Lookups {
		name, found := table.NameAt(lookup.Address)
		if lookup.Name == nil {
			if found {
				t.Fatal("unexpected symbol")
			}
		} else if !found || string(name) != *lookup.Name {
			t.Fatal("exact lookup mismatch", lookup, string(name))
		}
	}
	t.Logf("%d ordered exports, %d exact-name lookups, %d reads and %d acquired bytes independently verified against pinned ExportSymbolFinder and pefile", len(table.Entries), len(ref.Lookups), reads, table.ReadBytes)
}
