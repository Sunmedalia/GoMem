package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func saveIndex(t *testing.T, index *symbols.Index, path string) {
	t.Helper()
	data, err := index.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestIndexedSymbolsVerifyKernelAndShareTaskCache(t *testing.T) {
	ctx := context.Background()
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			f, err := testfixture.Write(t.TempDir(), platform)
			if err != nil {
				t.Fatal(err)
			}
			caseDir := t.TempDir()
			if err = os.Mkdir(filepath.Join(caseDir, "symbols"), 0700); err != nil {
				t.Fatal(err)
			}
			index, err := symbols.BuildIndex(ctx, []string{f.Symbols})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(caseDir, "symbols", "index.json")
			saveIndex(t, index, path)
			c := engine.Config{Image: f.Image, CaseDir: caseDir, DTB: f.DTB, KernelBase: f.KernelBase, Offline: true}
			e, err := engine.Open(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			if e.Env.OS != platform || e.Env.Symbols.Digest() != index.Entries[0].SHA256 {
				t.Fatal("wrong table or OS selected")
			}
			result, err := e.Run(ctx, platform+".pslist", nil, engine.RunOptions{})
			if err != nil || result.Task.Rows != 2 {
				t.Fatal(result, err)
			}
			if err = e.Close(); err != nil {
				t.Fatal(err)
			}
			c.Symbols = f.Symbols
			c.SymbolIndex = "explicit-symbols-override-this-missing-index"
			e, err = engine.Open(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			result, err = e.Run(ctx, platform+".pslist", nil, engine.RunOptions{})
			if err != nil || !result.Reused {
				t.Fatal("explicit and indexed tables must share the content cache", result, err)
			}
			e.Close()
		})
	}
}

func TestIndexedSymbolsRejectStaleAmbiguousAndUnreadable(t *testing.T) {
	ctx := context.Background()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	index, err := symbols.BuildIndex(ctx, []string{f.Symbols})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "index.json")
	c := engine.Config{Image: f.Image, SymbolIndex: path, DTB: f.DTB}
	probe := func(want string) {
		t.Helper()
		e, err := engine.Open(ctx, c)
		if e != nil {
			e.Close()
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatal("expected", want, "got", err)
		}
	}
	valid := index.Entries[0]
	index.Entries[0].Banner = "Linux version 0.0.0-wrong"
	saveIndex(t, index, path)
	probe("no exact resident kernel identity")
	index.Entries[0] = valid
	index.Entries[0].BannerAddress = "0xdeadbeef"
	saveIndex(t, index, path)
	probe("read/verification failures")
	index.Entries[0] = valid
	saveIndex(t, index, path)
	data, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(data, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	probe("stale")
	table, err := symbols.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	table.Meta["producer"] = json.RawMessage(`{"name":"other","version":"1"}`)
	different, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.json")
	if err = os.WriteFile(other, different, 0600); err != nil {
		t.Fatal(err)
	}
	index, err = symbols.BuildIndex(ctx, []string{f.Symbols, other})
	if err != nil {
		t.Fatal(err)
	}
	saveIndex(t, index, path)
	probe("ambiguous")
	c.DTB = ""
	probe("requires --dtb")
}
