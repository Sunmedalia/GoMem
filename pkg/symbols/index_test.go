package symbols_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestSymbolIndexArchivesRelativePathsAndStaleSources(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	table := &symbols.ISF{Meta: map[string]json.RawMessage{"format": json.RawMessage(`"6.2.0"`), "linux": json.RawMessage(`{}`)},
		Bases:   map[string]symbols.Type{"pointer": {Kind: "int", Size: 8, Endian: "little"}},
		Symbols: map[string]symbols.Symbol{"linux_banner": {Address: 0x4000, ConstantData: base64.StdEncoding.EncodeToString([]byte("Linux version 6.1.0-index-test\n\x00"))}}}
	data, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "table.json")
	if err = os.WriteFile(plain, data, 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	member, err := z.Create("linux/table.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	g := gzip.NewWriter(member)
	if _, err = g.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(dir, "symbols.zip")
	if err = os.WriteFile(zipPath, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	index, err := symbols.BuildIndex(ctx, []string{zipPath, plain, plain})
	if err != nil || len(index.Entries) != 2 {
		t.Fatal(index, err)
	}
	for n := range index.Entries {
		e := &index.Entries[n]
		if e.Banner != "Linux version 6.1.0-index-test\n" || e.BannerAddress != "0x4000" {
			t.Fatal("identity was normalized lossily", e)
		}
		if _, err = symbols.LoadEntry(ctx, *e); err != nil {
			t.Fatal(err)
		}
		filename, member, hasMember := strings.Cut(e.Location, "#")
		e.Location, err = filepath.Rel(dir, filename)
		if err != nil {
			t.Fatal(err)
		}
		if hasMember {
			e.Location += "#" + member
		}
	}
	encoded, err := index.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "index.json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := symbols.LoadIndex(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range loaded.Entries {
		if _, err = symbols.LoadEntry(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(plain, append(data, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	for _, e := range loaded.Entries {
		if e.Location == plain {
			if _, err = symbols.LoadEntry(ctx, e); err == nil || !strings.Contains(err.Error(), "stale") {
				t.Fatal("modified source reused", err)
			}
		}
	}
	if err = os.WriteFile(path, append(encoded, []byte("{}")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = symbols.LoadIndex(ctx, path); err == nil {
		t.Fatal("trailing index data accepted")
	}
	// Distinct JSON locations may resolve to the same file. Reject those too.
	index.Entries[0].Location = "table.json"
	index.Entries[1].Location = "nested/../table.json"
	alias, err := index.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = symbols.ParseIndex(alias, dir); err == nil {
		t.Fatal("relative path aliases accepted as distinct sources")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = symbols.BuildIndex(canceled, []string{plain}); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func FuzzSymbolIndex(f *testing.F) {
	f.Add([]byte(`{"schema":"gomem.symbol-index/v1","entries":[{"location":"symbols.json","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","os":"linux","pointer_size":8,"banner":"Linux version 6.1.0-test","banner_address":"0xffff800000000000"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		index, err := symbols.ParseIndex(data, ".")
		if err != nil {
			return
		}
		encoded, err := index.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = symbols.ParseIndex(encoded, "."); err != nil {
			t.Fatal("valid index did not round trip", err)
		}
	})
}
