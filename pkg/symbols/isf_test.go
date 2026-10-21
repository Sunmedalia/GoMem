package symbols_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/ulikunitz/xz"
)

func TestCompressedISFAndIdentity(t *testing.T) {
	f, e := testfixture.Write(t.TempDir(), "windows")
	if e != nil {
		t.Fatal(e)
	}
	original, e := symbols.Load(f.Symbols)
	if e != nil {
		t.Fatal(e)
	}
	if e = original.MatchPDB("ntkrnlmp.pdb", "112233445566778899AABBCCDDEEFF00", 1); e != nil {
		t.Fatal(e)
	}
	if e = original.MatchPDB("ntkrnlmp.pdb", "112233445566778899AABBCCDDEEFF00", 2); e == nil {
		t.Fatal("wrong age accepted")
	}
	data, _ := os.ReadFile(f.Symbols)
	for _, kind := range []string{"gz", "xz", "zip"} {
		t.Run(kind, func(t *testing.T) {
			var b bytes.Buffer
			switch kind {
			case "gz":
				w := gzip.NewWriter(&b)
				w.Write(data)
				w.Close()
			case "xz":
				w, _ := xz.NewWriter(&b)
				w.Write(data)
				w.Close()
			case "zip":
				w := zip.NewWriter(&b)
				f, _ := w.Create("nested/symbols.json")
				f.Write(data)
				w.Close()
			}
			name := filepath.Join(t.TempDir(), "symbols.json."+kind)
			os.WriteFile(name, b.Bytes(), 0600)
			back, e := symbols.Load(name)
			if e != nil || back.Digest() != original.Digest() {
				t.Fatal(back, e)
			}
		})
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, n := range []string{"one.json", "two.json"} {
		w, _ := z.Create(n)
		w.Write(data)
	}
	z.Close()
	p := filepath.Join(t.TempDir(), "ambiguous.zip")
	os.WriteFile(p, buf.Bytes(), 0600)
	if _, e = symbols.Load(p); e == nil {
		t.Fatal("ambiguous archive accepted")
	}
	if _, e = symbols.Load(p + "#two.json"); e != nil {
		t.Fatal(e)
	}
}
func FuzzISF(f *testing.F) {
	f.Add([]byte(`{"metadata":{"format":"6.2.0"}}`))
	f.Add([]byte(`{"user_types":null}`))
	f.Add([]byte(`{"metadata":{"format":"6.2.0"},"base_types":{"pointer":{"size":8,"kind":"int"}},"user_types":{"item":{"size":8,"kind":"struct","fields":{"next":{"offset":0,"type":{"kind":"pointer"}}}}},"symbols":{"head":{"address":4096}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = symbols.Parse(b)
	})
}

func TestARM64MetadataGeometry(t *testing.T) {
	for _, tc := range []struct {
		metadata string
		valid    bool
	}{
		{`{"architecture":"aarch64","page_shift":12,"va_bits":48}`, true},
		{`{"architecture":"aarch64","page_shift":16,"va_bits":48}`, false},
		{`{"architecture":"aarch64","page_shift":12,"va_bits":52}`, false},
		{`{"architecture":"aarch64"}`, false},
	} {
		table := &symbols.ISF{Meta: map[string]json.RawMessage{"zero": json.RawMessage(tc.metadata)}, Bases: map[string]symbols.Type{"pointer": {Size: 8}}}
		if table.Architecture() != "aarch64" {
			t.Fatal(table.Architecture())
		}
		if err := table.ValidateARM64(); (err == nil) != tc.valid {
			t.Fatal(tc, err)
		}
	}
}
