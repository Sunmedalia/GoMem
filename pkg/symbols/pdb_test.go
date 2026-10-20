package symbols_test

import (
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestPDBCompiledObjects(t *testing.T) {
	for _, arch := range []string{"x64", "x86"} {
		t.Run(arch, func(t *testing.T) {
			path := filepath.Join("testdata", "native-"+arch+".pdb")
			table, report, err := symbols.ConvertPDB(context.Background(), path, symbols.PDBOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if report.Types < 5 || report.Symbols != 5 || report.Enums != 1 {
				t.Fatal(report)
			}
			encoded, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := symbols.Parse(encoded)
			if err != nil || parsed.Digest() != table.Digest() {
				t.Fatal(err)
			}
			pdb, err := table.PDBIdentity()
			if err != nil || pdb.Database != "native-"+arch+".pdb" || pdb.Age != 1 {
				t.Fatal(pdb, err)
			}
			if err = table.MatchPDB(pdb.Database, pdb.GUID, pdb.Age+1); err == nil {
				t.Fatal("wrong age matched")
			}
			image := filepath.Join("testdata", "native-"+arch+".exe")
			file, err := pe.Open(image)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var imageBase uint64
			switch h := file.OptionalHeader.(type) {
			case *pe.OptionalHeader64:
				imageBase = h.ImageBase
			case *pe.OptionalHeader32:
				imageBase = uint64(h.ImageBase)
			}
			source, err := memory.OpenFile(image)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			var ranges []memory.Range
			for _, s := range file.Sections {
				if s.Size > 0 {
					ranges = append(ranges, memory.Range{Start: uint64(s.VirtualAddress), Length: uint64(s.Size), FileOffset: uint64(s.Offset)})
				}
			}
			layer, err := memory.NewMapped(source, "compiled-pe", ranges)
			if err != nil {
				t.Fatal(err)
			}
			r := &object.Reader{Layer: layer, Symbols: table}
			process, err := table.Lookup("SystemProcess")
			if err != nil {
				t.Fatal(err)
			}
			if process.Type == nil || process.Type.Name != "_EPROCESS" {
				t.Fatal("global type lost", process)
			}
			for _, f := range []struct {
				name string
				want int64
			}{{"signed_value", -987}, {"flags.b", -7}, {"packed.b", -4}, {"state", -1}} {
				v, err := r.Int(context.Background(), process.Address, "_EPROCESS", f.name)
				if err != nil || v != f.want {
					t.Fatal(f.name, v, err)
				}
			}
			for _, f := range []struct {
				name string
				want uint64
			}{{"flags.a", 5}, {"flags.c", 257}, {"packed.a", 6}, {"packed.c", 1}, {"UniqueProcessId", 4}} {
				v, err := r.Uint(context.Background(), process.Address, "_EPROCESS", f.name)
				if err != nil || v != f.want {
					t.Fatal(f.name, v, err)
				}
			}
			_, names, err := r.Enum(context.Background(), process.Address, "_EPROCESS", "state")
			if err != nil || len(names) != 1 || names[0] != "gone" {
				t.Fatal(names, err)
			}
			answer, err := table.Lookup("answer")
			if err != nil {
				t.Fatal(err)
			}
			callback, err := r.Uint(context.Background(), process.Address, "_EPROCESS", "callback")
			if err != nil || callback != imageBase+answer.Address {
				t.Fatal(callback, answer, err)
			}
			f, err := r.Field("_EPROCESS", "grid")
			if err != nil || f.Type.Count != 2 || f.Type.Subtype.Count != 3 {
				t.Fatal(f, err)
			}
			value, err := table.Lookup("private_value")
			if err != nil || value.Type == nil {
				t.Fatal("private data missing", value, err)
			}
			raw, err := r.Scalar(context.Background(), value.Address, *value.Type)
			if err != nil || raw != 0xffffff85 {
				t.Fatal(raw, err)
			}
			if alias, err := table.Type("LIST_ENTRY"); err != nil || alias.Size != uint64(table.PointerSize()*2) {
				t.Fatal(alias, err)
			}
			for _, opts := range []symbols.PDBOptions{{MaxBytes: 1024}, {MaxRecords: 1}, {Database: "../invalid.pdb"}} {
				if _, _, err := symbols.ConvertPDB(context.Background(), path, opts); err == nil {
					t.Fatal("invalid bounds or identity accepted", opts)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, _, err := symbols.ConvertPDB(ctx, path, symbols.PDBOptions{}); err == nil {
				t.Fatal("cancellation ignored")
			}
			loaded, err := symbols.Load(path)
			if err != nil || loaded.Digest() != table.Digest() {
				t.Fatal("direct loading differs", err)
			}
		})
	}
}

func TestPDBFixtureManifest(t *testing.T) {
	var m struct {
		Source string `json:"source_sha256"`
		Files  []struct{ Name, SHA256 string }
	}
	data, err := os.ReadFile("testdata/pdb-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("testdata/pdb_kernel.c")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(source)) != m.Source || len(m.Files) != 4 {
		t.Fatal("PDB fixture source changed")
	}
	for _, f := range m.Files {
		data, err := os.ReadFile(filepath.Join("testdata", f.Name))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != f.SHA256 {
			t.Fatal(f, err)
		}
	}
}

func FuzzPDB(f *testing.F) {
	for _, name := range []string{"native-x64.pdb", "native-x86.pdb"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			return
		}
		path := filepath.Join(t.TempDir(), "fuzz.pdb")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		table, _, err := symbols.ConvertPDB(context.Background(), path, symbols.PDBOptions{MaxBytes: 512 << 10, MaxRecords: 4096})
		if err == nil {
			encoded, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = symbols.Parse(encoded); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestPDBRejectsTruncatedOrWrongMSF(t *testing.T) {
	data, err := os.ReadFile("testdata/native-x64.pdb")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 4, 55, 4095, len(data) - 1} {
		path := filepath.Join(t.TempDir(), "truncated.pdb")
		if err = os.WriteFile(path, data[:n], 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = symbols.ConvertPDB(context.Background(), path, symbols.PDBOptions{}); err == nil {
			t.Fatal("truncated MSF accepted", n)
		}
	}
	if strings.HasPrefix(string(data), "Microsoft C/C++ program database 2.00") {
		t.Fatal("wrong fixture format")
	}
}
