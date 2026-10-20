package symbols_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestDWARFRealObjectLayouts(t *testing.T) {
	for _, name := range []string{"dwarf-x86_64-v2.elf", "dwarf-x86_64-v4.elf", "dwarf-x86_64-v5.elf", "dwarf-i386-v4.elf", "dwarf-powerpc64-v4.elf"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("testdata", name)
			table, report, err := symbols.ConvertDWARF(context.Background(), path, symbols.DWARFOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if report.Types < 3 || report.Enums == 0 || report.Entries == 0 || report.BuildID == "" || len(report.Warnings) > 0 {
				t.Fatal(report)
			}
			if strings.Contains(name, "i386") && table.PointerSize() != 4 {
				t.Fatal("wrong pointer size")
			}
			encoded, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			back, err := symbols.Parse(encoded)
			if err != nil || back.Digest() != table.Digest() {
				t.Fatal("conversion not reproducible", err)
			}
			banner, err := table.Banner()
			if err != nil || !bytes.HasPrefix(banner, []byte("Linux version 6.1.0-gomem-dwarf")) {
				t.Fatal(string(banner), err)
			}
			if strings.Contains(string(encoded), `"kind":"bitfield","subtype"`) {
				t.Fatal("nonstandard bitfield encoding")
			}
			file, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			source, err := memory.OpenFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			var runs []memory.Range
			for _, s := range file.Sections {
				if s.Type == elf.SHT_PROGBITS && s.Flags&elf.SHF_ALLOC != 0 && s.Size > 0 {
					runs = append(runs, memory.Range{Start: s.Addr, Length: s.Size, FileOffset: s.Offset})
				}
			}
			layer, err := memory.NewMapped(source, "elf-symbol-fixture", runs)
			if err != nil {
				t.Fatal(err)
			}
			r := &object.Reader{Layer: layer, Symbols: table}
			for _, typ := range []string{"flags", "packed_flags"} {
				for _, member := range []string{"a", "b", "c"} {
					field, err := r.Field(typ, member)
					if err != nil {
						t.Fatal(err)
					}
					base := field.Type.Underlying()
					width, err := r.Size(*base)
					if err != nil || width != 4 || strings.HasPrefix(base.Name, "__bitfield_") {
						t.Fatal("declared bitfield type was replaced", field, width, err)
					}
				}
			}
			sym, err := table.Lookup("init_task")
			if err != nil {
				t.Fatal(err)
			}
			if sym.Type == nil || sym.Type.Kind != "struct" || sym.Type.Name != "task_struct" {
				t.Fatal("global variable type was lost", sym)
			}
			address := sym.Address
			function, err := table.Lookup("answer")
			if err != nil || function.Type == nil || function.Type.Kind != "function" {
				t.Fatal("lost function type", function, err)
			}
			callback, err := r.Uint(context.Background(), address, "task_struct", "callback")
			if err != nil || callback != function.Address {
				t.Fatal("wrong function pointer", callback, function, err)
			}
			for _, field := range []struct {
				name string
				want int64
			}{{"pid", -123}, {"flags.b", -7}, {"packed.b", -4}, {"signed_value", -987}} {
				got, err := r.Int(context.Background(), address, "task_struct", field.name)
				if err != nil || got != field.want {
					t.Fatalf("%s got %d want %d: %v", field.name, got, field.want, err)
				}
			}
			for _, field := range []struct {
				name string
				want uint64
			}{{"flags.a", 5}, {"flags.c", 257}, {"packed.a", 6}, {"packed.c", 1}, {"next", address}, {"alias", address}} {
				got, err := r.Uint(context.Background(), address, "task_struct", field.name)
				if err != nil || got != field.want {
					t.Fatalf("%s got %#x want %#x: %v", field.name, got, field.want, err)
				}
			}
			_, names, err := r.Enum(context.Background(), address, "task_struct", "state")
			if err != nil || len(names) != 1 || names[0] != "gone" {
				t.Fatal(names, err)
			}
			state, err := table.Enumeration("state")
			if err != nil || len(state.Names(3)) != 2 {
				t.Fatal(state, err)
			}
			comm, err := r.String(context.Background(), address, "task_struct", "comm", 32)
			if err != nil || comm != "swapper/0" {
				t.Fatal(comm, err)
			}
			field, err := r.Field("task_struct", "grid")
			if err != nil || field.Type.Count != 2 || field.Type.Subtype.Count != 3 {
				t.Fatal(field, err)
			}
			if _, err = r.Uint(context.Background(), address, "task_struct", "bytes"); err == nil {
				t.Fatal("byte array treated as scalar")
			}
			if _, err = r.Field("task_t", "pid"); err != nil {
				t.Fatal("typedef alias unavailable", err)
			}
		})
	}
}

func TestDWARFCorpusManifest(t *testing.T) {
	var manifest struct {
		Source string `json:"source_sha256"`
		Files  []struct{ Name, SHA256 string }
	}
	b, err := os.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("testdata/kernel.c")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(source)) != manifest.Source {
		t.Fatal("fixture source changed without regeneration")
	}
	if len(manifest.Files) != 7 {
		t.Fatal("incomplete DWARF fixture inventory")
	}
	for _, file := range manifest.Files {
		b, err := os.ReadFile(filepath.Join("testdata", file.Name))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != file.SHA256 {
			t.Fatal("fixture digest mismatch", file.Name)
		}
	}
}

func TestFatMachOSelectsOnlyRequestedArchitecture(t *testing.T) {
	x86, err := os.ReadFile("testdata/dwarf-x86_64.macho")
	if err != nil {
		t.Fatal(err)
	}
	arm, err := os.ReadFile("testdata/dwarf-arm64.macho")
	if err != nil {
		t.Fatal(err)
	}
	for _, fat64 := range []bool{false, true} {
		stride := 20
		magic := uint32(0xcafebabe)
		if fat64 {
			stride = 32
			magic = 0xcafebabf
		}
		first := 4096
		second := (first + len(x86) + 4095) &^ 4095
		data := make([]byte, second+len(arm))
		binary.BigEndian.PutUint32(data, magic)
		binary.BigEndian.PutUint32(data[4:], 2)
		for i, slice := range []struct {
			cpu    macho.Cpu
			offset int
			body   []byte
		}{{macho.CpuAmd64, first, x86}, {macho.CpuArm64, second, arm}} {
			r := data[8+i*stride:]
			binary.BigEndian.PutUint32(r, uint32(slice.cpu))
			if fat64 {
				binary.BigEndian.PutUint64(r[8:], uint64(slice.offset))
				binary.BigEndian.PutUint64(r[16:], uint64(len(slice.body)))
				binary.BigEndian.PutUint32(r[24:], 12)
			} else {
				binary.BigEndian.PutUint32(r[8:], uint32(slice.offset))
				binary.BigEndian.PutUint32(r[12:], uint32(len(slice.body)))
				binary.BigEndian.PutUint32(r[16:], 12)
			}
			copy(data[slice.offset:], slice.body)
		}
		path := filepath.Join(t.TempDir(), "universal")
		os.WriteFile(path, data, 0600)
		if _, _, err = symbols.ConvertDWARF(context.Background(), path, symbols.DWARFOptions{}); err == nil {
			t.Fatal("universal file silently selected an architecture")
		}
		for _, arch := range []string{"x86_64", "arm64"} {
			table, report, err := symbols.ConvertDWARF(context.Background(), path, symbols.DWARFOptions{Arch: arch})
			if err != nil || report.Architecture != arch || table.PointerSize() != 8 {
				t.Fatal(arch, report, err)
			}
		}
		for i := range data[:8] {
			data[i] = 0xff
		}
		binary.BigEndian.PutUint32(data, magic)
		os.WriteFile(path, data, 0600)
		if _, _, err = symbols.ConvertDWARF(context.Background(), path, symbols.DWARFOptions{Arch: "x86_64"}); err == nil {
			t.Fatal("unbounded fat slice count accepted")
		}
	}
}

func FuzzDWARF(f *testing.F) {
	for _, name := range []string{"dwarf-x86_64-v4.elf", "dwarf-i386-v4.elf", "dwarf-x86_64.macho"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		_, _, _ = symbols.ConvertDWARF(context.Background(), path, symbols.DWARFOptions{MaxDebugBytes: 128 << 10, MaxEntries: 4096})
	})
}
func TestMachODWARFAndLoading(t *testing.T) {
	path := "testdata/dwarf-x86_64.macho"
	table, report, err := symbols.ConvertDWARF(context.Background(), path, symbols.DWARFOptions{Arch: "x86_64"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "mac" || table.PointerSize() != 8 {
		t.Fatal(report)
	}
	version, err := table.Lookup("version")
	if err != nil {
		t.Fatal(err)
	}
	banner, err := base64.StdEncoding.DecodeString(version.ConstantData)
	if err != nil || !bytes.HasPrefix(banner, []byte("Darwin Kernel Version")) {
		t.Fatal(string(banner), err)
	}
	loaded, err := symbols.Load(path)
	if err != nil || loaded.Digest() != table.Digest() {
		t.Fatal(loaded, err)
	}
	if _, _, err = symbols.ConvertDWARF(context.Background(), path, symbols.DWARFOptions{OS: "linux"}); err == nil {
		t.Fatal("platform mismatch accepted")
	}
}
func TestDWARFCancellationBoundsAndMap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := symbols.ConvertDWARF(ctx, "testdata/dwarf-x86_64-v4.elf", symbols.DWARFOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := symbols.ConvertDWARF(context.Background(), "testdata/dwarf-x86_64-v4.elf", symbols.DWARFOptions{MaxEntries: 2}); err == nil {
		t.Fatal("entry limit ignored")
	}
	if _, _, err := symbols.ConvertDWARF(context.Background(), "testdata/dwarf-x86_64-v4.elf", symbols.DWARFOptions{MaxDebugBytes: 1024}); err == nil {
		t.Fatal("section limit ignored")
	}
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "System.map")
	os.WriteFile(mapPath, []byte("0000000000abcdef D init_task\n"), 0600)
	table, report, err := symbols.ConvertDWARF(context.Background(), "testdata/dwarf-x86_64-v4.elf", symbols.DWARFOptions{SystemMap: mapPath})
	if err != nil {
		t.Fatal(err)
	}
	symbol, _ := table.Lookup("init_task")
	if symbol.Address != 0xabcdef || report.Sources[len(report.Sources)-1].Kind != "system-map" {
		t.Fatal(symbol, report)
	}
	os.WriteFile(mapPath, []byte("bad address"), 0600)
	if _, _, err = symbols.ConvertDWARF(context.Background(), "testdata/dwarf-x86_64-v4.elf", symbols.DWARFOptions{SystemMap: mapPath}); err == nil {
		t.Fatal("malformed map accepted")
	}
	encoded, _ := table.Encode()
	var doc map[string]any
	if err = json.Unmarshal(encoded, &doc); err != nil {
		t.Fatal(err)
	}
}
