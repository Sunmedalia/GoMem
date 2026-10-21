package elfimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

func TestModuleELFPinnedOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/module-elf-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Commit string
		Cases  []struct {
			Name     string
			Bits     int
			Sections []struct {
				Name    string
				Address uint64
				Data    string
			}
			Symbols, SHA256 string
			Size            int
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || oracle.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(oracle.Cases) != 18 {
		t.Fatal(err, len(oracle.Cases))
	}
	for _, tc := range oracle.Cases {
		t.Run(tc.Name+"/"+strconv.Itoa(tc.Bits), func(t *testing.T) {
			var sections []ModuleSection
			for _, s := range tc.Sections {
				data, err := hex.DecodeString(s.Data)
				if err != nil {
					t.Fatal(err)
				}
				sections = append(sections, ModuleSection{s.Name, s.Address, data})
			}
			symbols, err := hex.DecodeString(tc.Symbols)
			if err != nil {
				t.Fatal(err)
			}
			image, err := RebuildModule(context.Background(), tc.Bits, sections, symbols, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(image.Data)
			if hex.EncodeToString(sum[:]) != tc.SHA256 || len(image.Data) != tc.Size {
				t.Fatal(tc.Name, tc.Bits, len(image.Data), tc.Size, hex.EncodeToString(sum[:]), tc.SHA256)
			}
			if _, err = RebuildModule(context.Background(), tc.Bits, sections, symbols, uint64(len(image.Data)-1)); err == nil {
				t.Fatal("output limit ignored")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err = RebuildModule(ctx, tc.Bits, sections, symbols, 1<<20); err != context.Canceled {
				t.Fatal(err)
			}
		})
	}
}

func TestModuleELFMalformed(t *testing.T) {
	symbols := make([]byte, 24)
	valid := []ModuleSection{{".text", 0x1000, []byte{0x90}}, {".strtab", 0x1010, []byte{0}}, {".symtab", 0x1020, nil}}
	for _, tc := range []struct {
		bits     int
		sections []ModuleSection
		symbols  []byte
		max      uint64
	}{
		{16, valid, symbols, 4096}, {64, nil, symbols, 4096}, {64, valid, nil, 4096}, {64, valid, symbols[:23], 4096}, {64, valid, symbols, 0}, {64, valid, symbols, 1 << 31}, {64, valid[:2], symbols, 4096}, {64, []ModuleSection{{".text", 1, nil}, {".symtab", 2, nil}}, symbols, 4096}, {64, []ModuleSection{{"a\x00b", 1, nil}}, symbols, 4096}, {64, []ModuleSection{{"\xff", 1, nil}}, symbols, 4096},
	} {
		if _, err := RebuildModule(context.Background(), tc.bits, tc.sections, tc.symbols, tc.max); err == nil {
			t.Fatal("accepted malformed input", tc)
		}
	}
}

func FuzzModuleELFRebuild(f *testing.F) {
	f.Add([]byte{1, 2, 3}, uint64(0x1000), true)
	f.Fuzz(func(t *testing.T, data []byte, address uint64, wide bool) {
		if len(data) > 4096 {
			return
		}
		bits, stride := 32, 16
		if wide {
			bits, stride = 64, 24
		}
		sections := []ModuleSection{{".text", address, data}, {".strtab", address ^ 0x1000, []byte{0}}, {".symtab", address ^ 0x2000, nil}}
		symbols := make([]byte, stride)
		copy(symbols, data)
		result, err := RebuildModule(context.Background(), bits, sections, symbols, 16384)
		if err == nil && (len(result.Data) > 16384 || string(result.Data[:4]) != "\x7fELF") {
			t.Fatal("invalid bounded result")
		}
	})
}
