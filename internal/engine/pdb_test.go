package engine_test

import (
	"context"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
)

func TestNativePDBToVerifiedProcessEvidence(t *testing.T) {
	for _, arch := range []string{"x64", "x86"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			image := filepath.Join(dir, "physical.raw")
			file, err := pe.Open("../../pkg/symbols/testdata/native-" + arch + ".exe")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var base uint64
			var headers uint32
			switch h := file.OptionalHeader.(type) {
			case *pe.OptionalHeader64:
				base, headers = h.ImageBase, h.SizeOfHeaders
			case *pe.OptionalHeader32:
				base, headers = uint64(h.ImageBase), h.SizeOfHeaders
			}
			data := make([]byte, 4<<20)
			executable, err := os.ReadFile("../../pkg/symbols/testdata/native-" + arch + ".exe")
			if err != nil {
				t.Fatal(err)
			}
			copy(data[0x200000:], executable[:headers])
			for _, s := range file.Sections {
				if s.Size > 0 {
					bytes, err := s.Data()
					if err != nil {
						t.Fatal(err)
					}
					copy(data[0x200000+uint64(s.VirtualAddress):], bytes)
				}
			}
			put64 := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
			if arch == "x64" {
				put64(0x1000+((base>>39)&511)*8, 0x2003)
				put64(0x2000+((base>>30)&511)*8, 0x3003)
				put64(0x3000+((base>>21)&511)*8, 0x200083)
			} else {
				binary.LittleEndian.PutUint32(data[0x1000+((base>>22)&1023)*4:], 0x2003)
				for i := uint64(0); i < 512; i++ {
					binary.LittleEndian.PutUint32(data[0x2000+i*4:], uint32(0x200000+i*4096|3))
				}
			}
			if err = os.WriteFile(image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: image, Symbols: "../../pkg/symbols/testdata/native-" + arch + ".pdb", DTB: "0x1000", Arch: arch, KernelBase: base, CaseDir: dir, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			result, err := e.Run(context.Background(), "windows.pslist", nil, engine.RunOptions{})
			if err != nil || result.Task.Rows != 1 {
				t.Fatal(result, err)
			}
		})
	}
}
