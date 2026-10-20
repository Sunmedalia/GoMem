package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// These are selected-field checks on pinned official images, not a declaration
// that the plugins or their complete parameter semantics have passed acceptance.
func TestOfficialCorpus(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional official corpus: set GOMEM_CORPUS_DIR; not counted as release acceptance")
	}
	for _, tc := range []struct {
		os, image, symbols, dtb string
		base                    uint64
		processes, modules      int
	}{{"linux", "linux-sample-1.bin", "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", "23089152", 0, 133, 79}, {"windows", "win-10_19041-2025_03.dmp", "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json", "7159808", 0xfffff8043601f000, 120, 176}} {
		t.Run(tc.os, func(t *testing.T) {
			e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, tc.image), Symbols: filepath.Join(dir, tc.symbols), DTB: tc.dtb, OS: tc.os, Arch: "x64", KernelBase: tc.base, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			expectedHash := map[string]string{"linux": "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc", "windows": "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460"}[tc.os]
			if e.Hash != expectedHash {
				t.Fatal("official image checksum mismatch", e.Hash)
			}
			for _, kind := range []string{"pslist", "modules"} {
				name := tc.os + "." + kind
				referenceKind := kind
				expected := tc.processes
				if kind == "modules" {
					expected = tc.modules
					if tc.os == "linux" {
						name = "linux.lsmod"
						referenceKind = "lsmod"
					}
				}
				f, err := os.Open(filepath.Join(dir, "reference-"+tc.os+"-"+referenceKind+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var reference []map[string]any
				dec := json.NewDecoder(f)
				dec.UseNumber()
				err = dec.Decode(&reference)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
				if len(reference) != expected {
					t.Fatalf("reference corpus drift: %d != %d", len(reference), expected)
				}
				counts := map[string]int{}
				for _, r := range reference {
					offset, nameCol, pidCol, ppidCol := "Offset", "Name", "PID", "PPID"
					if kind == "pslist" {
						if tc.os == "linux" {
							offset, nameCol = "OFFSET (V)", "COMM"
						} else {
							offset, nameCol = "Offset(V)", "ImageFileName"
						}
					} else if tc.os == "linux" {
						nameCol = "Module Name"
					}
					address, err := strconv.ParseUint(string(r[offset].(json.Number)), 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					key := fmt.Sprintf("%x/%s", address, r[nameCol])
					if kind == "pslist" {
						key += fmt.Sprintf("/%s/%s", r[pidCol], r[ppidCol])
					}
					counts[key]++
				}
				res, err := e.Run(context.Background(), name, nil, engine.RunOptions{Emit: func(r evidence.Row) error {
					address, err := r.Cells["Offset"].Uint()
					if err != nil {
						return err
					}
					key := fmt.Sprintf("%x/%s", address&0xffffffffffff, r.Cells["Name"].String())
					if kind == "pslist" {
						key += "/" + r.Cells["PID"].String() + "/" + r.Cells["PPID"].String()
					}
					counts[key]--
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				if res.Task.Rows != int64(expected) {
					t.Fatalf("native count %d != %d", res.Task.Rows, expected)
				}
				for key, count := range counts {
					if count != 0 {
						t.Fatalf("difference %q: %d", key, count)
					}
				}
			}
		})
	}
}
