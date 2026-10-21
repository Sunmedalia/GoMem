package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestLinuxCheckModulesKobjectKeysAndSourceScope(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, scenario := range []string{"positive", "same-module-name", "active-kobject-name", "duplicate-key", "names-only"} {
			t.Run(arch+"/"+scenario, func(t *testing.T) {
				f := modxFixture(t, arch, "legacy", "")
				table, err := symbols.Load(f.Symbols)
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(f.Image)
				if err != nil {
					t.Fatal(err)
				}
				// check_modules must not need scanner globals or text-size metadata.
				delete(table.Symbols, "module_addr_min")
				delete(table.Symbols, "module_addr_max")
				delete(table.Types["module"].Fields, "core_text_size")
				expectedName, expectedKey := "sys-only", "sys-only"
				expectedCount := 1
				switch scenario {
				case "same-module-name":
					copy(data[0xc420:], "active\x00")
					expectedName = "active"
				case "active-kobject-name":
					copy(data[0x18040:], "active\x00")
					expectedCount = 0
				case "duplicate-key":
					copy(data[0x18000:], "stealth\x00")
					copy(data[0x18040:], "stealth\x00")
					expectedKey = "stealth"
				case "names-only":
					copy(data[0x18040:], "active\x00")
					expectedCount = 0
					// No module display fields are needed when the selected key set is empty.
					for _, field := range []string{"module_core", "core_size", "init_size", "taints"} {
						delete(table.Types["module"].Fields, field)
					}
				}
				// Give the positive record a nonzero init size and a known plain taint.
				binary.LittleEndian.PutUint32(data[0xc444:], 32)
				binary.LittleEndian.PutUint64(data[0xc470:], 1)
				encoded, err := table.Encode()
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(f.Image, data, 0600); err != nil {
					t.Fatal(err)
				}
				e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", Offline: true, CaseDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				hidden, captures := 0, 0
				var original bytes.Buffer
				verify := func(row evidence.Row) error {
					if row.Cells["Source"].String() == "Scanner" || row.Cells["RecordType"].String() == "scan_candidate" {
						t.Fatal("comparison scanned module allocations", row)
					}
					if row.Cells["FieldEvidence"].Kind == "structure" {
						raw, err := json.Marshal(row.Cells["FieldEvidence"].Data)
						if err != nil {
							t.Fatal(err)
						}
						var fields map[string]evidence.Value
						if err = json.Unmarshal(raw, &fields); err != nil {
							t.Fatal(err)
						}
						for _, proof := range fields {
							if proof.Kind != "structure" {
								t.Fatal(proof)
							}
							raw, err := json.Marshal(proof.Data)
							if err != nil {
								t.Fatal(err)
							}
							var c map[string]evidence.Value
							if err = json.Unmarshal(raw, &c); err != nil {
								t.Fatal(err)
							}
							address, err := c["Address"].Uint()
							if err != nil {
								t.Fatal(err)
							}
							captured, err := base64.StdEncoding.DecodeString(c["Raw"].String())
							if err != nil || len(captured) == 0 || c["ReadComplete"].Data != true {
								t.Fatal(c, err)
							}
							actual, err := memory.Read(context.Background(), e.Env.Kernel, address, len(captured))
							if err != nil || !bytes.Equal(captured, actual) {
								t.Fatal("kernel evidence mismatch", c, err)
							}
							captures++
						}
					}
					if row.Cells["RecordType"].String() == "kset_only" {
						hidden++
						offset, err := row.Cells["Offset"].Uint()
						if err != nil || offset != 0xc400 || row.Cells["Module Name"].String() != expectedName || row.Cells["KObjectName"].String() != expectedKey || row.Cells["Code Size"].String() != "0x0000000000001020" || row.Cells["Taints"].String() != "PG" || row.Cells["Load Arguments"].String() != "" || row.Cells["File Output"].Reason != "not_requested" {
							t.Fatal(row, err)
						}
					}
					return nil
				}
				params := map[string]string{"plain-taints": "true"}
				result, err := e.Run(context.Background(), "linux.check_modules", params, engine.RunOptions{Emit: func(row evidence.Row) error {
					if err := verify(row); err != nil {
						return err
					}
					return json.NewEncoder(&original).Encode(row)
				}})
				if err != nil || result.Task.State != "completed" || hidden != expectedCount || captures < 10 {
					t.Fatal(result, err, hidden, captures)
				}
				var cached bytes.Buffer
				replay, err := e.Run(context.Background(), "linux.check_modules", params, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&cached).Encode(row) }})
				if err != nil || !replay.Reused || !bytes.Equal(original.Bytes(), cached.Bytes()) {
					t.Fatal(replay, err)
				}
			})
		}
	}
}

func TestLinuxCheckModulesFailuresAndOutputStop(t *testing.T) {
	for _, fault := range []string{"bad-name", "bad-module", "bad-sysfs-backlink", "missing-kset", "output"} {
		t.Run(fault, func(t *testing.T) {
			f := modxFixture(t, "x64", "legacy", fault)
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			outputErr := errors.New("stop output")
			calls := 0
			result, err := e.Run(context.Background(), "linux.check_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				calls++
				if fault == "output" {
					return outputErr
				}
				return nil
			}})
			if err == nil || result.Task.State != "failed" {
				t.Fatal(result, err)
			}
			if fault == "output" && (!errors.Is(err, outputErr) || calls != 1) {
				t.Fatal(calls, err)
			}
		})
	}
}
