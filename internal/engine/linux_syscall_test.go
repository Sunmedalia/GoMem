package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func syscallFixture(t *testing.T, arch, variant string) (testfixture.Fixture, uint64) {
	t.Helper()
	f := linuxCapabilityFixture(t, arch)
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	width := uint64(table.PointerSize())
	slide := uint64(0)
	if variant == "slide" {
		slide = 0x1000
	}
	banner := table.Symbols["linux_banner"]
	table.Symbols = map[string]symbols.Symbol{"linux_banner": banner}
	if slide != 0 {
		banner.Address -= slide
		table.Symbols["linux_banner"] = banner
	}
	rel := func(abs uint64) uint64 { return abs - slide }
	table.Symbols["sys_call_table"] = symbols.Symbol{Address: rel(0x18000)}
	if variant != "primary-only" {
		table.Symbols["ia32_sys_call_table"] = symbols.Symbol{Address: rel(0x18200)}
	}
	meta := 6
	if variant == "no-meta" {
		meta = 0
	}
	if variant == "meta-short" {
		meta = 2
	}
	for i := 0; i < meta; i++ {
		table.Symbols[fmt.Sprintf("__syscall_meta__%d", i)] = symbols.Symbol{Address: rel(0x7000) + uint64(i)}
	}
	if variant != "no-next" {
		table.Symbols["after_primary"] = symbols.Symbol{Address: rel(0x18000 + 4*width)}
		table.Symbols["after_ia32"] = symbols.Symbol{Address: rel(0x18200 + 3*width)}
	}
	if variant == "qualified" {
		table.Symbols["owner!entry!tail"] = symbols.Symbol{Address: rel(0x8500)}
	} else {
		table.Symbols["alias_handler"] = symbols.Symbol{Address: rel(0x8500)}
		table.Symbols["known_handler"] = symbols.Symbol{Address: rel(0x8500)}
	}
	if variant == "zero-known" {
		table.Symbols["zero_handler"] = symbols.Symbol{Address: 0}
	}
	write := func(at, v uint64) {
		if at+width > uint64(len(data)) {
			t.Fatal("fixture image too small", at)
		}
		if width == 8 {
			binary.LittleEndian.PutUint64(data[at:], v)
		} else {
			binary.LittleEndian.PutUint32(data[at:], uint32(v))
		}
	}
	for i, v := range []uint64{0x8500, 0x8501, 0, 0x8600, 0x8500, 0} {
		write(0x18000+uint64(i)*width, v)
	}
	for i, v := range []uint64{0x8500, 0, 0x8501, 0x8600, 0x8500, 0} {
		write(0x18200+uint64(i)*width, v)
	}
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil || os.WriteFile(f.Image, data, 0600) != nil {
		t.Fatal(err)
	}
	return f, slide
}

func openSyscall(t *testing.T, f testfixture.Fixture, arch string, slide uint64) *engine.Engine {
	t.Helper()
	if arch == "control" {
		arch = "x64"
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", CaseDir: t.TempDir(), Offline: true, KernelSlide: slide})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLinuxSyscallLayoutsAndPinnedGenerator(t *testing.T) {
	raw, err := os.ReadFile("../plugins/testdata/linux-syscall-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Generators []struct {
			Width int
			Name  string
			Rows  []struct {
				TableAddress uint64 `json:"table_address"`
				TableName    string `json:"table_name"`
				Index        uint64
				Address      uint64
				Symbol       string
			}
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil || len(oracle.Generators) != 16 {
		t.Fatal(err)
	}
	for _, arch := range []string{"control", "x86", "pae"} {
		for _, variant := range []string{"control", "no-meta", "meta-short", "no-next", "primary-only", "slide", "qualified", "zero-known"} {
			t.Run(arch+"/"+variant, func(t *testing.T) {
				f, slide := syscallFixture(t, arch, variant)
				e := openSyscall(t, f, arch, slide)
				var selected []evidence.Row
				captures := 0
				result, err := e.Run(context.Background(), "linux.check_syscall", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
					if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
						for key, proof := range fields {
							if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" && c["ReadComplete"].Data == true {
								captures++
								at, err := c["Address"].Uint()
								raw := c["Raw"].Data.([]byte)
								actual, readErr := memory.Read(context.Background(), e.Env.Kernel, at, len(raw))
								if err != nil || readErr != nil || !bytes.Equal(raw, actual) {
									t.Fatal(key, err, readErr)
								}
							}
						}
					}
					if r.Cells["RecordType"].String() == "syscall" {
						selected = append(selected, r)
					}
					return nil
				}})
				if err != nil || result.Task.State != "completed" {
					t.Fatal(result, err)
				}
				found := false
				for _, profile := range oracle.Generators {
					if profile.Width != e.Env.Symbols.PointerSize() || profile.Name != variant {
						continue
					}
					found = true
					if len(profile.Rows) != len(selected) || captures != len(selected) {
						t.Fatal(len(selected), len(profile.Rows), captures)
					}
					for i, want := range profile.Rows {
						r := selected[i]
						table, _ := r.Cells["Table Address"].Uint()
						at, _ := r.Cells["Handler Address"].Uint()
						idx, _ := r.Cells["Index"].Uint()
						if table != want.TableAddress || at != want.Address || idx != want.Index || r.Cells["Table Name"].String() != want.TableName || r.Cells["Handler Symbol"].String() != want.Symbol {
							t.Fatal(want, table, at, idx, r.Cells["Table Name"], r.Cells["Handler Symbol"])
						}
						if r.Cells["Sizing"].Data.(map[string]any)["NativeDisassembly"] != "unavailable" {
							t.Fatal(r.Cells["Sizing"])
						}
					}
				}
				if !found {
					t.Fatal("missing oracle")
				}
				cached, err := e.Run(context.Background(), "linux.check_syscall", nil, engine.RunOptions{})
				if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
					t.Fatal(cached, err)
				}
				t.Logf("entries=%d raw_captures_reread=%d; five fields and order match no-capstone generator; cache reused", len(selected), captures)
			})
		}
	}
}

func TestLinuxSyscallFailuresAndCancellation(t *testing.T) {
	f, _ := syscallFixture(t, "control", "control")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	delete(table.Symbols, "sys_call_table")
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	e := openSyscall(t, f, "control", 0)
	if result, err := e.Run(context.Background(), "linux.check_syscall", nil, engine.RunOptions{}); err == nil || result.Task.State != "failed" {
		t.Fatal(result, err)
	}

	f, _ = syscallFixture(t, "control", "no-meta")
	table, err = symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	delete(table.Symbols, "after_primary")
	delete(table.Symbols, "after_ia32")
	encoded, err = table.Encode()
	if err != nil || os.WriteFile(f.Symbols, encoded, 0600) != nil {
		t.Fatal(err)
	}
	e = openSyscall(t, f, "control", 0)
	if result, err := e.Run(context.Background(), "linux.check_syscall", nil, engine.RunOptions{}); err == nil || result.Task.State != "failed" {
		t.Fatal("unsized table succeeded", result, err)
	}

	e = openSyscall(t, func() testfixture.Fixture { f, _ := syscallFixture(t, "control", "control"); return f }(), "control", 0)
	layer := idtFaultLayer{e.Env.Kernel, 0x18000, 0x18008}
	e.Env.Kernel = layer
	e.Env.Objects = &object.Reader{Layer: layer, Symbols: e.Env.Symbols}
	continued := false
	result, err := e.Run(context.Background(), "linux.check_syscall", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		if r.Cells["RecordType"].String() == "syscall" && r.Cells["Table Name"].String() == "64bit" {
			idx, _ := r.Cells["Index"].Uint()
			if idx > 0 {
				continued = true
			}
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || !continued {
		t.Fatal(result, err, continued)
	}

	e = openSyscall(t, func() testfixture.Fixture { f, _ := syscallFixture(t, "control", "control"); return f }(), "control", 0)
	if result, err = e.Run(context.Background(), "linux.check_syscall", map[string]string{"max-entries": "3"}, engine.RunOptions{}); err == nil || result.Task.State != "failed" {
		t.Fatal(result, err)
	}
	for _, params := range []map[string]string{{"max-entries": "0"}, {"max-entries": "1000001"}} {
		e = openSyscall(t, func() testfixture.Fixture { f, _ := syscallFixture(t, "control", "control"); return f }(), "control", 0)
		if result, err = e.Run(context.Background(), "linux.check_syscall", params, engine.RunOptions{}); err == nil || result.Task.State != "failed" {
			t.Fatal(params, result, err)
		}
	}
	for _, cancel := range []bool{true, false} {
		e = openSyscall(t, func() testfixture.Fixture { f, _ := syscallFixture(t, "control", "control"); return f }(), "control", 0)
		ctx, stop := context.WithCancel(context.Background())
		sentinel := errors.New("output failure")
		_, err = e.Run(ctx, "linux.check_syscall", nil, engine.RunOptions{Emit: func(evidence.Row) error {
			if cancel {
				stop()
				return nil
			}
			return sentinel
		}})
		stop()
		want := sentinel
		if cancel {
			want = context.Canceled
		}
		if !errors.Is(err, want) {
			t.Fatal(cancel, err)
		}
	}
}
