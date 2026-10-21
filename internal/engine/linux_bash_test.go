package engine_test

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func openBashFixture(t *testing.T, arch, fault string) *engine.Engine {
	t.Helper()
	f := linuxCapabilityFixture(t, arch)
	raw, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(raw[at:], v) }
	clear(raw[0xa018:0xa028])
	copy(raw[0xa018:], "bash")
	// Keep one VMA only, wholly inside a much larger resident page-table run.
	put(0x10000, 0x18000)
	put(0x10008, 0x19000)
	put(0x10010, 0)
	put(0xe010, 0x18080)
	put(0xe018, 0x18100)
	width := 8
	if arch == "x86" || arch == "pae" {
		width = 4
	}
	pointer := func(at, v uint64) {
		if width == 4 {
			binary.LittleEndian.PutUint32(raw[at:], uint32(v))
		} else {
			put(at, v)
		}
	}
	for _, base := range []uint64{0x18000, 0x1a000} {
		pointer(base+0x101, base+0x300)
		pointer(base+0x101+uint64(width), base+0x400)
		copy(raw[base+0x300:], "heap command\x00")
		copy(raw[base+0x400:], "#1403606200\x00")
	}
	if fault == "hole" {
		put(0x10008, 0x21000)
	} // raw image ends at 0x20000
	if fault == "read-error" {
		pointer(0x18101, 0x300000)
	}
	if err = os.WriteFile(f.Image, raw, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: arch, OS: "linux", Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLinuxBashHeapScopeNativeWidthsAndFailures(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		t.Run(arch, func(t *testing.T) {
			e := openBashFixture(t, arch, "")
			count := 0
			r, err := e.Run(context.Background(), "linux.bash", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Cells["RecordType"].String() == "history" {
					count++
					entry, err := row.Cells["Entry"].Uint()
					if err != nil || entry != 0x18101 || row.Cells["Command"].String() != "heap command" {
						t.Fatal(row, err)
					}
					if got := bashVerifyProcessCaptures(t, context.Background(), e, row); got != 3 {
						t.Fatal(got)
					}
				}
				return nil
			}})
			if err != nil || r.Task.State != "completed" || count != 1 {
				t.Fatal(r, count, err)
			}
		})
	}
	for _, fault := range []string{"hole", "read-error"} {
		t.Run(fault, func(t *testing.T) {
			e := openBashFixture(t, "x64", fault)
			histories, diagnostics := 0, 0
			r, err := e.Run(context.Background(), "linux.bash", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error {
				switch row.Cells["RecordType"].String() {
				case "history":
					histories++
				case "diagnostic":
					diagnostics++
				}
				return nil
			}})
			if err == nil || r.Task.State != "failed" || diagnostics == 0 || fault == "hole" && histories != 2 || fault == "read-error" && histories != 0 {
				t.Fatal(r, err, histories, diagnostics)
			}
			// Incomplete tasks must never be reported as cached clean results.
			again, err := e.Run(context.Background(), "linux.bash", map[string]string{"pid": "100"}, engine.RunOptions{})
			if err == nil || again.Reused {
				t.Fatal(again, err)
			}
		})
	}
}

func TestLinuxBashOutputAndCancellationStopImmediately(t *testing.T) {
	for _, mode := range []string{"coverage", "history", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			e := openBashFixture(t, "x64", "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("output failed")
			calls := 0
			_, err := e.Run(ctx, "linux.bash", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(row evidence.Row) error {
				calls++
				if mode == "cancel" {
					cancel()
					return nil
				}
				if row.Cells["RecordType"].String() == mode {
					return sentinel
				}
				return nil
			}})
			expected := 1
			if mode == "history" {
				expected = 2
			}
			if calls != expected || mode == "cancel" && !errors.Is(err, context.Canceled) || mode != "cancel" && !errors.Is(err, sentinel) {
				t.Fatal(calls, err)
			}
		})
	}
}
