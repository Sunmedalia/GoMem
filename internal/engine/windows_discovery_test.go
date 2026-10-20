package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// writeWindowsCrash wraps deterministic synthetic physical memory. Its explicit
// symbols declare all padding; it is not an acquired Windows system image.
func writeWindowsCrash(t *testing.T, mode, scenario string) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	put64 := func(off, v uint64) { binary.LittleEndian.PutUint64(data[off:], v) }
	put32 := func(off, v uint64) { binary.LittleEndian.PutUint32(data[off:], uint32(v)) }
	if mode != "x64" {
		pointer := table.Bases["pointer"]
		pointer.Size = 4
		table.Bases["pointer"] = pointer
		list := table.Types["_LIST_ENTRY"]
		field := list.Fields["Blink"]
		field.Offset = 4
		list.Fields["Blink"] = field
		table.Types["_LIST_ENTRY"] = list
		for _, item := range []struct {
			head  uint64
			nodes []uint64
		}{{0x6000, []uint64{0x8000, 0x9000}}, {0x6010, []uint64{0xa000}}} {
			put32(item.head, item.nodes[0])
			put32(item.head+4, item.nodes[len(item.nodes)-1])
			for n, a := range item.nodes {
				next, prev := item.head, item.head
				if n > 0 {
					prev = item.nodes[n-1]
				}
				if n+1 < len(item.nodes) {
					next = item.nodes[n+1]
				}
				put32(a, next)
				put32(a+4, prev)
			}
		}
		clear(data[0x1000:0x4000])
		if mode == "pae" {
			put64(0x1000, 0x2001)
			put64(0x2000, 0x83)
		} else {
			put32(0x1000, 0x83)
		}
		binary.LittleEndian.PutUint16(data[0x4084:], 0x14c)
		binary.LittleEndian.PutUint16(data[0x4098:], 0x10b)
		put32(0x4098+92, 16)
		put32(0x4098+96+48, 0x300)
		put32(0x4098+96+52, 28)
		table.Meta["windows"] = json.RawMessage(`{"pdb":{"database":"ntkrnlmp.pdb","GUID":"112233445566778899AABBCCDDEEFF00","age":1,"machine_type":332}}`)
	}
	copy(data[0x7010:], "KDBG")
	put32(0x7014, 0x380)
	put64(0x7018, 0x4000)
	put64(0x7048, 0x6010)
	put64(0x7050, 0x6000)
	switch scenario {
	case "encoded":
		clear(data[0x7010:0x7014])
	case "forged-kdbg":
		copy(data[0x10000:0x11000], data[0x4000:0x5000])
		put64(0x7018, 0x10000)
	case "bad-list":
		clear(data[0x7010:0x7014])
		if mode == "x64" {
			put64(0xa000, 0xa000)
		} else {
			put32(0xa000, 0xa000)
		}
	case "bad-slot":
		clear(data[0x7010:0x7014])
		put64(0xa010, 0x4501)
		put64(0xa018, 0x4000)
	case "wrong-symbols":
		s := table.Symbols["PsLoadedModuleList"]
		s.Address += 8
		table.Symbols["PsLoadedModuleList"] = s
	case "wrong-pdb":
		table.Meta["windows"] = json.RawMessage(`{"pdb":{"database":"ntkrnlmp.pdb","GUID":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF","age":1,"machine_type":34404}}`)
	case "bad-pe-size":
		put32(0x4098+56, 0)
	}
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	size, desc, dumpAt, stride := 8192, 136, 3992, 16
	if mode != "x64" {
		size, desc, dumpAt, stride = 4096, 100, 3976, 8
	}
	dump := make([]byte, size+len(data))
	copy(dump, "PAGEDU64")
	copy(dump[size:], data)
	root := uint64(0x1000)
	if scenario == "bad-dtb" {
		root = 0xdead000
	}
	binary.LittleEndian.PutUint32(dump[dumpAt:], 1)
	binary.LittleEndian.PutUint32(dump[desc:], 1)
	if stride == 16 {
		binary.LittleEndian.PutUint64(dump[16:], root)
		binary.LittleEndian.PutUint64(dump[32:], 0x6010)
		binary.LittleEndian.PutUint64(dump[40:], 0x6000)
		binary.LittleEndian.PutUint32(dump[48:], 0x8664)
		binary.LittleEndian.PutUint64(dump[128:], 0x7000)
		binary.LittleEndian.PutUint64(dump[desc+8:], uint64(len(data)/4096))
		binary.LittleEndian.PutUint64(dump[desc+24:], uint64(len(data)/4096))
	} else {
		copy(dump, "PAGEDUMP")
		binary.LittleEndian.PutUint32(dump[16:], uint32(root))
		binary.LittleEndian.PutUint32(dump[24:], 0x6010)
		binary.LittleEndian.PutUint32(dump[28:], 0x6000)
		binary.LittleEndian.PutUint32(dump[32:], 0x14c)
		binary.LittleEndian.PutUint32(dump[96:], 0x7000)
		if mode == "pae" {
			dump[92] = 1
		}
		binary.LittleEndian.PutUint32(dump[desc+4:], uint32(len(data)/4096))
		binary.LittleEndian.PutUint32(dump[desc+12:], uint32(len(data)/4096))
	}
	f.Image = filepath.Join(filepath.Dir(f.Image), "memory.dmp")
	if err = os.WriteFile(f.Image, dump, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWindowsCrashAutomaticConfiguration(t *testing.T) {
	for _, mode := range []string{"x64", "x86", "pae"} {
		for _, scenario := range []string{"decoded", "encoded", "forged-kdbg"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := writeWindowsCrash(t, mode, scenario)
				c := engine.Config{Image: f.Image, Symbols: f.Symbols, CaseDir: t.TempDir(), Offline: true}
				e, err := engine.Open(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				if e.WindowsDiscoveryError != nil {
					t.Fatal(e.WindowsDiscoveryError)
				}
				if e.WindowsDiscovery == nil || !e.WindowsDiscovery.Verified || e.Config.Arch != mode || e.Config.DTB != "0x1000" || e.Config.KernelBase != 0x4000 {
					t.Fatal(e.Config, e.WindowsDiscovery)
				}
				method := "crash-header-kdbg-pe"
				if scenario != "decoded" {
					method = "crash-header-module-list-pe"
				}
				if e.WindowsDiscovery.Method != method {
					t.Fatal(e.WindowsDiscovery)
				}
				for _, plugin := range []string{"windows.pslist", "windows.modules"} {
					result, err := e.Run(context.Background(), plugin, nil, engine.RunOptions{})
					if err != nil || result.Task.Rows == 0 {
						t.Fatal(result, err)
					}
				}
				if err = e.Close(); err != nil {
					t.Fatal(err)
				}
				// Explicit values override acquisition hints and have identical
				// normalized evidence-cache parameters.
				c.Arch, c.DTB, c.KernelBase = mode, "4096", 0x4000
				e, err = engine.Open(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				result, err := e.Run(context.Background(), "windows.pslist", nil, engine.RunOptions{})
				if err != nil || !result.Reused {
					t.Fatal("automatic/explicit configuration cache differs", result, err)
				}
			})
		}
	}
}

func TestWindowsDiscoveryFailuresRemainPhysicalReadable(t *testing.T) {
	for _, scenario := range []string{"bad-dtb", "bad-list", "bad-slot", "wrong-symbols", "wrong-pdb", "bad-pe-size"} {
		t.Run(scenario, func(t *testing.T) {
			f := writeWindowsCrash(t, "x64", scenario)
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.WindowsDiscoveryError == nil || e.WindowsDiscovery != nil {
				t.Fatal("invalid discovery accepted", e.WindowsDiscovery)
			}
			if result, err := e.Run(context.Background(), "generic.info", nil, engine.RunOptions{}); err != nil || result.Task.Rows != 1 {
				t.Fatal(result, err)
			}
			if _, err := e.Run(context.Background(), "windows.pslist", nil, engine.RunOptions{}); err == nil || !strings.Contains(err.Error(), "automatic configuration") {
				t.Fatal("failure became successful/empty process analysis", err)
			}
		})
	}
}

func TestWindowsHeaderDTBExplicitOverride(t *testing.T) {
	f := writeWindowsCrash(t, "x64", "bad-dtb")
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: "0x1003", KernelBase: 0x4000, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Config.DTB != "0x1000" {
		t.Fatal("CR3 flags were not normalized", e.Config.DTB)
	}
	if result, err := e.Run(context.Background(), "windows.pslist", nil, engine.RunOptions{}); err != nil || result.Task.Rows != 2 {
		t.Fatal(result, err)
	}
}
