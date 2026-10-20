package engine_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func dllFixture(t *testing.T, scenario string) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put32 := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(data[a:], v) }
	switch scenario {
	case "wow64":
		put(0x9060, 0x1b800)
		put(0x1b800, 0x1b900)
		put32(0x1b90c, 0x1ba00)
		put32(0x1ba0c, 0x1c200)
		put32(0x1ba10, 0x1c200)
		put32(0x1c200, 0x1ba0c)
		put32(0x1c204, 0x1ba0c)
		put32(0x1c218, 0x600000)
		put32(0x1c220, 8192)
		for _, text := range []struct {
			offset, buffer uint64
			value          string
		}{{44, 0x1d800, "wow32.dll"}, {36, 0x1d900, `C:\Windows\SysWOW64\wow32.dll`}} {
			binary.LittleEndian.PutUint16(data[0x1c200+text.offset:], uint16(len(text.value)*2))
			binary.LittleEndian.PutUint16(data[0x1c202+text.offset:], uint16(len(text.value)*2))
			put32(0x1c204+text.offset, uint32(text.buffer))
			for i, c := range text.value {
				binary.LittleEndian.PutUint16(data[text.buffer+uint64(i)*2:], uint16(c))
			}
		}
	case "peb-unreadable":
		put(0x9058, 0x300000)
	case "loader-null":
		put(0x1b000, 0)
	case "list-cycle":
		put(0x1c000, 0x1c000)
	case "name-unreadable":
		put(0x1c028, 0x300000)
	case "independent-process-root":
		// Bootstrap metadata points to a user PEB above the kernel's identity
		// mapping. Only this process's CR3 maps it back to the fixture data.
		put(0x9058, 0x21b000)
		put(0x9038, 0x1e000)
		put(0x1e000, 0x1f003)
		put(0x1f000, 0x1a003)
		put(0x1a008, 0x83)
		put(0x1a000, 0x83)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDLLListNativeWOW64AndProcessIdentities(t *testing.T) {
	for _, scenario := range []string{"native", "wow64", "independent-process-root"} {
		t.Run(scenario, func(t *testing.T) {
			f := dllFixture(t, scenario)
			ctx := context.Background()
			e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var identity string
			if _, err = e.Run(ctx, "windows.pslist", map[string]string{"pid": "104"}, engine.RunOptions{Emit: func(r evidence.Row) error { identity = r.Cells["Identity"].String(); return nil }}); err != nil {
				t.Fatal(err)
			}
			var rows []evidence.Row
			result, err := e.Run(ctx, "windows.dlllist", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			want := int64(2)
			if scenario == "wow64" {
				want = 3
			}
			if err != nil || result.Task.Rows != want {
				t.Fatal(result, err)
			}
			for _, r := range rows {
				if r.Verify() != nil || r.Cells["ProcessIdentity"].String() != identity || r.Provenance.Layer != "process:"+identity || r.Cells["LayoutSHA256"].String() == "" {
					t.Fatal(r)
				}
				if r.Cells["Architecture"].String() == "wow64-x86" {
					if r.Cells["Name"].String() != "wow32.dll" || r.Cells["LoadTime"].Reason != "unsupported_loader_field" {
						t.Fatal(r)
					}
				} else if r.Cells["LoadCount"].String() != "-1" || !strings.Contains(r.Cells["LoadTime"].String(), ".1234567Z") {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestDLLFiltersBoundsAndVisibleDiagnostics(t *testing.T) {
	e, _ := openFixture(t, "windows")
	ctx := context.Background()
	for _, tc := range []struct {
		p map[string]string
		n int64
	}{{map[string]string{"pid": "4"}, 0}, {map[string]string{"base": "0x500000"}, 1}, {map[string]string{"base": "0"}, 2}, {map[string]string{"name": "EXAMPLE", "ignore-case": "true"}, 1}, {map[string]string{"name": "EXAMPLE"}, 0}, {map[string]string{"pid": "4,104", "name": "System32"}, 2}} {
		r, err := e.Run(ctx, "windows.dlllist", tc.p, engine.RunOptions{})
		if err != nil || r.Task.Rows != tc.n {
			t.Fatal(tc, r, err)
		}
	}
	for _, p := range []map[string]string{{"name": "(?<=x)y"}, {"base": "bad"}, {"offset": "0x1"}, {"dump": "true"}, {"max-modules": "0"}} {
		if _, err := e.Run(ctx, "windows.dlllist", p, engine.RunOptions{}); err == nil {
			t.Fatal("unsupported semantics accepted", p)
		}
	}
	var rows []evidence.Row
	r, err := e.Run(ctx, "windows.dlllist", map[string]string{"max-modules": "1"}, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
	if err == nil || r.Task.State != "failed" || r.Task.Rows != 2 || rows[1].Cells["RecordType"].String() != "diagnostic" {
		t.Fatal(r, rows, err)
	}
	for _, scenario := range []string{"peb-unreadable", "loader-null", "list-cycle", "name-unreadable"} {
		t.Run(scenario, func(t *testing.T) {
			f := dllFixture(t, scenario)
			e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			r, err := e.Run(ctx, "windows.dlllist", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if scenario == "name-unreadable" {
				if err != nil || len(rows) != 2 || rows[0].Cells["Name"].Kind != "missing" || rows[0].Cells["Name"].Error == "" || rows[0].Cells["Path"].Kind != "string" {
					t.Fatal(r, rows, err)
				}
				return
			}
			if err == nil || r.Task.State != "failed" || rows[len(rows)-1].Cells["RecordType"].String() != "diagnostic" || rows[len(rows)-1].Cells["Error"].Error == "" {
				t.Fatal(r, rows, err)
			}
		})
	}
}

func TestDLLCancellationAndOutputFailuresPreserveRows(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			e, _ := openFixture(t, "windows")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			outputErr := fmt.Errorf("output closed")
			r, err := e.Run(ctx, "windows.dlllist", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error {
				if cancelled {
					cancel()
					return nil
				}
				return outputErr
			}})
			if cancelled {
				if !errors.Is(err, context.Canceled) || r.Task.State != "canceled" {
					t.Fatal(r, err)
				}
			} else if !errors.Is(err, outputErr) || r.Task.State != "failed" {
				t.Fatal(r, err)
			}
			if r.Task.Rows != 1 {
				t.Fatal("partial DLL evidence not retained", r)
			}
		})
	}
}

func TestDLLNative32BitAndPAEProcessSpaces(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			f := writeWindowsCrash(t, mode, "decoded")
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			physical := data[4096:]
			put := func(a uint64, v uint32) { binary.LittleEndian.PutUint32(physical[a:], v) }
			put(0x1b100, 0x1c000)
			put(0x1b104, 0x1c100)
			put(0x1c000, 0x1c100)
			put(0x1c004, 0x1b100)
			put(0x1c100, 0x1b100)
			put(0x1c104, 0x1c000)
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var rows []evidence.Row
			r, err := e.Run(context.Background(), "windows.dlllist", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
			if err != nil || r.Task.Rows != 2 || rows[0].Cells["Architecture"].String() != "x86" || rows[1].Cells["Name"].String() != "example.dll" {
				t.Fatal(r, rows, err)
			}
		})
	}
}
