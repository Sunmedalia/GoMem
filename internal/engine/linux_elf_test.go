package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxELFFixture(t *testing.T, fault string) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, make([]byte, 128<<10)...)
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put(0x1d000, 0x1e003)
	put(0x1e000, 0x1f003)
	put(0x1f010, 0x1c003)
	clear(data[0x1c000:0x1c800])
	put(0x1c000, 0x20003)
	put(0x1c018, 0x23003)
	put(0xe000, 0x1d000)
	put(0xe040, 0x400000)
	put(0x10010, 0)
	// Separate mm/VMA objects share a valid process page table. Failure of one
	// mm must not suppress the other task's evidence.
	copy(data[0x30000:0x30048], data[0xe000:0xe048])
	put(0xb038, 0x30000)
	put(0x30008, 0x30100)
	copy(data[0x30100:0x30140], data[0x10000:0x10040])
	put(0x30120, 0x30000)
	h := data[0x20000:0x21000]
	copy(h, "\x7fELF")
	h[4] = 2
	h[5] = 1
	h[6] = 1
	binary.LittleEndian.PutUint16(h[16:], 2)
	binary.LittleEndian.PutUint16(h[18:], 62)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint64(h[24:], 0x400100)
	binary.LittleEndian.PutUint64(h[32:], 64)
	binary.LittleEndian.PutUint16(h[52:], 64)
	binary.LittleEndian.PutUint16(h[54:], 56)
	binary.LittleEndian.PutUint16(h[56:], 2)
	for i := 0; i < 2; i++ {
		p := h[64+i*56:]
		binary.LittleEndian.PutUint32(p, 1)
		binary.LittleEndian.PutUint32(p[4:], 5)
		binary.LittleEndian.PutUint64(p[8:], uint64(i)*4096)
		binary.LittleEndian.PutUint64(p[16:], 0x400000+uint64(i)*0x3000)
		binary.LittleEndian.PutUint64(p[32:], 4096)
		binary.LittleEndian.PutUint64(p[40:], 4096)
		binary.LittleEndian.PutUint64(p[48:], 4096)
	}
	for i := 0x23000; i < 0x24000; i++ {
		data[i] = byte(i % 251)
	}
	switch fault {
	case "gap":
		put(0x1c018, 0)
	case "bad-first-root":
		put(0xe000, 0)
	case "bad-header":
		h[4] = 0
	case "unreadable-signature":
		put(0x1c000, 0)
	case "bad-owner":
		put(0x10020, 0)
	case "no-main":
		put(0xe040, 0x400100)
	case "null-mm":
		put(0xa038, 0)
	case "dyn":
		binary.LittleEndian.PutUint16(h[16:], 3)
		binary.LittleEndian.PutUint64(h[80:], 0)
		binary.LittleEndian.PutUint64(h[136:], 0x3000)
	}
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	mm := table.Types["mm_struct"]
	mm.Size = 72
	mm.Fields["start_code"] = symbols.Field{Offset: 64, Type: symbols.TypeRef{Kind: "pointer"}}
	table.Types["mm_struct"] = mm
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
	return f
}

func openLinuxELF(t *testing.T, f testfixture.Fixture, persistent bool) *engine.Engine {
	t.Helper()
	dir := ""
	if persistent {
		dir = t.TempDir()
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, CaseDir: dir, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestLinuxELFExtractionLayoutsAndGapSourceAddresses(t *testing.T) {
	for _, scenario := range []string{"mapped", "reference", "gap", "dyn"} {
		t.Run(scenario, func(t *testing.T) {
			f := linuxELFFixture(t, scenario)
			e := openLinuxELF(t, f, true)
			ctx := context.Background()
			layout := "mapped"
			if scenario == "reference" {
				layout = scenario
			}
			var row evidence.Row
			r, err := e.Run(ctx, "linux.elfs", map[string]string{"pid": "100", "dump": "true", "elf-layout": layout}, engine.RunOptions{Emit: func(v evidence.Row) error { row = v; return nil }})
			if err != nil || r.Task.Rows != 1 || row.Cells["RecordType"].String() != "elf" || row.Cells["ELF"].Kind != "structure" {
				t.Fatal(r, row, err)
			}
			files, err := e.Store.Artifacts(ctx, r.Task.ID)
			if err != nil || len(files) != 1 {
				t.Fatal(files, err)
			}
			a := files[0]
			if a.ExpectedSize != "8192" || a.Size != "8192" || a.Provenance.Offset != "0x400000" || a.Provenance.Layer != "process:"+row.Cells["ProcessIdentity"].String() {
				t.Fatal(a)
			}
			data, err := os.ReadFile(filepath.Join(e.Store.Dir, a.Path))
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "reference":
				if a.MissingBytes != "8192" || !bytes.Equal(data, make([]byte, 8192)) {
					t.Fatal(a)
				}
			case "gap":
				if a.MissingBytes != "4096" || string(data[:4]) != "\x7fELF" {
					t.Fatal(a)
				}
				raw, err := os.ReadFile(filepath.Join(e.Store.Dir, a.GapsPath))
				if err != nil {
					t.Fatal(err)
				}
				var gap evidence.ArtifactGap
				if err = json.Unmarshal(bytes.TrimSpace(raw), &gap); err != nil || gap.Offset != "0x1000" || gap.Address != "0x403000" || gap.Layer != a.Provenance.Layer {
					t.Fatal("gap lost source address", string(raw), err)
				}
			default:
				original, _ := os.ReadFile(f.Image)
				if a.MissingBytes != "0" || !bytes.Equal(data[:4096], original[0x20000:0x21000]) || !bytes.Equal(data[4096:], original[0x23000:0x24000]) {
					t.Fatal("wrong segment mapping", a)
				}
			}
			if err = e.Store.VerifyTaskArtifacts(ctx, r.Task.ID); err != nil {
				t.Fatal(err)
			}
			var main evidence.Row
			result, err := e.Run(ctx, "linux.pslist", map[string]string{"pid": "100", "dump": "true", "elf-layout": layout}, engine.RunOptions{Emit: func(v evidence.Row) error { main = v; return nil }})
			if err != nil || result.Task.Rows != 1 || main.Cells["FileOutput"].Kind != "artifact" || main.Cells["ImageBase"].String() != "0x0000000000400000" {
				t.Fatal(result, main, err)
			}
			if main.Cells["FileOutput"].Data.(evidence.Artifact).SHA256 != a.SHA256 {
				t.Fatal("pslist and elfs extraction diverged")
			}
		})
	}
}

func TestLinuxELFFailuresAreRowsAndOtherProcessesContinue(t *testing.T) {
	for _, fault := range []string{"bad-first-root", "bad-header", "unreadable-signature", "bad-owner", "no-case", "size-limit"} {
		t.Run(fault, func(t *testing.T) {
			e := openLinuxELF(t, linuxELFFixture(t, fault), fault != "no-case")
			params := map[string]string{"dump": "true"}
			if fault == "size-limit" {
				params["max-elf-size"] = "8191"
			}
			var rows []evidence.Row
			r, err := e.Run(context.Background(), "linux.elfs", params, engine.RunOptions{Emit: func(v evidence.Row) error { rows = append(rows, v); return nil }})
			if err == nil || r.Task.State != "failed" || len(rows) != 2 {
				t.Fatal(r, rows, err)
			}
			if fault == "bad-first-root" || fault == "bad-owner" {
				if rows[0].Cells["RecordType"].String() != "diagnostic" || rows[1].Cells["FileOutput"].Kind != "artifact" {
					t.Fatal(rows)
				}
			} else if fault != "unreadable-signature" {
				for _, row := range rows {
					if row.Cells["FileOutput"].Kind != "missing" || row.Cells["FileOutput"].Error == "" {
						t.Fatal(row)
					}
				}
			}
			if fault == "unreadable-signature" {
				for _, row := range rows {
					if row.Cells["RecordType"].String() != "diagnostic" {
						t.Fatal(row)
					}
				}
			}
		})
	}
}

func TestLinuxELFSignatureEnumerationMainSelectionAndCancellation(t *testing.T) {
	// Enumeration deliberately checks only the signature, like the baseline;
	// dumping demands a complete interpretable header.
	e := openLinuxELF(t, linuxELFFixture(t, "bad-header"), true)
	r, err := e.Run(context.Background(), "linux.elfs", map[string]string{"pid": "100"}, engine.RunOptions{})
	if err != nil || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	for _, fault := range []string{"no-main", "null-mm"} {
		e := openLinuxELF(t, linuxELFFixture(t, fault), true)
		var row evidence.Row
		r, err := e.Run(context.Background(), "linux.pslist", map[string]string{"pid": "100", "dump": "true"}, engine.RunOptions{Emit: func(v evidence.Row) error { row = v; return nil }})
		if fault == "null-mm" {
			if err != nil || row.Cells["FileOutput"].Reason != "no_user_mm" {
				t.Fatal(r, row, err)
			}
		} else if err == nil || row.Cells["Error"].Error == "" {
			t.Fatal(r, row, err)
		}
	}
	for _, params := range []map[string]string{{"elf-layout": "bad"}, {"max-elf-size": "0"}, {"max-elf-size": "4294967296"}, {"max-regions": "0"}, {"max-regions": "1000001"}} {
		if _, err = e.Run(context.Background(), "linux.elfs", params, engine.RunOptions{}); err == nil {
			t.Fatal("bad option accepted", params)
		}
	}
	sentinel := errors.New("stop output")
	r, err = e.Run(context.Background(), "linux.elfs", nil, engine.RunOptions{Emit: func(v evidence.Row) error { return sentinel }})
	if !errors.Is(err, sentinel) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err = e.Run(ctx, "linux.elfs", nil, engine.RunOptions{Emit: func(v evidence.Row) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
}

func TestLinuxELFTotalTraversalBudget(t *testing.T) {
	e := openLinuxELF(t, linuxELFFixture(t, ""), true)
	var kinds []string
	r, err := e.Run(context.Background(), "linux.elfs", map[string]string{"max-regions": "1"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		kinds = append(kinds, row.Cells["RecordType"].String())
		return nil
	}})
	if err == nil || r.Task.State != "failed" || len(kinds) != 2 || kinds[0] != "elf" || kinds[1] != "diagnostic" {
		t.Fatal(r, kinds, err)
	}
}
