package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func editWindowsImage(t *testing.T, f testfixture.Fixture, edit func([]byte)) {
	t.Helper()
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	edit(data)
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func openWindowsImage(t *testing.T, f testfixture.Fixture) *engine.Engine {
	t.Helper()
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestWindowsProcessFieldsAndPhysicalIdentity(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	editWindowsImage(t, f, func(data []byte) {
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		put(0x3008, 0x83) // Alias the second 2MiB virtual range to physical zero.
		put(0x6000, 0x208000)
		put(0x6008, 0x209000)
		put(0x8000, 0x209000)
		put(0x9008, 0x208000)
		put(0x9070, 133000000001234567)
		put(0x9060, 1) // WoW64 predicate only; no user-layout dereference here.
	})
	e := openWindowsImage(t, f)
	ctx := context.Background()
	var physical, virtual []evidence.Row
	for _, tc := range []struct {
		p    map[string]string
		rows *[]evidence.Row
	}{{map[string]string{"physical": "true"}, &physical}, {nil, &virtual}} {
		r, err := e.Run(ctx, "windows.pslist", tc.p, engine.RunOptions{Emit: func(row evidence.Row) error { *tc.rows = append(*tc.rows, row); return nil }})
		if err != nil || r.Task.Rows != 2 {
			t.Fatal(r, err)
		}
	}
	for i, row := range physical {
		if row.Cells["Identity"].String() != virtual[i].Cells["Identity"].String() || row.Provenance.Offset != virtual[i].Provenance.Offset || row.Cells["VirtualOffset"].String() != virtual[i].Cells["Offset"].String() {
			t.Fatal("physical display changed process identity", row)
		}
		pa, _ := row.Cells["Offset"].Uint()
		va, _ := row.Cells["VirtualOffset"].Uint()
		if va-pa != 0x200000 || row.Cells["OffsetSpace"].String() != "physical" || row.Verify() != nil {
			t.Fatal(row)
		}
	}
	worker := physical[1].Cells
	if worker["Threads"].String() != "1" || worker["Handles"].String() != "20" || worker["SessionId"].String() != "1" || worker["Wow64"].Data != true || !strings.Contains(worker["Exited"].String(), ".1234567Z") || worker["FileOutput"].Reason != "not_requested" || physical[0].Cells["SessionId"].Reason != "not_applicable" {
		t.Fatal(worker)
	}
}

func TestWindowsProcessDumpUsesItsOwnPEBAndRetainsFailures(t *testing.T) {
	f := dllFixture(t, "independent-process-root")
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1b008:], 0x204000)
		// The first process has an unreadable PEB, the second remains recoverable.
		binary.LittleEndian.PutUint64(data[0x8058:], 0x300000)
	})
	e := openWindowsImage(t, f)
	var rows []evidence.Row
	r, err := e.Run(context.Background(), "windows.pslist", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
	if err == nil || r.Task.State != "failed" || r.Task.Rows != 2 || rows[0].Cells["FileOutput"].Reason != "peb_image_base_unreadable" || rows[1].Cells["FileOutput"].Kind != "artifact" {
		t.Fatal(r, rows, err)
	}
	files, err := e.Store.Artifacts(context.Background(), r.Task.ID)
	if err != nil || len(files) != 1 || files[0].Name != "104.worker.exe.0x204000.dmp" || !strings.HasPrefix(files[0].Provenance.Layer, "process:") {
		t.Fatal(files, err)
	}
	data, err := os.ReadFile(filepath.Join(e.Store.Dir, filepath.FromSlash(files[0].Path)))
	if err != nil || binary.LittleEndian.Uint64(data[0xb0:]) != 0x204000 || rows[1].Cells["Patches"].Kind != "structure" {
		t.Fatal("main image did not use process layer", err)
	}
}

func TestWindowsModuleFiltersAndPaths(t *testing.T) {
	e, _ := openFixture(t, "windows")
	for _, tc := range []struct {
		p map[string]string
		n int64
	}{{nil, 1}, {map[string]string{"base": "0"}, 1}, {map[string]string{"base": "0x4000", "name": "krnl"}, 1}, {map[string]string{"base": "0x5000"}, 0}, {map[string]string{"name": "NTOS"}, 0}, {map[string]string{"name": "ntos.*"}, 0}, {map[string]string{"name": "SystemRoot"}, 0}} {
		var row evidence.Row
		r, err := e.Run(context.Background(), "windows.modules", tc.p, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
		if err != nil || r.Task.Rows != tc.n || tc.n > 0 && row.Cells["Path"].String() != `\SystemRoot\system32\ntoskrnl.exe` {
			t.Fatal(tc.p, r, row, err)
		}
	}
	for _, p := range []map[string]string{{"base": "bad"}, {"max-session-layers": "0"}, {"max-session-layers": "4097"}} {
		if _, err := e.Run(context.Background(), "windows.modules", p, engine.RunOptions{}); err == nil {
			t.Fatal("invalid filter/bound accepted", p)
		}
	}
}

func TestWindowsModuleSessionLayerExtraction(t *testing.T) {
	f := dllFixture(t, "independent-process-root")
	editWindowsImage(t, f, func(data []byte) { binary.LittleEndian.PutUint64(data[0xa010:], 0x204000) })
	e := openWindowsImage(t, f)
	var row evidence.Row
	r, err := e.Run(context.Background(), "windows.modules", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
	if err != nil || r.Task.Rows != 1 || row.Cells["FileOutput"].Kind != "artifact" {
		t.Fatal(r, row, err)
	}
	files, err := e.Store.Artifacts(context.Background(), r.Task.ID)
	if err != nil || len(files) != 1 || files[0].Name != "ntoskrnl.exe.0xa000.0x204000.dmp" || !strings.HasPrefix(files[0].Provenance.Layer, "process:") {
		t.Fatal(files, err)
	}
	// JSON is the public evidence interface: both failed kernel attempt and the
	// selected session root must be independently reviewable in saved results.
	b, _ := json.Marshal(row.Cells["ExtractionAttempts"].Data)
	var attempts []map[string]string
	if err = json.Unmarshal(b, &attempts); err != nil || len(attempts) != 2 || attempts[0]["error"] == "" || attempts[1]["session_id"] != "1" || attempts[1]["pid"] != "104" || attempts[1]["error"] != "" || attempts[1]["layer"] != files[0].Provenance.Layer {
		t.Fatal(string(b), err)
	}
	if err = e.Store.VerifyTaskArtifacts(context.Background(), r.Task.ID); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsModuleReadFailuresRemainVisible(t *testing.T) {
	for _, scenario := range []string{"unreadable-name", "unreadable-path", "unreadable-session", "opaque-session-layout", "invalid-pe", "session-bound"} {
		t.Run(scenario, func(t *testing.T) {
			f := dllFixture(t, "independent-process-root")
			editWindowsImage(t, f, func(data []byte) {
				put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
				switch scenario {
				case "unreadable-name":
					put(0xa028, 0x300000)
				case "unreadable-path":
					put(0xa038, 0x300000)
				case "invalid-pe":
					put(0xa010, 0x10000)
				default:
					put(0xa010, 0x204000)
					if scenario == "unreadable-session" {
						put(0x9080, 0x300000)
					}
					if scenario == "session-bound" {
						put(0x8080, 0x1a200)
					}
				}
			})
			if scenario == "opaque-session-layout" {
				b, _ := os.ReadFile(f.Symbols)
				var table symbols.ISF
				if err := json.Unmarshal(b, &table); err != nil {
					t.Fatal(err)
				}
				delete(table.Types, "_MM_SESSION_SPACE")
				b, _ = json.Marshal(table)
				if err := os.WriteFile(f.Symbols, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			e := openWindowsImage(t, f)
			p := map[string]string{"dump": "true"}
			if scenario == "unreadable-name" {
				p["name"] = "ntos"
			}
			if scenario == "session-bound" {
				p["max-session-layers"] = "1"
			}
			var row evidence.Row
			r, err := e.Run(context.Background(), "windows.modules", p, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
			if r.Task.Rows != 1 || (err == nil) != (scenario == "unreadable-path") {
				t.Fatal(r, row, err)
			}
			if scenario == "unreadable-path" {
				if row.Cells["Path"].Error == "" || row.Cells["FileOutput"].Kind != "artifact" {
					t.Fatal(row)
				}
			} else if row.Cells["FileOutput"].Kind != "missing" || row.Cells["FileOutput"].Error == "" || r.Task.State != "failed" {
				t.Fatal(row, r)
			}
		})
	}
}

func TestWindowsModuleDumpContinuesAfterInvalidPE(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	editWindowsImage(t, f, func(data []byte) {
		put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
		copy(data[0xa100:0xa140], data[0xa000:0xa040])
		put(0x6018, 0xa100)
		put(0xa000, 0xa100)
		put(0xa010, 0x10000) // Mapped, but invalid DOS signature.
		put(0xa100, 0x6010)
		put(0xa108, 0xa000)
	})
	e := openWindowsImage(t, f)
	var rows []evidence.Row
	r, err := e.Run(context.Background(), "windows.modules", map[string]string{"dump": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
	if err == nil || r.Task.State != "failed" || r.Task.Rows != 2 || rows[0].Cells["FileOutput"].Reason != "invalid_or_unreadable_pe" || rows[1].Cells["FileOutput"].Kind != "artifact" {
		t.Fatal(r, rows, err)
	}
	files, err := e.Store.Artifacts(context.Background(), r.Task.ID)
	if err != nil || len(files) != 1 || files[0].Name != "ntoskrnl.exe.0xa100.0x4000.dmp" {
		t.Fatal(files, err)
	}
}

func TestProcessDumpNullPEBAndUnreadableFieldsAreDistinct(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x8078:], 0x300000)
		binary.LittleEndian.PutUint64(data[0x8080:], 0x300000)
	})
	e := openWindowsImage(t, f)
	var row evidence.Row
	r, err := e.Run(context.Background(), "windows.pslist", map[string]string{"pid": "4", "dump": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
	if err != nil || r.Task.Rows != 1 || row.Cells["FileOutput"].Reason != "no_process_peb" || row.Cells["FileOutput"].Error != "" || row.Cells["Handles"].Error == "" || row.Cells["SessionId"].Error == "" {
		t.Fatal(r, row, err)
	}
	files, err := e.Store.Artifacts(context.Background(), r.Task.ID)
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
}

func TestProcessAndModuleOutputErrorsAndCancellation(t *testing.T) {
	for _, name := range []string{"windows.pslist", "windows.modules"} {
		e, _ := openFixture(t, "windows")
		stop := errors.New("stop output")
		_, err := e.Run(context.Background(), name, nil, engine.RunOptions{Emit: func(evidence.Row) error { return stop }})
		if !errors.Is(err, stop) {
			t.Fatal(name, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := e.Run(ctx, name, map[string]string{"dump": "true"}, engine.RunOptions{}); !errors.Is(err, context.Canceled) {
			t.Fatal(name, err)
		}
	}
}
