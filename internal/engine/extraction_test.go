package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func processExtractionFixture(t *testing.T, platform string) testfixture.Fixture {
	t.Helper()
	f, err := testfixture.Write(t.TempDir(), platform)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put(0x1d000, 0x1e003)
	put(0x1e000, 0x1f003)
	if platform == "linux" {
		put(0xe000, 0x1d000)
		put(0x1f010, 0x83)
	} else {
		put(0x9038, 0x1d000)
		put(0x1f018, 0x1c003)
		put(0x1c800, 3)
	}
	copy(data[0x100:], "captured-from-process-page-table")
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestExtractionMissingProcessRootAndNonpersistentCaseAreFailures(t *testing.T) {
	for _, scenario := range []string{"root-unset", "root-flags-only", "no-case"} {
		t.Run(scenario, func(t *testing.T) {
			f := processExtractionFixture(t, "windows")
			if scenario != "no-case" {
				data, err := os.ReadFile(f.Image)
				if err != nil {
					t.Fatal(err)
				}
				root := uint64(0)
				if scenario == "root-flags-only" {
					root = 1
				}
				binary.LittleEndian.PutUint64(data[0x9038:], root)
				if err = os.WriteFile(f.Image, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			caseDir := t.TempDir()
			if scenario == "no-case" {
				caseDir = ""
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: caseDir, Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var row evidence.Row
			r, err := e.Run(context.Background(), "windows.vadinfo", map[string]string{"pid": "104", "address": "0x700000", "dump": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
			if err == nil || r.Task.State != "failed" || r.Task.Rows != 1 || row.Cells["FileOutput"].Kind != "missing" || row.Cells["FileOutput"].Error == "" {
				t.Fatal("extraction setup failure became clean metadata", r, row, err)
			}
		})
	}
}

func TestWindowsAndLinuxRegionExtractionUsesProcessRoots(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			f := processExtractionFixture(t, platform)
			ctx := context.Background()
			e, err := engine.Open(ctx, engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			plugin, pid, address, maxsize, size := "windows.vadinfo", "104", "0x700000", "65536", 65536
			if platform == "linux" {
				plugin, pid, address, maxsize, size = "linux.maps", "100", "0x400000", "4097", 4096
			}
			var row evidence.Row
			result, err := e.Run(ctx, plugin, map[string]string{"pid": pid, "address": address, "dump": "true", "maxsize": maxsize}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
			if err != nil || result.Task.Rows != 1 || row.Cells["FileOutput"].Kind != "artifact" {
				t.Fatal(result, row, err)
			}
			files, err := e.Store.Artifacts(ctx, result.Task.ID)
			if err != nil || len(files) != 1 {
				t.Fatal(files, err)
			}
			a := files[0]
			if a.Provenance.Offset != address || a.Provenance.Layer != "process:"+row.Cells["ProcessIdentity"].String() {
				t.Fatal("wrong dump address space", a)
			}
			data, err := os.ReadFile(filepath.Join(e.Store.Dir, filepath.FromSlash(a.Path)))
			if err != nil || len(data) != size || !bytes.Equal(data[0x100:0x100+len("captured-from-process-page-table")], []byte("captured-from-process-page-table")) {
				t.Fatal("wrong process-root data", len(data), err)
			}
			if platform == "windows" {
				if a.State != "completed_with_gaps" || a.MissingBytes != "61440" || a.GapCount != "15" {
					t.Fatal(a)
				}
			} else if a.State != "completed" || a.MissingBytes != "0" {
				t.Fatal(a)
			}
			if err = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); err != nil {
				t.Fatal(err)
			}
			limit := "65535"
			if platform == "linux" {
				limit = "4096"
			}
			var skipped evidence.Row
			r, err := e.Run(ctx, plugin, map[string]string{"pid": pid, "address": address, "dump": "true", "maxsize": limit}, engine.RunOptions{Emit: func(r evidence.Row) error { skipped = r; return nil }})
			if err != nil || r.Task.Rows != 1 || skipped.Cells["FileOutput"].Reason != "maxsize_exceeded" {
				t.Fatal(r, skipped, err)
			}
			artifacts, err := e.Store.Artifacts(ctx, r.Task.ID)
			if err != nil || len(artifacts) != 0 {
				t.Fatal(artifacts, err)
			}
			var zeroLimit evidence.Row
			z, err := e.Run(ctx, plugin, map[string]string{"pid": pid, "address": address, "dump": "true", "maxsize": "0"}, engine.RunOptions{Emit: func(r evidence.Row) error { zeroLimit = r; return nil }})
			if err != nil {
				t.Fatal(z, err)
			}
			if platform == "linux" {
				if zeroLimit.Cells["FileOutput"].Reason != "maxsize_exceeded" {
					t.Fatal("Linux zero maxsize boundary changed", zeroLimit)
				}
			} else if zeroLimit.Cells["FileOutput"].Kind != "artifact" {
				t.Fatal("Windows zero maxsize should disable size limit", zeroLimit)
			}
		})
	}
}
