package engine_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestPEDumpRewritesImageBaseAndPreservesEvidence(t *testing.T) {
	e, f := openFixture(t, "windows")
	ctx := context.Background()
	before, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	var row evidence.Row
	result, err := e.Run(ctx, "windows.pedump", map[string]string{"base": "0x4000", "kernel-module": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
	if err != nil || result.Task.Rows != 1 || row.Cells["Patches"].Kind != "structure" || row.Cells["FileOutput"].Kind != "artifact" {
		t.Fatal(result, row, err)
	}
	files, err := e.Store.Artifacts(ctx, result.Task.ID)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	a := files[0]
	data, err := os.ReadFile(filepath.Join(e.Store.Dir, filepath.FromSlash(a.Path)))
	if err != nil || len(data) != 0x10000 || binary.LittleEndian.Uint64(data[0xb0:]) != 0x4000 {
		t.Fatal("PE reconstruction failed", len(data), err)
	}
	if a.State != "completed" || a.Provenance.Offset != "0x4000" {
		t.Fatal(a)
	}
	after, err := os.ReadFile(f.Image)
	if err != nil || string(before) != string(after) {
		t.Fatal("source modified", err)
	}
	for _, parameters := range []map[string]string{{"base": "0"}, {"base": "0x4000"}, {"base": "0x4000", "pid": "104", "kernel-module": "true"}, {"base": "bad", "pid": "104"}} {
		if _, err = e.Run(ctx, "windows.pedump", parameters, engine.RunOptions{}); err == nil {
			t.Fatal("invalid PE extraction selection accepted", parameters)
		}
	}
	bad, err := e.Run(ctx, "windows.pedump", map[string]string{"base": "0x10000", "pid": "104"}, engine.RunOptions{})
	if err == nil || bad.Task.State != "failed" || bad.Task.Rows != 1 {
		t.Fatal("invalid PE became silent empty output", bad, err)
	}
}

func TestPEDumpRequiresPersistentArtifacts(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	r, err := e.Run(context.Background(), "windows.pedump", map[string]string{"base": "0x4000", "kernel-module": "true"}, engine.RunOptions{})
	if err == nil || r.Task.State != "failed" || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
}

func TestDLLDumpUsesPEReconstructionRatherThanRawMemory(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(data[0x1c010:], 0x4000)
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, KernelBase: f.KernelBase, CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var row evidence.Row
	r, err := e.Run(context.Background(), "windows.dlllist", map[string]string{"pid": "104", "base": "0x4000", "dump": "true"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
	if err != nil || r.Task.Rows != 1 || row.Cells["Patches"].Kind != "structure" {
		t.Fatal(r, row, err)
	}
	files, err := e.Store.Artifacts(context.Background(), r.Task.ID)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	a := files[0]
	rebuilt, err := os.ReadFile(filepath.Join(e.Store.Dir, filepath.FromSlash(a.Path)))
	if err != nil || binary.LittleEndian.Uint64(rebuilt[0xb0:]) != 0x4000 || a.Name != "pid.104.worker.exe.0x1c000.0x4000.dmp" {
		t.Fatal(a, err)
	}
}
