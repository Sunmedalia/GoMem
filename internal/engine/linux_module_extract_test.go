package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestLinuxModuleExtractIndependentAndCache(t *testing.T) {
	for _, arch := range []string{"x64", "x86", "pae"} {
		for _, layout := range []string{"legacy", "inline", "pointer"} {
			t.Run(arch+"/"+layout, func(t *testing.T) {
				e := moduleExportEngine(t, arch, layout, "extract-only")
				ctx := context.Background()
				var fresh, replay bytes.Buffer
				check := func(row evidence.Row) {
					base, err := row.Cells["Base"].Uint()
					if err != nil || base != 0xc400 || row.Cells["Name"].String() != "sys-only" || row.Cells["File Size"].Kind != "uint64" || row.Cells["File output"].Kind != "artifact" {
						t.Fatal(row, err)
					}
					if err = row.Verify(); err != nil {
						t.Fatal(err)
					}
					if count := verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"]); count != 2 {
						t.Fatal("probe/name captures", count)
					}
					fields := bashProofFields(t, row.Cells["DumpEvidence"])
					if count := verifyModuleParameterWireCaptures(t, e, fields["SymbolTableRaw"]); count != 1 {
						t.Fatal("symbol bytes", count)
					}
				}
				result, err := e.Run(ctx, "linux.module_extract", map[string]string{"base": "0xc400"}, engine.RunOptions{Emit: func(row evidence.Row) error { check(row); return json.NewEncoder(&fresh).Encode(row) }})
				if err != nil || result.Task.State != "completed" || result.Task.Rows != 1 {
					t.Fatal(result, err)
				}
				artifacts, err := e.Store.Artifacts(ctx, result.Task.ID)
				if err != nil || len(artifacts) != 1 || artifacts[0].Name != "kernel_module.sys-only.0xc400.elf" || artifacts[0].State != "completed" {
					t.Fatal(artifacts, err)
				}
				if err = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); err != nil {
					t.Fatal(err)
				}
				cached, err := e.Run(ctx, "linux.module_extract", map[string]string{"base": "0xc400"}, engine.RunOptions{Emit: func(row evidence.Row) error { check(row); return json.NewEncoder(&replay).Encode(row) }})
				if err != nil || !cached.Reused || !bytes.Equal(fresh.Bytes(), replay.Bytes()) {
					t.Fatal(cached, err)
				}
				// Equivalent decimal input must retain the same address/file bytes.
				decimal, err := e.Run(ctx, "linux.module_extract", map[string]string{"base": "50176"}, engine.RunOptions{})
				if err != nil {
					t.Fatal(decimal, err)
				}
				decimalArtifacts, err := e.Store.Artifacts(ctx, decimal.Task.ID)
				if err != nil || len(decimalArtifacts) != 1 || decimalArtifacts[0].SHA256 != artifacts[0].SHA256 {
					t.Fatal(decimalArtifacts, err)
				}
			})
		}
	}
}

func TestLinuxModuleExtractFailuresRemainEvidence(t *testing.T) {
	for _, fault := range []string{"metadata", "missing-symtab", "symbol-hole", "symbol-limit", "section-limit", "name-hole"} {
		t.Run(fault, func(t *testing.T) {
			e := moduleExportEngine(t, "x64", "legacy", fault)
			for i := 0; i < 2; i++ {
				var rows []evidence.Row
				result, err := e.Run(context.Background(), "linux.module_extract", map[string]string{"base": "0xc000"}, engine.RunOptions{Emit: func(row evidence.Row) error { rows = append(rows, row); return nil }})
				if err == nil || result.Reused || result.Task.State != "failed" || len(rows) != 1 || rows[0].Cells["File output"].Kind != "missing" || rows[0].Cells["File Size"].Kind != "missing" || rows[0].Cells["Error"].Error == "" {
					t.Fatal(result, err, rows)
				}
				artifacts, err := e.Store.Artifacts(context.Background(), result.Task.ID)
				if err != nil || len(artifacts) != 0 {
					t.Fatal(artifacts, err)
				}
			}
		})
	}
	e := moduleExportEngine(t, "x64", "legacy", "")
	for _, base := range []string{"", "-1", "no-address", "0x1000000000000", "0xffff000000000000"} {
		var rows int
		result, err := e.Run(context.Background(), "linux.module_extract", map[string]string{"base": base}, engine.RunOptions{Emit: func(evidence.Row) error { rows++; return nil }})
		if err == nil || rows != 0 || result.Reused {
			t.Fatal(base, result, err, rows)
		}
	}
	var row evidence.Row
	result, err := e.Run(context.Background(), "linux.module_extract", map[string]string{"base": "0x500000"}, engine.RunOptions{Emit: func(r evidence.Row) error { row = r; return nil }})
	if err == nil || result.Task.Rows != 1 || row.Cells["File output"].Reason != "module_base_unreadable" || row.Cells["Error"].Error == "" {
		t.Fatal(result, err, row)
	}
}

func TestLinuxModuleExtractPaddingAndStop(t *testing.T) {
	e := moduleExportEngine(t, "x64", "legacy", "gaps")
	ctx := context.Background()
	result, err := e.Run(ctx, "linux.module_extract", map[string]string{"base": "0xc000"}, engine.RunOptions{})
	if err != nil {
		t.Fatal(result, err)
	}
	artifacts, err := e.Store.Artifacts(ctx, result.Task.ID)
	if err != nil || len(artifacts) != 1 || artifacts[0].State != "completed_with_gaps" || artifacts[0].MissingBytes != "61440" {
		t.Fatal(artifacts, err)
	}
	data, err := os.ReadFile(filepath.Join(e.Config.CaseDir, artifacts[0].Path))
	if err != nil || len(data) == 0 {
		t.Fatal(err)
	}
	if err = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("stop output")
	calls := 0
	_, err = e.Run(ctx, "linux.module_extract", map[string]string{"base": "0xc000"}, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { calls++; return sentinel }})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal(err, calls)
	}
	during, cancelDuring := context.WithCancel(ctx)
	calls = 0
	_, err = e.Run(during, "linux.module_extract", map[string]string{"base": "0xc000"}, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { calls++; cancelDuring(); return nil }})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	calls = 0
	_, err = e.Run(cancelled, "linux.module_extract", map[string]string{"base": "0xc000"}, engine.RunOptions{Emit: func(evidence.Row) error { calls++; return nil }})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(err, calls)
	}
}
