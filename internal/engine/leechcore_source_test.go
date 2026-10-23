package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestLeechCoreNativeProcessesEvidenceAndCache(t *testing.T) {
	library := os.Getenv("GOMEM_LEECHCORE_LIBRARY")
	if library == "" || !memory.LeechCoreSupported() {
		t.Skip("set GOMEM_LEECHCORE_LIBRARY for native acquisition")
	}
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			fixture, err := testfixture.Write(t.TempDir(), platform)
			if err != nil {
				t.Fatal(err)
			}
			// The actual library's file provider requires at least 16MiB.
			if err := os.Truncate(fixture.Image, 32<<20); err != nil {
				t.Fatal(err)
			}
			cfg := engine.Config{Image: fixture.Image, Symbols: fixture.Symbols, OS: platform, DTB: fixture.DTB, KernelBase: fixture.KernelBase, Arch: "x64", Offline: true, CaseDir: t.TempDir()}
			expected := runXenProcesses(t, cfg, 2)
			cfg.Image = "leechcore://" + fixture.Image
			cfg.Offline = false
			cfg.CaseDir = t.TempDir()
			cfg.LeechCore = memory.LeechCoreOptions{Library: library}
			e, err := engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.Format != "lime" {
				t.Fatal(e.Format)
			}
			result, err := e.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Provenance.Parameters["engine.source.protocol"] != "leechcore" || row.Provenance.Parameters["engine.source.sha256"] != e.Hash {
					t.Fatal("snapshot provenance missing")
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			cached, err := e.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{})
			if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
				t.Fatal(cached, err)
			}
			verification, err := e.Store.VerifyCase(context.Background(), "")
			if err != nil || !verification.Verified {
				t.Fatal(verification, err)
			}
			e.Close()
			cfg.CaseDir = t.TempDir()
			rows := runXenProcesses(t, cfg, 2)
			for i := range rows {
				if !bytes.Equal(rows[i], expected[i]) {
					t.Fatalf("process %d differs", i)
				}
			}
		})
	}
}

func TestOfficialLeechCoreLinux(t *testing.T) {
	library, dir := os.Getenv("GOMEM_LEECHCORE_LIBRARY"), os.Getenv("GOMEM_CORPUS_DIR")
	if library == "" || dir == "" || !memory.LeechCoreSupported() {
		t.Skip("set GOMEM_LEECHCORE_LIBRARY and GOMEM_CORPUS_DIR for native library corpus control")
	}
	raw := filepath.Join(dir, "linux-sample-1.bin")
	cfg := engine.Config{Image: raw, Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", OS: "linux", Offline: true, CaseDir: t.TempDir()}
	expected := runXenProcesses(t, cfg, 133)
	cfg.Image = "leechcore://" + raw
	cfg.Offline = false
	cfg.CaseDir = t.TempDir()
	cfg.LeechCore = memory.LeechCoreOptions{Library: library}
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	buffer := make([]byte, 4<<20)
	for at := uint64(0); at < 512<<20; at += uint64(len(buffer)) {
		if _, err := e.Env.Physical.ReadAt(context.Background(), buffer, at); err != nil {
			t.Fatal(err)
		}
		hash.Write(buffer)
	}
	if hex.EncodeToString(hash.Sum(nil)) != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" || e.Discovery == nil {
		t.Fatal("physical bytes or automatic DTB differ")
	}
	e.Close()
	rows := runXenProcesses(t, cfg, 133)
	for i := range rows {
		if !bytes.Equal(rows[i], expected[i]) {
			t.Fatalf("process %d differs", i)
		}
	}
	t.Log("actual native library file provider: 512MiB physical SHA, automatic DTB, 133 ordered process fields, case seals and cache match RAW; no live hardware acceptance")
}
