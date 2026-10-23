package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestFTPSnapshotPagingEvidenceAndCache(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			fixture, err := testfixture.Write(t.TempDir(), platform)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(fixture.Image)
			if err != nil {
				t.Fatal(err)
			}
			cfg := engine.Config{Image: fixture.Image, Symbols: fixture.Symbols, OS: platform, DTB: fixture.DTB, KernelBase: fixture.KernelBase, Arch: "x64", Offline: true, CaseDir: t.TempDir()}
			reference := runXenProcesses(t, cfg, 2)
			server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Files: map[string][]byte{"memory.raw": data}})
			cfg.Image = strings.Replace(server.URL(), "ftp://", "ftp://secret-user:secret-password@", 1) + "/memory.raw"
			cfg.CaseDir = t.TempDir()
			cfg.Offline = false
			e, err := engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, ok := e.Source.(*memory.SnapshotSource)
			if !ok {
				t.Fatal("not a local snapshot")
			}
			if e.Hash != snapshot.SnapshotInfo().SHA256 || e.Format != "raw" {
				t.Fatal("acquisition identity mismatch")
			}
			initialHash := e.Hash
			var selected [][]byte
			options := engine.RunOptions{Emit: func(row evidence.Row) error {
				p := row.Provenance
				if p.Parameters["engine.source.schema"] != "gomem.remote-snapshot/v1" || p.Parameters["engine.source.protocol"] != "ftp" || p.Parameters["engine.source.sha256"] != initialHash || p.ImageSHA256 != initialHash {
					t.Fatal("snapshot provenance absent")
				}
				cells := map[string]evidence.Value{}
				for _, key := range []string{"Offset", "PID", "PPID", "Name", "TID", "Created", "DTB"} {
					if value, ok := row.Cells[key]; ok {
						cells[key] = value
					}
				}
				encoded, err := json.Marshal(cells)
				selected = append(selected, encoded)
				return err
			}}
			first, err := e.Run(context.Background(), platform+".pslist", nil, options)
			if err != nil || len(selected) != 2 {
				t.Fatal(first, err)
			}
			for i := range selected {
				if !bytes.Equal(selected[i], reference[i]) {
					t.Fatal("selected process fields differ")
				}
			}
			changed := bytes.Clone(data)
			changed[0] ^= 1
			server.SetFile("memory.raw", changed)
			cached, err := e.Run(context.Background(), platform+".pslist", nil, options)
			if err != nil || !cached.Reused || cached.Task.ID != first.Task.ID || server.Retrievals.Load() != 1 {
				t.Fatal("snapshot cache changed after server replacement", cached, err)
			}
			verification, err := e.Store.VerifyCase(context.Background(), "")
			if err != nil || !verification.Verified {
				t.Fatal(verification, err)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			files, err := os.ReadDir(filepath.Join(cfg.CaseDir, "sources"))
			if err != nil || len(files) != 0 {
				t.Fatal("snapshot retained after close", err)
			}
			e, err = engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.Hash == initialHash || server.Retrievals.Load() != 2 {
				t.Fatal("new acquisition reused remote bytes")
			}
			next, err := e.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{})
			if err != nil || next.Reused {
				t.Fatal("new source reused old cache", next, err)
			}
		})
	}
}
func TestFTPSnapshotMutationRejectsCache(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture.Image)
	if err != nil {
		t.Fatal(err)
	}
	server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Files: map[string][]byte{"memory.raw": data}})
	cfg := engine.Config{Image: server.URL() + "/memory.raw", Symbols: fixture.Symbols, OS: "linux", DTB: fixture.DTB, Arch: "x64", CaseDir: t.TempDir()}
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(cfg.CaseDir, "sources"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	if err := os.WriteFile(filepath.Join(cfg.CaseDir, "sources", files[0].Name()), []byte{0}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{}); err == nil {
		t.Fatal("modified local snapshot cache replayed")
	}
}
func TestFTPVMwareCompanionAssembly(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "memory.vmem")
	metadata := wrapVMwareSource(t, fixture.Image, image)
	raw, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := os.ReadFile(metadata)
	if err != nil {
		t.Fatal(err)
	}
	server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{Files: map[string][]byte{"memory.vmem": raw, "memory.vmss": meta}})
	cfg := engine.Config{Image: server.URL() + "/memory.vmem;type=i", Symbols: fixture.Symbols, OS: "linux", DTB: fixture.DTB, Arch: "x64", CaseDir: t.TempDir()}
	runXenProcesses(t, cfg, 2)
	files, err := os.ReadDir(filepath.Join(cfg.CaseDir, "sources"))
	if err != nil || len(files) != 0 {
		t.Fatal("pair snapshots leaked", files, err)
	}
	if server.Retrievals.Load() != 2 {
		t.Fatal("incorrect companion acquisition count")
	}
}

func TestOfficialFTPSnapshotLinux(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("set GOMEM_CORPUS_DIR for official RAW over local FTP control")
	}
	raw := filepath.Join(dir, "linux-sample-1.bin")
	cfg := engine.Config{Image: raw, Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", OS: "linux", Offline: true, CaseDir: t.TempDir()}
	reference := runXenProcesses(t, cfg, 133)
	server := testfixture.StartFTPServer(t, testfixture.FTPServerOptions{FilePaths: map[string]string{"memory.raw": raw}})
	cfg.Image = server.URL() + "/memory.raw"
	cfg.CaseDir = t.TempDir()
	cfg.Offline = false
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" || e.Discovery == nil {
		e.Close()
		t.Fatal("remote bytes or automatic discovery drift")
	}
	e.Close()
	rows := runXenProcesses(t, cfg, 133)
	for i := range rows {
		if !bytes.Equal(rows[i], reference[i]) {
			t.Fatalf("process row %d differs", i)
		}
	}
	t.Log("512MiB FTP capture SHA, automatic DTB, 133 ordered selected process fields, seals and cache replay verified against local RAW; loopback server only")
}
