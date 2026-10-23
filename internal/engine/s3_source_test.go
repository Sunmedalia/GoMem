package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestS3WindowsLinuxEvidenceAndCache(t *testing.T) {
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
			server := testfixture.StartS3Server(t, "", "")
			server.Put("test-bucket", "memory.raw", "v1", data)
			cfg.Image = "s3://test-bucket/memory.raw"
			cfg.CaseDir = t.TempDir()
			cfg.Offline = false
			cfg.S3 = memory.S3Options{Endpoint: server.Endpoint(), Region: "us-east-1", PathStyle: true, Anonymous: true}
			e, err := engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			var rows [][]byte
			options := engine.RunOptions{Emit: func(row evidence.Row) error {
				if row.Provenance.Parameters["engine.source.protocol"] != "s3" || row.Provenance.Parameters["engine.source.version"] != "v1" || row.Provenance.Parameters["engine.source.key"] != "memory.raw" {
					t.Fatal("cloud provenance absent")
				}
				cells := map[string]evidence.Value{}
				for _, key := range []string{"Offset", "PID", "PPID", "Name", "TID", "Created", "DTB"} {
					if value, ok := row.Cells[key]; ok {
						cells[key] = value
					}
				}
				encoded, err := json.Marshal(cells)
				rows = append(rows, encoded)
				return err
			}}
			result, err := e.Run(context.Background(), platform+".pslist", nil, options)
			if err != nil || len(rows) != 2 {
				t.Fatal(result, err)
			}
			for i := range rows {
				if !bytes.Equal(rows[i], reference[i]) {
					t.Fatal("process columns differ")
				}
			}
			changed := bytes.Clone(data)
			changed[0] ^= 1
			server.Put("test-bucket", "memory.raw", "v2", changed)
			cached, err := e.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{})
			if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
				t.Fatal("version-pinned cache lost", cached, err)
			}
			verify, err := e.Store.VerifyCase(context.Background(), "")
			if err != nil || !verify.Verified {
				t.Fatal(verify, err)
			}
			e.Close()
			e, err = engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			next, err := e.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{})
			if err != nil || next.Reused {
				t.Fatal("new version replayed old task", next, err)
			}
		})
	}
}
func TestS3MutableObjectRejectsCache(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture.Image)
	if err != nil {
		t.Fatal(err)
	}
	server := testfixture.StartS3Server(t, "", "")
	server.Put("test-bucket", "memory.raw", "", data)
	cfg := engine.Config{Image: "s3://test-bucket/memory.raw", Symbols: fixture.Symbols, OS: "linux", DTB: fixture.DTB, Arch: "x64", CaseDir: t.TempDir(), S3: memory.S3Options{Endpoint: server.Endpoint(), Region: "us-east-1", PathStyle: true, Anonymous: true}}
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	server.Put("test-bucket", "memory.raw", "", bytes.Repeat([]byte{'X'}, len(data)))
	if _, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{}); err == nil {
		t.Fatal("changed object cache replayed")
	}
}
func TestS3VMwareCompanionVersions(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "memory.vmem")
	metadata := wrapVMwareSource(t, fixture.Image, image)
	data, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := os.ReadFile(metadata)
	if err != nil {
		t.Fatal(err)
	}
	server := testfixture.StartS3Server(t, "", "")
	server.Put("test-bucket", "memory.vmem", "vmem-version", data)
	server.Put("test-bucket", "memory.vmss", "vmss-version", meta)
	cfg := engine.Config{Image: "s3://test-bucket/memory.vmem?versionId=vmem-version", Symbols: fixture.Symbols, OS: "linux", DTB: fixture.DTB, Arch: "x64", CaseDir: t.TempDir(), S3: memory.S3Options{Endpoint: server.Endpoint(), Region: "us-east-1", PathStyle: true, Anonymous: true}}
	runXenProcesses(t, cfg, 2)
	cfg.VMwareMetadata = "s3://test-bucket/memory.vmem?versionId=vmem-version"
	if e, err := engine.Open(context.Background(), cfg); err == nil {
		e.Close()
		t.Fatal("same cloud member accepted")
	}
	cfg.VMwareMetadata = "s3://test-bucket/memory.vmss?versionId=vmss-version"
	cfg.CaseDir = t.TempDir()
	runXenProcesses(t, cfg, 2)
}
func TestOfficialS3Linux(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("set GOMEM_CORPUS_DIR for loopback S3 transport control")
	}
	raw := filepath.Join(dir, "linux-sample-1.bin")
	cfg := engine.Config{Image: raw, Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", OS: "linux", Offline: true, CaseDir: t.TempDir()}
	reference := runXenProcesses(t, cfg, 133)
	server := testfixture.StartS3Server(t, "", "")
	server.PutFile(t, "test-bucket", "memory.raw", "v1", raw)
	cfg.Image = "s3://test-bucket/memory.raw"
	cfg.Offline = false
	cfg.CaseDir = t.TempDir()
	cfg.S3 = memory.S3Options{Endpoint: server.Endpoint(), Region: "us-east-1", PathStyle: true, Anonymous: true}
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" || e.Discovery == nil {
		e.Close()
		t.Fatal("object hash or automatic discovery drift")
	}
	e.Close()
	rows := runXenProcesses(t, cfg, 133)
	for i := range rows {
		if !bytes.Equal(rows[i], reference[i]) {
			t.Fatalf("row %d differs", i)
		}
	}
	t.Log("512MiB S3 object hash, automatic DTB, 133 ordered process columns, case seals and cache replay match local RAW; loopback fixture only")
}
