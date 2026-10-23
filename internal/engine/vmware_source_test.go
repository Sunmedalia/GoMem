package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// Independent one-region writer: the physical bytes remain unchanged.
func wrapVMwareSource(t testing.TB, input, output string) string {
	t.Helper()
	source, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 || info.Size()%4096 != 0 || info.Size()/4096 > 0xffffffff {
		t.Fatal("bounded page-aligned fixture required")
	}
	target, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	n, copyErr := io.CopyBuffer(target, source, make([]byte, 64<<10))
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil || n != info.Size() {
		t.Fatal(n, copyErr, closeErr)
	}
	var metadata bytes.Buffer
	for _, v := range []uint32{0xbed2bed2, 0, 1} {
		binary.Write(&metadata, binary.LittleEndian, v)
	}
	group := make([]byte, 80)
	copy(group, "memory")
	binary.LittleEndian.PutUint64(group[64:], 92)
	metadata.Write(group)
	for _, tag := range []struct {
		name    string
		value   uint32
		indexed bool
	}{{"regionsCount", 1, false}, {"regionPPN", 0, true}, {"regionPageNum", 0, true}, {"regionSize", uint32(info.Size() / 4096), true}} {
		flags := byte(4)
		if tag.indexed {
			flags |= 64
		}
		metadata.Write([]byte{flags, byte(len(tag.name))})
		metadata.WriteString(tag.name)
		if tag.indexed {
			binary.Write(&metadata, binary.LittleEndian, uint32(0))
		}
		binary.Write(&metadata, binary.LittleEndian, tag.value)
	}
	metadata.Write([]byte{0, 0})
	path := output[:len(output)-len(filepath.Ext(output))] + ".vmss"
	if err := os.WriteFile(path, metadata.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestVMwareWindowsLinuxPagingEvidenceAndCache(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			fixture, err := testfixture.Write(t.TempDir(), platform)
			if err != nil {
				t.Fatal(err)
			}
			cfg := engine.Config{Image: fixture.Image, Symbols: fixture.Symbols, OS: platform, DTB: fixture.DTB, KernelBase: fixture.KernelBase, Arch: "x64", Offline: true, CaseDir: t.TempDir()}
			reference := runXenProcesses(t, cfg, 2)
			image := filepath.Join(t.TempDir(), "memory.vmem")
			metadata := wrapVMwareSource(t, fixture.Image, image)
			cfg.Image = image
			cfg.CaseDir = t.TempDir()
			rows := runXenProcesses(t, cfg, 2)
			for i := range rows {
				if !bytes.Equal(rows[i], reference[i]) {
					t.Fatalf("process columns differ: %s / %s", rows[i], reference[i])
				}
			}
			e, err := engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if e.Format != "vmware" || e.VMwareAcquisition == nil || e.Hash == e.VMwareAcquisition.MemorySHA256 {
				t.Fatal("acquisition identity not bound")
			}
			_, err = e.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
				members := e.VMwareAcquisition
				if row.Provenance.ImageSHA256 != e.Hash || row.Provenance.Parameters["engine.acquisition.memory.sha256"] != members.MemorySHA256 || row.Provenance.Parameters["engine.acquisition.metadata.sha256"] != members.MetadataSHA256 {
					t.Fatal("cached provenance lost member identities")
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			hash := e.Hash
			data, err := os.ReadFile(metadata)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metadata, append(data, 0), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Run(context.Background(), platform+".pslist", nil, engine.RunOptions{}); err == nil {
				t.Fatal("replayed cache after metadata mutation")
			}
			e.Close()
			cfg.Image = metadata
			e, err = engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if e.Hash == hash {
				t.Fatal("metadata change did not invalidate acquisition hash")
			}
			e.Close()
		})
	}
}
func TestVMwareCaseCannotAliasMetadata(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "memory.vmem")
	metadata := wrapVMwareSource(t, fixture.Image, image)
	caseDir := t.TempDir()
	if err := os.Link(metadata, filepath.Join(caseDir, "case.db")); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(metadata)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, CaseDir: caseDir, Offline: true})
	if err == nil {
		e.Close()
		t.Fatal("case aliased metadata")
	}
	after, err := os.ReadFile(metadata)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("metadata modified", err)
	}
}

func TestOfficialVMwareReencodedLinux(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional reencoded RAW control; not a VMware producer corpus")
	}
	raw := filepath.Join(dir, "linux-sample-1.bin")
	cfg := engine.Config{Image: raw, Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", OS: "linux", Offline: true, CaseDir: t.TempDir()}
	reference := runXenProcesses(t, cfg, 133)
	image := filepath.Join(t.TempDir(), "reencoded.vmem")
	wrapVMwareSource(t, raw, image)
	cfg.Image = image
	cfg.CaseDir = t.TempDir()
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	const digest = "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc"
	if e.VMwareAcquisition == nil || e.VMwareAcquisition.MemorySHA256 != digest || xenPhysicalDigest(t, e.Env.Physical, e.Source.Size()) != digest || e.Discovery == nil {
		e.Close()
		t.Fatal("physical bytes or automatic discovery drift")
	}
	e.Close()
	rows := runXenProcesses(t, cfg, 133)
	for i := range rows {
		if !bytes.Equal(rows[i], reference[i]) {
			t.Fatalf("selected fields differ at row %d", i)
		}
	}
	t.Log("512MiB physical hash, automatic DTB, 133 ordered process fields, sealed case and cached replay verified; reencoded pair only")
}
