package engine_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
)

// Independent writer emits RAM v4 and the length-framed debug description. It
// never loads the whole input; repeated-byte pages use QEMU fill compression.
func wrapQEMUSource(t testing.TB, input, output string) uint64 {
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
	if info.Size() == 0 || info.Size()%4096 != 0 {
		t.Fatal("page aligned source required")
	}
	target, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	w := bufio.NewWriterSize(target, 64<<10)
	write := func(data []byte) {
		t.Helper()
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	integer := func(value uint64, width int) {
		t.Helper()
		var data [8]byte
		binary.BigEndian.PutUint64(data[:], value)
		write(data[8-width:])
	}
	section := func(id uint64, name string, version uint64) {
		t.Helper()
		write([]byte{4})
		integer(id, 4)
		write([]byte{byte(len(name))})
		write([]byte(name))
		integer(0, 4)
		integer(version, 4)
	}
	write([]byte("QEVM\x00\x00\x00\x03\x07"))
	machine := "pc-i440fx-2.0"
	integer(uint64(len(machine)), 4)
	write([]byte(machine))
	section(1, "pbs-state", 1)
	integer(8192, 8)
	write(make([]byte, 8192))
	write([]byte{0x7e})
	integer(1, 4)
	section(2, "ram", 4)
	integer(uint64(info.Size())|4, 8)
	write([]byte("\x06pc.ram"))
	integer(uint64(info.Size()), 8)
	page := make([]byte, 4096)
	for at := uint64(0); at < uint64(info.Size()); at += 4096 {
		if _, err := io.ReadFull(source, page); err != nil {
			t.Fatal(err)
		}
		fill := bytes.Count(page, page[:1]) == len(page)
		flags := uint64(8)
		if fill {
			flags = 2
		}
		if at != 0 {
			flags |= 32
		}
		integer(at|flags, 8)
		if at == 0 {
			write([]byte("\x06pc.ram"))
		}
		if fill {
			write(page[:1])
		} else {
			write(page)
		}
	}
	integer(16, 8)
	write([]byte{0x7e})
	integer(2, 4)
	write([]byte{0, 6})
	description, err := json.Marshal(map[string]any{"page_size": 4096, "devices": []any{map[string]any{"vmsd_name": "PIIX3"}}})
	if err != nil {
		t.Fatal(err)
	}
	integer(uint64(len(description)), 4)
	write(description)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	return uint64(info.Size())
}
func TestQEMUWindowsLinuxPagingEvidenceAndCache(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			fixture, err := testfixture.Write(t.TempDir(), platform)
			if err != nil {
				t.Fatal(err)
			}
			cfg := engine.Config{Image: fixture.Image, Symbols: fixture.Symbols, OS: platform, DTB: fixture.DTB, KernelBase: fixture.KernelBase, Arch: "x64", Offline: true, CaseDir: t.TempDir()}
			reference := runXenProcesses(t, cfg, 2)
			image := filepath.Join(t.TempDir(), "guest.qemu")
			size := wrapQEMUSource(t, fixture.Image, image)
			cfg.Image = image
			cfg.CaseDir = t.TempDir()
			e, err := engine.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(fixture.Image)
			if err != nil {
				t.Fatal(err)
			}
			sum := xenPhysicalDigest(t, e.Env.Physical, size)
			if e.Format != "qemu" || sum == e.Hash {
				t.Fatal("container hash not preserved")
			}
			var actual bytes.Buffer
			page := make([]byte, 4096)
			for at := uint64(0); at < size; at += 4096 {
				n, err := e.Env.Physical.ReadAt(context.Background(), page, at)
				if err != nil || n != len(page) {
					t.Fatal(n, err)
				}
				actual.Write(page)
			}
			if !bytes.Equal(raw, actual.Bytes()) {
				t.Fatal("physical reconstruction differs")
			}
			e.Close()
			rows := runXenProcesses(t, cfg, 2)
			for i := range rows {
				if !bytes.Equal(rows[i], reference[i]) {
					t.Fatal("selected process columns differ")
				}
			}
		})
	}
}
func TestQEMUHTTPRangePipeline(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "guest.qemu")
	wrapQEMUSource(t, fixture.Image, image)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, err := os.Open(image)
		if err != nil {
			t.Error(err)
			http.Error(w, "unavailable", 500)
			return
		}
		defer source.Close()
		w.Header().Set("ETag", `"snapshot-v1"`)
		http.ServeContent(w, r, "guest.qemu", time.Time{}, source)
	}))
	defer server.Close()
	cfg := engine.Config{Image: server.URL + "/guest.qemu", Symbols: fixture.Symbols, OS: "linux", Arch: "x64", DTB: fixture.DTB, CaseDir: t.TempDir()}
	remote := runXenProcesses(t, cfg, 2)
	cfg.Image = image
	cfg.CaseDir = t.TempDir()
	cfg.Offline = true
	local := runXenProcesses(t, cfg, 2)
	for i := range local {
		if !bytes.Equal(local[i], remote[i]) {
			t.Fatal("remote QEMU fields differ")
		}
	}
}
func TestOfficialQEMUReencodedLinux(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional RAW reencoding, not actual QEMU producer corpus")
	}
	raw := filepath.Join(dir, "linux-sample-1.bin")
	cfg := engine.Config{Image: raw, Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", OS: "linux", Offline: true, CaseDir: t.TempDir()}
	reference := runXenProcesses(t, cfg, 133)
	image := filepath.Join(t.TempDir(), "guest.qemu")
	size := wrapQEMUSource(t, raw, image)
	cfg.Image = image
	cfg.CaseDir = t.TempDir()
	e, err := engine.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.Discovery == nil || xenPhysicalDigest(t, e.Env.Physical, size) != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		e.Close()
		t.Fatal("physical bytes or automatic discovery drift")
	}
	e.Close()
	rows := runXenProcesses(t, cfg, 133)
	for i := range rows {
		if !bytes.Equal(rows[i], reference[i]) {
			t.Fatalf("process row %d differs", i)
		}
	}
	t.Log("512MiB physical SHA, automatic DTB, 133 ordered selected process fields, sealed case and cache replay verified; reencoded stream only")
}
