package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

// Write the physical source verbatim into a synthetic Xen container. The index
// and metadata stay bounded; the acquisition itself is copied as a stream.
func wrapXenSource(t testing.TB, input, output string, p2m bool) uint64 {
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
		t.Fatal("test source must have complete pages")
	}
	count := uint64(info.Size() / 4096)
	stride := uint64(8)
	indexName := ".xen_pfn"
	if p2m {
		stride = 16
		indexName = ".xen_p2m"
	}
	names := []byte("\x00.shstrtab\x00" + indexName + "\x00.xen_pages\x00.note.Xen\x00")
	stringsOffset := uint64(64 + 5*64)
	indexOffset := (stringsOffset + uint64(len(names)) + 15) &^ uint64(15)
	notesOffset := (indexOffset + count*stride + 15) &^ uint64(15)
	pagesOffset := (notesOffset + 88 + 4095) &^ uint64(4095)
	prefix := make([]byte, pagesOffset)
	order := binary.LittleEndian
	copy(prefix, "\x7fELF")
	prefix[4], prefix[5], prefix[6] = 2, 1, 1
	order.PutUint16(prefix[16:], 4)
	order.PutUint16(prefix[18:], 62)
	order.PutUint32(prefix[20:], 1)
	order.PutUint64(prefix[40:], 64)
	order.PutUint16(prefix[52:], 64)
	order.PutUint16(prefix[58:], 64)
	order.PutUint16(prefix[60:], 5)
	order.PutUint16(prefix[62:], 1)
	copy(prefix[stringsOffset:], names)
	nameOffset := uint32(1)
	offsets := []uint64{stringsOffset, indexOffset, pagesOffset, notesOffset}
	lengths := []uint64{uint64(len(names)), count * stride, uint64(info.Size()), 88}
	for i, name := range []string{".shstrtab", indexName, ".xen_pages", ".note.Xen"} {
		header := prefix[64+64*(i+1):]
		kind := uint32(1)
		if i == 0 {
			kind = 3
		}
		if i == 3 {
			kind = 7
		}
		order.PutUint32(header, nameOffset)
		order.PutUint32(header[4:], kind)
		order.PutUint64(header[24:], offsets[i])
		order.PutUint64(header[32:], lengths[i])
		order.PutUint64(header[48:], 1)
		nameOffset += uint32(len(name) + 1)
	}
	for i := uint64(0); i < count; i++ {
		order.PutUint64(prefix[indexOffset+i*stride:], i)
		if p2m {
			order.PutUint64(prefix[indexOffset+i*stride+8:], i+count)
		}
	}
	magic := uint64(0xf00febee)
	if p2m {
		magic = 0xf00febed
	}
	at := notesOffset
	for _, note := range []struct {
		kind   uint32
		values []uint64
	}{{0x2000000, nil}, {0x2000001, []uint64{magic, 2, count, 4096}}, {0x2000003, []uint64{1}}} {
		order.PutUint32(prefix[at:], 4)
		order.PutUint32(prefix[at+4:], uint32(len(note.values)*8))
		order.PutUint32(prefix[at+8:], note.kind)
		copy(prefix[at+12:], "Xen\x00")
		for i, v := range note.values {
			order.PutUint64(prefix[at+16+uint64(i)*8:], v)
		}
		at += 16 + uint64(len(note.values))*8
	}
	outputFile, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer outputFile.Close()
	if _, err = outputFile.Write(prefix); err != nil {
		t.Fatal(err)
	}
	n, err := io.CopyBuffer(outputFile, source, make([]byte, 64<<10))
	if err != nil || n != info.Size() {
		t.Fatal(n, err)
	}
	if err = outputFile.Close(); err != nil {
		t.Fatal(err)
	}
	return uint64(info.Size())
}
func xenPhysicalDigest(t testing.TB, layer memory.MemoryLayer, size uint64) string {
	t.Helper()
	hash := sha256.New()
	buffer := make([]byte, 4<<20)
	for offset := uint64(0); offset < size; {
		length := min(uint64(len(buffer)), size-offset)
		got, err := layer.ReadAt(context.Background(), buffer[:int(length)], offset)
		if err != nil || uint64(got) != length {
			t.Fatal(got, err)
		}
		hash.Write(buffer[:got])
		offset += length
	}
	return hex.EncodeToString(hash.Sum(nil))
}
func runXenProcesses(t testing.TB, config engine.Config, expected int) [][]byte {
	t.Helper()
	e, err := engine.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows [][]byte
	result, err := e.Run(context.Background(), config.OS+".pslist", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		cells := map[string]evidence.Value{}
		for _, key := range []string{"Offset", "PID", "PPID", "Name", "TID", "Created", "DTB"} {
			if value, ok := row.Cells[key]; ok {
				cells[key] = value
			}
		}
		encoded, err := json.Marshal(cells)
		rows = append(rows, encoded)
		return err
	}})
	if err != nil || len(rows) != expected {
		t.Fatal(result, len(rows), err)
	}
	cached, err := e.Run(context.Background(), config.OS+".pslist", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
		t.Fatal(cached, err)
	}
	verified, err := e.Store.VerifyCase(context.Background(), "")
	if err != nil || !verified.Verified {
		t.Fatal(verified, err)
	}
	return rows
}
func TestXenWindowsLinuxPagingEvidenceAndCache(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			fixture, err := testfixture.Write(t.TempDir(), platform)
			if err != nil {
				t.Fatal(err)
			}
			config := engine.Config{Image: fixture.Image, Symbols: fixture.Symbols, OS: platform, DTB: fixture.DTB, KernelBase: fixture.KernelBase, Arch: "x64", Offline: true, CaseDir: t.TempDir()}
			reference := runXenProcesses(t, config, 2)
			for _, p2m := range []bool{false, true} {
				t.Run(fmt.Sprint(p2m), func(t *testing.T) {
					image := filepath.Join(t.TempDir(), "memory.xen")
					size := wrapXenSource(t, fixture.Image, image, p2m)
					config.Image, config.CaseDir = image, t.TempDir()
					e, err := engine.Open(context.Background(), config)
					if err != nil {
						t.Fatal(err)
					}
					if e.Format != "xen" {
						e.Close()
						t.Fatal(e.Format)
					}
					rawSource, err := memory.OpenFile(fixture.Image)
					if err != nil {
						e.Close()
						t.Fatal(err)
					}
					digest, err := engine.Hash(context.Background(), rawSource)
					rawSource.Close()
					if err != nil || xenPhysicalDigest(t, e.Env.Physical, size) != digest || e.Hash == digest {
						e.Close()
						t.Fatal("container/physical identity mismatch", err)
					}
					e.Close()
					rows := runXenProcesses(t, config, 2)
					for i := range rows {
						if string(rows[i]) != string(reference[i]) {
							t.Fatalf("selected process fields differ: %s / %s", rows[i], reference[i])
						}
					}
				})
			}
		})
	}
}
func TestOfficialXenReencodedLinux(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional reencoded RAW acquisition; not a real Xen producer corpus")
	}
	rawImage := filepath.Join(dir, "linux-sample-1.bin")
	symbols := filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"
	config := engine.Config{Image: rawImage, Symbols: symbols, OS: "linux", CaseDir: t.TempDir(), Offline: true}
	reference := runXenProcesses(t, config, 133)
	for _, p2m := range []bool{false, true} {
		t.Run(fmt.Sprint(p2m), func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "reencoded.xen")
			size := wrapXenSource(t, rawImage, image, p2m)
			config.Image, config.CaseDir = image, t.TempDir()
			e, err := engine.Open(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			if e.Format != "xen" || xenPhysicalDigest(t, e.Env.Physical, size) != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
				e.Close()
				t.Fatal("physical acquisition drift")
			}
			if e.Discovery == nil {
				e.Close()
				t.Fatal("Linux discovery missing")
			}
			e.Close()
			rows := runXenProcesses(t, config, 133)
			for i := range rows {
				if string(rows[i]) != string(reference[i]) {
					t.Fatalf("row %d differs", i)
				}
			}
			t.Log("full 512MiB physical digest, auto DTB discovery, 133 ordered selected process fields, seals and cache verified; reencoded container only")
		})
	}
}

func TestXenHTTPRangeLayerAssembly(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "guest.xen")
	wrapXenSource(t, fixture.Image, image, true)
	source, err := memory.OpenFile(image)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := engine.Hash(context.Background(), source)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, err := os.Open(image)
		if err != nil {
			t.Error(err)
			http.Error(w, "unavailable", 500)
			return
		}
		defer file.Close()
		w.Header().Set("ETag", `"`+digest+`"`)
		http.ServeContent(w, r, "guest.xen", time.Time{}, file)
	}))
	defer server.Close()
	config := engine.Config{Image: server.URL + "/guest.xen", Symbols: fixture.Symbols, OS: "linux", DTB: fixture.DTB, Arch: "x64", CaseDir: t.TempDir()}
	remote := runXenProcesses(t, config, 2)
	config.Image, config.CaseDir = image, t.TempDir()
	local := runXenProcesses(t, config, 2)
	for i := range local {
		if string(remote[i]) != string(local[i]) {
			t.Fatal("remote Xen process fields differ")
		}
	}
}
