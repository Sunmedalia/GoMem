package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lcTestDevice struct {
	runs   []Range
	fail   bool
	cancel context.CancelFunc
	reads  int
}

func (d *lcTestDevice) Ranges() ([]Range, error) { return d.runs, nil }
func (d *lcTestDevice) Read(p []byte, at uint64) bool {
	d.reads++
	for i := range p {
		p[i] = byte(at + uint64(i))
	}
	if d.cancel != nil {
		d.cancel()
	}
	return !d.fail
}
func (d *lcTestDevice) Close() {}
func TestLeechCoreCaptureRangesAndIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sources")
	d := &lcTestDevice{runs: []Range{{Start: 0x8000, Length: 4096}, {Start: 0x1000, Length: 4096}}}
	s, err := captureLeechCore(context.Background(), d, LeechCoreOptions{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Size() != 8256 || s.SnapshotInfo().Protocol != "leechcore" {
		t.Fatal(s.SnapshotInfo())
	}
	data := make([]byte, s.Size())
	if _, err := s.ReadAt(context.Background(), data, 0); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if s.SnapshotInfo().SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("capture hash differs")
	}
	layer, format, err := Detect(context.Background(), s)
	if err != nil || format != "lime" {
		t.Fatal(format, err)
	}
	if len(layer.Ranges()) != 2 || layer.Ranges()[0].Start != 0x1000 || layer.Ranges()[1].Start != 0x8000 {
		t.Fatal(layer.Ranges())
	}
	p := make([]byte, 16)
	if _, err := layer.ReadAt(context.Background(), p, 0x8011); err != nil || p[0] != 0x11 {
		t.Fatal(p, err)
	}
	if _, err := layer.ReadAt(context.Background(), p, 0x2000); !errors.Is(err, ErrUnmapped) {
		t.Fatal("hole padded", err)
	}
	if err := s.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := s.path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capture leaked")
	}
}
func TestLeechCoreCaptureRejectsFailuresAndBounds(t *testing.T) {
	for _, runs := range [][]Range{nil, {{Length: 0}}, {{Start: ^uint64(0), Length: 1}}, {{Length: 8192}, {Start: 4096, Length: 4096}}} {
		d := &lcTestDevice{runs: runs}
		if s, err := captureLeechCore(context.Background(), d, LeechCoreOptions{Directory: t.TempDir()}); err == nil {
			s.Close()
			t.Fatal("invalid ranges accepted")
		}
		if d.reads != 0 {
			t.Fatal("invalid map read")
		}
	}
	for _, mode := range []string{"read-fault", "cancel", "budget"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d := &lcTestDevice{runs: []Range{{Length: 4096}}}
			options := LeechCoreOptions{Directory: dir}
			switch mode {
			case "read-fault":
				d.fail = true
			case "cancel":
				d.cancel = cancel
			case "budget":
				options.MaxBytes = 4096
			}
			if s, err := captureLeechCore(ctx, d, options); err == nil {
				s.Close()
				t.Fatal("failure accepted")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("partial capture leaked", entries, err)
			}
		})
	}
}
func TestLeechCoreURIAndOffline(t *testing.T) {
	for _, uri := range []string{"", "file://image", "leechcore://", "leechcore://a\x00b", "leechcore://" + strings.Repeat("x", 260)} {
		if _, err := leechCoreDeviceURI(uri); err == nil {
			t.Fatal("invalid URI accepted")
		}
	}
	uri := "leechcore://file:///tmp/memory.raw"
	if d, err := leechCoreDeviceURI(uri); err != nil || d != "file:///tmp/memory.raw" {
		t.Fatal(d, err)
	}
	if _, err := OpenImageSource(context.Background(), uri, ImageSourceOptions{Offline: true}); err == nil {
		t.Fatal("offline device opened")
	}
	if _, err := OpenLeechCore(context.Background(), uri, LeechCoreOptions{Library: "relative"}); err == nil {
		t.Fatal("implicit library accepted")
	}
}
func TestLeechCoreActualLibrarySparseLiME(t *testing.T) {
	library := os.Getenv("GOMEM_LEECHCORE_LIBRARY")
	if library == "" || !LeechCoreSupported() {
		t.Skip("set GOMEM_LEECHCORE_LIBRARY for actual native library")
	}
	var data bytes.Buffer
	for _, at := range []uint64{0x1000, 0x2000000} {
		var h [32]byte
		binary.LittleEndian.PutUint32(h[:], 0x4c694d45)
		binary.LittleEndian.PutUint32(h[4:], 1)
		binary.LittleEndian.PutUint64(h[8:], at)
		binary.LittleEndian.PutUint64(h[16:], at+(8<<20)-1)
		data.Write(h[:])
		data.Write(bytes.Repeat([]byte{byte(at >> 12)}, 8<<20))
	}
	path := filepath.Join(t.TempDir(), "source.lime")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenLeechCore(context.Background(), "leechcore://"+path, LeechCoreOptions{Library: library, Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := make([]byte, s.Size())
	for at := 0; at < len(got); {
		end := min(at+MaxRead, len(got))
		if _, err := s.ReadAt(context.Background(), got[at:end], uint64(at)); err != nil {
			t.Fatal(err)
		}
		at = end
	}
	if !bytes.Equal(got, data.Bytes()) {
		t.Fatal("native map or captured physical bytes differ")
	}
}
func FuzzLeechCoreURI(f *testing.F) {
	for _, s := range []string{"leechcore://file:///tmp/a", "leechcore://fpga", "leechcore://", "leechcore://a\x00b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		device, err := leechCoreDeviceURI(s)
		if err == nil && (len(device) == 0 || len(device) >= 260 || strings.ContainsRune(device, 0)) {
			t.Fatal("invalid accepted device")
		}
	})
}
