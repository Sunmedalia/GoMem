package memory

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LeechCoreOptions configures a read-only acquisition. Library must be an
// explicit absolute path; no system search or implicit native library loading.
type LeechCoreOptions struct {
	Library   string
	Remote    string
	Directory string
	MaxBytes  uint64
}

type leechCoreDevice interface {
	Ranges() ([]Range, error)
	Read([]byte, uint64) bool
	Close()
}

func leechCoreDeviceURI(location string) (string, error) {
	const prefix = "leechcore://"
	if len(location) < len(prefix) || !strings.EqualFold(location[:len(prefix)], prefix) {
		return "", fmt.Errorf("invalid LeechCore URI")
	}
	device := location[len(prefix):]
	if len(device) == 0 || len(device) >= 260 || strings.IndexFunc(device, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", fmt.Errorf("invalid LeechCore device")
	}
	return device, nil
}

// OpenLeechCore captures physical ranges into a private LiME file. Failed reads
// are never zero-padded. Native device access ends before analysis starts.
func OpenLeechCore(ctx context.Context, location string, options LeechCoreOptions) (*SnapshotSource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	device, err := leechCoreDeviceURI(location)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(options.Library) || strings.ContainsRune(options.Library, 0) {
		return nil, fmt.Errorf("LeechCore requires an absolute --leechcore-library path")
	}
	if len(options.Remote) >= 260 || strings.IndexFunc(options.Remote, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("invalid LeechCore remote configuration")
	}
	backend, err := openNativeLeechCore(options.Library, device, options.Remote)
	if err != nil {
		return nil, err
	}
	defer backend.Close()
	return captureLeechCore(ctx, backend, options)
}
func captureLeechCore(ctx context.Context, device leechCoreDevice, options LeechCoreOptions) (source *SnapshotSource, err error) {
	runs, err := device.Ranges()
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 || len(runs) > 65536 {
		return nil, fmt.Errorf("invalid LeechCore memory range count")
	}
	runs = append([]Range(nil), runs...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].Start < runs[j].Start })
	var total, end uint64
	for i, r := range runs {
		next, e := Add(r.Start, r.Length)
		if e != nil || r.Length == 0 || (i > 0 && r.Start < end) {
			return nil, fmt.Errorf("invalid LeechCore memory range")
		}
		end = next
		n, e := Add(r.Length, 32)
		if e != nil {
			return nil, e
		}
		total, e = Add(total, n)
		if e != nil || total > math.MaxInt64 {
			return nil, fmt.Errorf("LeechCore capture size overflow")
		}
	}
	if options.MaxBytes != 0 && total > options.MaxBytes {
		return nil, fmt.Errorf("LeechCore capture exceeds budget")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Directory != "" {
		if err := os.MkdirAll(options.Directory, 0700); err != nil {
			return nil, fmt.Errorf("LeechCore snapshot directory unavailable")
		}
	}
	target, err := os.CreateTemp(options.Directory, "gomem-leechcore-*.lime")
	if err != nil {
		return nil, fmt.Errorf("LeechCore snapshot creation failed")
	}
	path := target.Name()
	retained := false
	defer func() {
		target.Close()
		if !retained {
			os.Remove(path)
		}
	}()
	hash := sha256.New()
	output := io.MultiWriter(target, hash)
	buffer := make([]byte, 1<<20)
	for _, r := range runs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var header [32]byte
		binary.LittleEndian.PutUint32(header[:], 0x4c694d45)
		binary.LittleEndian.PutUint32(header[4:], 1)
		binary.LittleEndian.PutUint64(header[8:], r.Start)
		binary.LittleEndian.PutUint64(header[16:], r.Start+r.Length-1)
		if _, err = output.Write(header[:]); err != nil {
			return nil, fmt.Errorf("LeechCore snapshot write failed")
		}
		for at := uint64(0); at < r.Length; {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			n := min(uint64(len(buffer)), r.Length-at)
			if !device.Read(buffer[:n], r.Start+at) {
				return nil, &ReadError{Address: r.Start + at, Length: int(n), Layer: "leechcore:acquisition", Cause: fmt.Errorf("native read failed")}
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if _, err = output.Write(buffer[:n]); err != nil {
				return nil, fmt.Errorf("LeechCore snapshot write failed")
			}
			at += n
		}
	}
	if err = target.Sync(); err != nil {
		return nil, fmt.Errorf("LeechCore snapshot sync failed")
	}
	info, err := target.Stat()
	if err != nil {
		return nil, fmt.Errorf("LeechCore snapshot stat failed")
	}
	if err = target.Close(); err != nil {
		return nil, fmt.Errorf("LeechCore snapshot close failed")
	}
	file, err := OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("LeechCore snapshot reopen failed")
	}
	reopened, err := file.Stat()
	if err != nil || !os.SameFile(info, reopened) || reopened.Size() != int64(total) {
		file.Close()
		return nil, fmt.Errorf("LeechCore snapshot changed")
	}
	retained = true
	return &SnapshotSource{file: file, info: reopened, path: path, name: "leechcore://acquired-memory", capture: RemoteSnapshotInfo{Schema: "gomem.remote-snapshot/v1", Protocol: "leechcore", SHA256: hex.EncodeToString(hash.Sum(nil)), Size: total}}, nil
}
