package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type ImageSourceOptions struct {
	Offline        bool
	VMwareMetadata string
}

// OpenImageSource assembles acquisition members; OpenSource opens one stream.
// The returned source owns every opened member and exposes the VMEM bytes.
func OpenImageSource(ctx context.Context, location string, options ImageSourceOptions) (source MemorySource, err error) {
	source, err = OpenSource(ctx, location, options.Offline)
	if err != nil {
		return nil, err
	}
	input := source
	var extra MemorySource
	defer func() {
		if err != nil {
			input.Close()
			if extra != nil {
				extra.Close()
			}
		}
	}()
	ext := sourceExtension(location)
	memorySource, metadataSource := source, MemorySource(nil)
	if ext == ".vmss" || ext == ".vmsn" {
		if options.VMwareMetadata != "" {
			return nil, fmt.Errorf("--vmware-metadata requires a VMEM input")
		}
		extra, err = OpenSource(ctx, replaceSourceExtension(location, ".vmem"), options.Offline)
		if err != nil {
			return nil, fmt.Errorf("VMware VMEM companion: %w", err)
		}
		memorySource, metadataSource = extra, source
	} else if ext == ".vmem" || options.VMwareMetadata != "" {
		candidates := []string{options.VMwareMetadata}
		if options.VMwareMetadata == "" {
			candidates = []string{replaceSourceExtension(location, ".vmss"), replaceSourceExtension(location, ".vmsn")}
		}
		for _, candidate := range candidates {
			extra, err = OpenSource(ctx, candidate, options.Offline)
			if err == nil {
				metadataSource = extra
				break
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if metadataSource == nil {
			return nil, fmt.Errorf("VMware metadata companion unavailable: %w", err)
		}
	} else {
		return source, nil
	}
	bundle, err := NewVMwareSource(memorySource, metadataSource)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}
func sourceExtension(location string) string {
	if strings.Contains(location, "://") {
		if u, err := url.Parse(location); err == nil {
			return strings.ToLower(filepath.Ext(u.Path))
		}
	}
	return strings.ToLower(filepath.Ext(location))
}
func replaceSourceExtension(location, extension string) string {
	if strings.Contains(location, "://") {
		if u, err := url.Parse(location); err == nil {
			u.Path = strings.TrimSuffix(u.Path, filepath.Ext(u.Path)) + extension
			u.RawPath = ""
			return u.String()
		}
	}
	return strings.TrimSuffix(location, filepath.Ext(location)) + extension
}
func sourceDisplay(source MemorySource) string {
	name := source.Name()
	if !strings.Contains(name, "://") {
		if absolute, err := filepath.Abs(name); err == nil {
			return absolute
		}
	}
	return name
}

type VMwareAcquisition struct {
	Schema         string `json:"schema"`
	MemorySHA256   string `json:"memory_sha256"`
	MemorySize     uint64 `json:"memory_size"`
	MetadataSHA256 string `json:"metadata_sha256"`
	MetadataSize   uint64 `json:"metadata_size"`
}

// VMwareSource pins both acquisition members. It does not own them until
// construction succeeds. Validation is task-bound, not a stat for every page.
type VMwareSource struct {
	memory, metadata MemorySource
	files            []struct {
		source *FileSource
		info   os.FileInfo
	}
	closeOnce sync.Once
	closeErr  error
}

func NewVMwareSource(memorySource, metadataSource MemorySource) (*VMwareSource, error) {
	if memorySource == nil || metadataSource == nil {
		return nil, fmt.Errorf("VMware requires memory and metadata sources")
	}
	source := &VMwareSource{memory: memorySource, metadata: metadataSource}
	for _, member := range []MemorySource{memorySource, metadataSource} {
		if file, ok := member.(*FileSource); ok {
			info, err := file.Stat()
			if err != nil {
				return nil, err
			}
			if info.Size() < 0 || uint64(info.Size()) != member.Size() {
				return nil, fmt.Errorf("VMware member changed size during opening")
			}
			for _, other := range source.files {
				if os.SameFile(info, other.info) {
					return nil, fmt.Errorf("VMware memory and metadata alias the same file")
				}
			}
			source.files = append(source.files, struct {
				source *FileSource
				info   os.FileInfo
			}{file, info})
		}
	}
	if memoryHTTP, ok := memorySource.(*HTTPSource); ok {
		if metadataHTTP, ok := metadataSource.(*HTTPSource); ok && memoryHTTP.location == metadataHTTP.location {
			return nil, fmt.Errorf("VMware members alias the same HTTP resource")
		}
	}
	return source, nil
}
func (s *VMwareSource) Name() string { return sourceDisplay(s.memory) }
func (s *VMwareSource) Size() uint64 { return s.memory.Size() }
func (s *VMwareSource) ReadAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	return s.memory.ReadAt(ctx, p, offset)
}
func (s *VMwareSource) Close() error {
	s.closeOnce.Do(func() { s.closeErr = errors.Join(s.memory.Close(), s.metadata.Close()) })
	return s.closeErr
}
func (s *VMwareSource) FileInfos() []os.FileInfo {
	result := make([]os.FileInfo, 0, len(s.files))
	for _, file := range s.files {
		result = append(result, file.info)
	}
	return result
}
func (s *VMwareSource) Validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, file := range s.files {
		info, err := file.source.Stat()
		if err != nil {
			return err
		}
		if info.Size() != file.info.Size() || !info.ModTime().Equal(file.info.ModTime()) {
			return fmt.Errorf("VMware acquisition member changed since opening")
		}
	}
	for _, member := range []MemorySource{s.memory, s.metadata} {
		if remote, ok := member.(interface{ Validate(context.Context) error }); ok {
			if err := remote.Validate(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// AcquisitionIdentity binds region metadata to the memory content. The returned
// hash is the SHA-256 of the fixed JSON manifest, not the VMEM file hash alone.
func (s *VMwareSource) AcquisitionIdentity(ctx context.Context, memoryHash string) (string, VMwareAcquisition, error) {
	manifest := VMwareAcquisition{Schema: "gomem.vmware-acquisition/v1", MemorySHA256: memoryHash, MemorySize: s.memory.Size(), MetadataSize: s.metadata.Size()}
	if err := s.Validate(ctx); err != nil {
		return "", manifest, err
	}
	hash := sha256.New()
	buffer := make([]byte, 4<<20)
	for offset := uint64(0); offset < s.metadata.Size(); {
		length := min(uint64(len(buffer)), s.metadata.Size()-offset)
		n, err := s.metadata.ReadAt(ctx, buffer[:int(length)], offset)
		if err != nil {
			return "", manifest, err
		}
		if uint64(n) != length {
			return "", manifest, io.ErrUnexpectedEOF
		}
		hash.Write(buffer[:n])
		offset += length
	}
	if err := s.Validate(ctx); err != nil {
		return "", manifest, err
	}
	manifest.MetadataSHA256 = hex.EncodeToString(hash.Sum(nil))
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", manifest, err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), manifest, nil
}
