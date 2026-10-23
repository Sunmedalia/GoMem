package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type vmwareOracleCase struct {
	Name             string
	Memory, Metadata []byte
	MemorySHA        string `json:"memory_sha256"`
	MetadataSHA      string `json:"metadata_sha256"`
	NativeError      bool   `json:"native_error"`
	Expected         []struct {
		Address      string
		Offset, Size uint64
		SHA256       string
	}
	Upstream struct {
		Error string
		Reads []struct{ Address, SHA256 string }
	}
}

func vmwareOracle(t testing.TB) []vmwareOracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/vmware-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Baseline string `json:"baseline_commit"`
		Cases    []vmwareOracleCase
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || len(fixture.Cases) != 26 {
		t.Fatal("oracle drift")
	}
	return fixture.Cases
}
func TestVMwareActualBaselineAndPhysicalBytes(t *testing.T) {
	for _, test := range vmwareOracle(t) {
		t.Run(test.Name, func(t *testing.T) {
			for _, member := range []struct {
				data []byte
				hash string
			}{{test.Memory, test.MemorySHA}, {test.Metadata, test.MetadataSHA}} {
				sum := sha256.Sum256(member.data)
				if hex.EncodeToString(sum[:]) != member.hash {
					t.Fatal("fixture digest")
				}
			}
			source, err := NewVMwareSource(bufferSource(test.Memory), bufferSource(test.Metadata))
			if err != nil {
				t.Fatal(err)
			}
			layer, format, err := Detect(context.Background(), source)
			if test.NativeError {
				if err == nil {
					t.Fatal("accepted invalid acquisition")
				}
				return
			}
			if err != nil || format != "vmware" {
				t.Fatal(format, err)
			}
			var total uint64
			for _, r := range layer.Ranges() {
				total += r.Length
			}
			var expectedTotal uint64
			for _, expected := range test.Expected {
				expectedTotal += expected.Size
				address, err := strconv.ParseUint(expected.Address, 0, 64)
				if err != nil {
					t.Fatal(err)
				}
				data, err := Read(context.Background(), layer, address, int(expected.Size))
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(data)
				if hex.EncodeToString(sum[:]) != expected.SHA256 || !bytes.Equal(data, test.Memory[expected.Offset:expected.Offset+expected.Size]) {
					t.Fatal("mapping bytes differ")
				}
				if test.Name != "unordered" {
					found := false
					for _, r := range test.Upstream.Reads {
						if r.Address == expected.Address && r.SHA256 == expected.SHA256 {
							found = true
						}
					}
					if !found || test.Upstream.Error != "" {
						t.Fatal("upstream mismatch", test.Upstream.Error)
					}
				}
			}
			if total != expectedTotal {
				t.Fatal("extra mappings")
			}
			if test.Name == "unordered" && test.Upstream.Error != "InvalidAddressException" {
				t.Fatal("upstream ordering divergence changed")
			}
		})
	}
}
func TestVMwarePairOpeningAndIdentity(t *testing.T) {
	test := vmwareOracle(t)[0]
	dir := t.TempDir()
	memory := filepath.Join(dir, "sample.vmem")
	metadata := filepath.Join(dir, "sample.vmsn")
	if err := os.WriteFile(memory, test.Memory, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenImageSource(context.Background(), memory, ImageSourceOptions{Offline: true}); err == nil {
		t.Fatal("missing metadata became RAW")
	}
	if err := os.WriteFile(metadata, test.Metadata, 0600); err != nil {
		t.Fatal(err)
	}
	var identity string
	for _, input := range []string{memory, metadata} {
		source, err := OpenImageSource(context.Background(), input, ImageSourceOptions{Offline: true})
		if err != nil {
			t.Fatal(err)
		}
		bundle := source.(*VMwareSource)
		hash, manifest, err := bundle.AcquisitionIdentity(context.Background(), test.MemorySHA)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.MetadataSHA256 != test.MetadataSHA || manifest.MemorySHA256 != test.MemorySHA {
			t.Fatal(manifest)
		}
		if identity != "" && hash != identity {
			t.Fatal("input member changed acquisition identity")
		}
		identity = hash
		if err := bundle.Close(); err != nil {
			t.Fatal(err)
		}
		if err := bundle.Close(); err != nil {
			t.Fatal(err)
		}
	}
	source, err := OpenImageSource(context.Background(), memory, ImageSourceOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	changed := append(bytes.Clone(test.Metadata), 0)
	if err := os.WriteFile(metadata, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.(*VMwareSource).Validate(context.Background()); err == nil {
		t.Fatal("metadata mutation undetected")
	}
	if _, err := OpenImageSource(context.Background(), memory, ImageSourceOptions{VMwareMetadata: memory}); err == nil {
		t.Fatal("same-file pair accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Detect(ctx, source); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestVMwareTruncatedMetadata(t *testing.T) {
	test := vmwareOracle(t)[0]
	for end := 0; end < len(test.Metadata); end++ {
		source, err := NewVMwareSource(bufferSource(test.Memory), bufferSource(test.Metadata[:end]))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Detect(context.Background(), source); err == nil {
			t.Fatalf("accepted truncated metadata at %d", end)
		}
	}
}
func FuzzVMwareMetadata(f *testing.F) {
	for _, test := range vmwareOracle(f) {
		f.Add(test.Metadata)
	}
	f.Fuzz(func(t *testing.T, metadata []byte) {
		if len(metadata) > 2<<20 {
			t.Skip()
		}
		source, err := NewVMwareSource(bufferSource(make([]byte, 3*4096)), bufferSource(metadata))
		if err != nil {
			t.Fatal(err)
		}
		layer, _, err := Detect(context.Background(), source)
		if err != nil {
			return
		}
		for _, r := range layer.Ranges() {
			if r.Length == 0 || r.FileOffset > source.Size() || r.Length > source.Size()-r.FileOffset {
				t.Fatal("invalid accepted range")
			}
		}
	})
}

func TestVMwareHTTPCompanionIdentity(t *testing.T) {
	test := vmwareOracle(t)[0]
	var changed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data []byte
		switch r.URL.Path {
		case "/sample.vmem":
			data = test.Memory
		case "/sample.vmss":
			data = test.Metadata
		default:
			http.NotFound(w, r)
			return
		}
		etag := `"v1"`
		if r.URL.Path == "/sample.vmss" && changed.Load() {
			etag = `"v2"`
		}
		w.Header().Set("ETag", etag)
		http.ServeContent(w, r, "sample", time.Time{}, bytes.NewReader(data))
	}))
	defer server.Close()
	location := server.URL + "/sample.vmem?token=private-value"
	if _, err := OpenImageSource(context.Background(), location, ImageSourceOptions{Offline: true}); err == nil {
		t.Fatal("offline network allowed")
	}
	source, err := OpenImageSource(context.Background(), location, ImageSourceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	layer, _, err := Detect(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	header := layer.(*VMwareLayer).VMwareHeader()
	if strings.Contains(header.MemorySource+header.MetadataSource+source.Name(), "private-value") {
		t.Fatal("credential leaked")
	}
	if _, err := Read(context.Background(), layer, 0x2000, 8192); err != nil {
		t.Fatal(err)
	}
	changed.Store(true)
	if err := source.(*VMwareSource).Validate(context.Background()); err == nil {
		t.Fatal("remote metadata change undetected")
	}
}
func TestVMwareMalformedHeaderAndRegionFields(t *testing.T) {
	test := vmwareOracle(t)[0]
	for _, name := range []string{"magic", "groups-zero", "groups-limit", "group-offset", "duplicate-group", "region-layout", "region-index", "region-count", "empty-region"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(test.Metadata)
			switch name {
			case "magic":
				data[0] = 0
			case "groups-zero":
				binary.LittleEndian.PutUint32(data[8:], 0)
			case "groups-limit":
				binary.LittleEndian.PutUint32(data[8:], 65537)
			case "group-offset":
				binary.LittleEndian.PutUint64(data[156:], 12)
			case "duplicate-group":
				copy(data[12:76], make([]byte, 64))
				copy(data[12:], "memory")
			case "region-layout":
				i := bytes.Index(data, []byte("regionPPN"))
				data[i-2] = 0xc4
			case "region-index":
				i := bytes.Index(data, []byte("regionPPN"))
				binary.LittleEndian.PutUint32(data[i+9:], 65536)
			case "region-count":
				i := bytes.Index(data, []byte("regionsCount"))
				binary.LittleEndian.PutUint32(data[i+12:], 65537)
			case "empty-region":
				i := bytes.Index(data, []byte("regionSize"))
				binary.LittleEndian.PutUint32(data[i+14:], 0)
			}
			source, err := NewVMwareSource(bufferSource(test.Memory), bufferSource(data))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Detect(context.Background(), source); err == nil {
				t.Fatal("malformed metadata accepted")
			}
		})
	}
}
