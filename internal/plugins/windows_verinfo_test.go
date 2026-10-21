package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestProductVersionMatchesPefile(t *testing.T) {
	image := syntheticVersionImage(t, versionFixture{key: "VS_VERSION_INFO", major: 10, minor: 0, product: 19041, build: 2965})
	quad, err := readProductVersion(context.Background(), flatMemory(image), 0)
	if err != nil {
		t.Fatal(err)
	}
	if quad != (versionQuad{10, 0, 19041, 2965}) {
		t.Fatalf("%+v", quad)
	}
	python := filepath.Join("..", "..", ".cache", "reference-venv", "bin", "python")
	if _, err = os.Stat(python); err != nil {
		t.Skip("reference pefile is unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.dll")
	if err = os.WriteFile(path, image, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `import pefile, pathlib
pe = pefile.PE(data=pathlib.Path(%q).read_bytes(), fast_load=True)
pe.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
info = pe.VS_FIXEDFILEINFO[0]
print(info.ProductVersionMS >> 16, info.ProductVersionMS & 0xFFFF, info.ProductVersionLS >> 16, info.ProductVersionLS & 0xFFFF)
`
	script = strings.Replace(script, "%q", strconv.Quote(path), 1)
	cmd := exec.Command(python, "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "10 0 19041 2965" {
		t.Fatalf("pefile %s", out)
	}
}

func TestProductVersionUsesFirstParsableLanguage(t *testing.T) {
	image := syntheticVersionImage(t,
		versionFixture{key: "NOPE", major: 1, minor: 2, product: 3, build: 4},
		versionFixture{key: "VS_VERSION_INFO", major: 6, minor: 1, product: 7601, build: 2},
		versionFixture{key: "VS_VERSION_INFO", major: 9, minor: 9, product: 9, build: 9},
	)
	quad, err := readProductVersion(context.Background(), flatMemory(image), 0)
	if err != nil || quad != (versionQuad{6, 1, 7601, 2}) {
		t.Fatal(quad, err)
	}
	image = syntheticVersionImage(t, versionFixture{key: "NOT_VERSION", major: 1, minor: 0, product: 1, build: 0})
	if _, err = readProductVersion(context.Background(), flatMemory(image), 0); err == nil {
		t.Fatal("accepted a resource without VS_VERSION_INFO")
	}
}

func TestExtensiveVersionUsesFileVersionAndMissingMarker(t *testing.T) {
	buf := make([]byte, 0x800)
	copy(buf[0x500:], utf16BE("OriginalFilename\x00abc.dll"))
	// No signature marker: parsing starts at window offset 3.
	binary.LittleEndian.PutUint16(buf[7:], 2)
	binary.LittleEndian.PutUint16(buf[9:], 1)
	binary.LittleEndian.PutUint16(buf[11:], 4)
	binary.LittleEndian.PutUint16(buf[13:], 3)
	quad, ok, err := findExtensiveVersion(context.Background(), flatMemory(buf), "abc.dll")
	if err != nil || !ok || quad != (versionQuad{1, 2, 3, 4}) {
		t.Fatal(quad, ok, err)
	}
	copy(buf[10:14], []byte{0xbd, 0x04, 0xef, 0xfe})
	binary.LittleEndian.PutUint16(buf[14+4:], 8)
	binary.LittleEndian.PutUint16(buf[14+6:], 7)
	binary.LittleEndian.PutUint16(buf[14+8:], 6)
	binary.LittleEndian.PutUint16(buf[14+10:], 5)
	quad, ok, err = findExtensiveVersion(context.Background(), flatMemory(buf), "abc.dll")
	if err != nil || !ok || quad != (versionQuad{7, 8, 5, 6}) {
		t.Fatal(quad, ok, err)
	}
	needle := utf16BE("OriginalFilename\x00abc.dll")
	short := make([]byte, 0x10+len(needle))
	copy(short[0x10:], needle)
	if _, _, err = findExtensiveVersion(context.Background(), flatMemory(short), "abc.dll"); err == nil || !strings.Contains(err.Error(), "preamble") {
		t.Fatal(err)
	}
}

func TestVerInfoPluginRegistered(t *testing.T) {
	registry := plugin.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	spec, err := registry.Get("windows.verinfo")
	if err != nil || spec.Spec().Upstream != "windows.verinfo.VerInfo" {
		t.Fatal(err, spec)
	}
}

type versionFixture struct {
	key                          string
	major, minor, product, build uint16
}

func syntheticVersionImage(t *testing.T, fixtures ...versionFixture) []byte {
	t.Helper()
	if len(fixtures) == 0 || len(fixtures) > 3 {
		t.Fatal("fixture count")
	}
	const (
		imageSize   = 0x3000
		resourceRVA = 0x1000
		blobBase    = 0x1800
	)
	image := make([]byte, imageSize)
	copy(image, []byte("MZ"))
	binary.LittleEndian.PutUint32(image[0x3C:], 0x80)
	copy(image[0x80:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(image[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(image[0x86:], 1)
	binary.LittleEndian.PutUint16(image[0x94:], 0xF0)
	optional := image[0x98:]
	binary.LittleEndian.PutUint16(optional, 0x20B)
	binary.LittleEndian.PutUint32(optional[32:], 0x1000)
	binary.LittleEndian.PutUint32(optional[36:], 0x200)
	binary.LittleEndian.PutUint32(optional[56:], imageSize)
	binary.LittleEndian.PutUint32(optional[60:], 0x400)
	binary.LittleEndian.PutUint16(optional[68:], 3)
	binary.LittleEndian.PutUint32(optional[108:], 16)
	binary.LittleEndian.PutUint32(optional[112+16:], resourceRVA)
	binary.LittleEndian.PutUint32(optional[112+20:], 0x1000)
	section := image[0x188:]
	copy(section[:8], ".rsrc\x00\x00\x00")
	binary.LittleEndian.PutUint32(section[8:], 0x1000)
	binary.LittleEndian.PutUint32(section[12:], resourceRVA)
	binary.LittleEndian.PutUint32(section[16:], 0x1000)
	binary.LittleEndian.PutUint32(section[20:], resourceRVA)
	blobs := make([][]byte, len(fixtures))
	for i, fixture := range fixtures {
		blobs[i] = versionBlob(fixture, blobBase+uint32(i)*0x200)
	}
	writeResourceTree(image[resourceRVA:], blobs)
	for i, blob := range blobs {
		copy(image[blobBase+i*0x200:], blob)
	}
	return image
}

func versionBlob(fixture versionFixture, rva uint32) []byte {
	key := utf16.Encode([]rune(fixture.key))
	key = append(key, 0)
	header := 6 + len(key)*2
	rel := dwordAlign(uint32(header), rva)
	out := make([]byte, int(rel)+52)
	binary.LittleEndian.PutUint16(out[4:], 52)
	for i, unit := range key {
		binary.LittleEndian.PutUint16(out[6+i*2:], unit)
	}
	binary.LittleEndian.PutUint32(out[rel:], 0xFEEF04BD)
	binary.LittleEndian.PutUint32(out[rel+16:], uint32(fixture.major)<<16|uint32(fixture.minor))
	binary.LittleEndian.PutUint32(out[rel+20:], uint32(fixture.product)<<16|uint32(fixture.build))
	return out
}

func writeResourceTree(section []byte, blobs [][]byte) {
	// Root, one name directory, one language directory, then one data entry per blob.
	putU16(section, 12, 0)
	putU16(section, 14, 1)
	binary.LittleEndian.PutUint32(section[16:], verRTVersion)
	binary.LittleEndian.PutUint32(section[20:], 0x80000018)
	putU16(section, 0x18+12, 0)
	putU16(section, 0x18+14, 1)
	binary.LittleEndian.PutUint32(section[0x28:], 1)
	binary.LittleEndian.PutUint32(section[0x2C:], 0x80000030)
	putU16(section, 0x30+12, 0)
	putU16(section, 0x30+14, uint16(len(blobs)))
	for i := range blobs {
		binary.LittleEndian.PutUint32(section[0x40+i*8:], uint32(0x409+i))
		binary.LittleEndian.PutUint32(section[0x44+i*8:], uint32(0x80+i*16))
		data := section[0x80+i*16:]
		binary.LittleEndian.PutUint32(data, 0x1800+uint32(i)*0x200)
		binary.LittleEndian.PutUint32(data[4:], uint32(len(blobs[i])))
	}
}

func TestVersionBlobAlignment(t *testing.T) {
	blob := versionBlob(versionFixture{key: "VS_VERSION_INFO", major: 1, minor: 2, product: 3, build: 4}, 0x1800)
	if !bytes.Contains(blob, []byte{0xbd, 0x04, 0xef, 0xfe}) {
		t.Fatal("missing fixed signature")
	}
}

func verListEnv(mem flatMemory) plugin.Environment {
	table := &symbols.ISF{Bases: map[string]symbols.Type{"pointer": {Size: 8, Endian: "little"}}}
	return plugin.Environment{Symbols: table, Objects: &object.Reader{Layer: mem, Symbols: table}}
}

func TestForwardListStopsWhenNextEntryIsUnmapped(t *testing.T) {
	mem := make(flatMemory, 0x300)
	putU64(mem, 0x100, 0x200)
	putU64(mem, 0x200, 0x300)
	var got []uint64
	var stopped uint64
	err := walkVerForwardList(context.Background(), verListEnv(mem), 0x100, 0, 10, func(address uint64) error {
		got = append(got, address)
		return nil
	}, &stopped)
	if err != nil || len(got) != 1 || got[0] != 0x200 || stopped != 1 {
		t.Fatal(got, stopped, err)
	}
}

func TestForwardListStopsAtSentinelWithoutTruncation(t *testing.T) {
	mem := make(flatMemory, 0x300)
	putU64(mem, 0x100, 0x200)
	putU64(mem, 0x200, 0x100)
	var got []uint64
	var stopped uint64
	err := walkVerForwardList(context.Background(), verListEnv(mem), 0x100, 0, 10, func(address uint64) error {
		got = append(got, address)
		return nil
	}, &stopped)
	if err != nil || len(got) != 1 || got[0] != 0x200 || stopped != 0 {
		t.Fatal(got, stopped, err)
	}
}

func TestForwardListSentinelPointerMustBeReadable(t *testing.T) {
	mem := make(flatMemory, 0x101)
	var stopped uint64
	err := walkVerForwardList(context.Background(), verListEnv(mem), 0x100, 0, 10, func(uint64) error { return nil }, &stopped)
	if err == nil || stopped != 0 {
		t.Fatal(err, stopped)
	}
}
