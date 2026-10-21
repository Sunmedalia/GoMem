package library

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func image(t *testing.T, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func tableData(t *testing.T, banner string) []byte {
	t.Helper()
	table := &symbols.ISF{Meta: map[string]json.RawMessage{"format": json.RawMessage(`"6.2.0"`), "linux": json.RawMessage(`{}`)}, Bases: map[string]symbols.Type{"pointer": {Kind: "int", Size: 8, Endian: "little"}}, Symbols: map[string]symbols.Symbol{"linux_banner": {Address: 0x4000, ConstantData: base64.StdEncoding.EncodeToString([]byte(banner + "\x00"))}}}
	b, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProbeUnknownLinuxWindowsAndAmbiguity(t *testing.T) {
	ctx := context.Background()
	p, err := ProbeFile(ctx, image(t, make([]byte, 100)))
	if err != nil || p.OS != "unknown" || p.Status != "unavailable" {
		t.Fatal(p, err)
	}
	// Exercise the scan chunk overlap and a banner ending in the catalog-omitted newline.
	b := make([]byte, (1<<20)+1024)
	copy(b[(1<<20)-5:], "Linux version 6.1-test (compiler) #1 SMP\n\x00")
	p, err = ProbeFile(ctx, image(t, b))
	if err != nil || p.OS != "linux" || len(p.Identities) != 1 || p.Identities[0].Physical != (1<<20)-5 {
		t.Fatal(p, err)
	}
	copy(b[0:], "RSDS")
	for i := 4; i < 20; i++ {
		b[i] = byte(i)
	}
	binary.LittleEndian.PutUint32(b[20:], 10)
	copy(b[24:], "C:\\build\\ntkrnlmp.pdb\x00")
	p, err = ProbeFile(ctx, image(t, b))
	if err != nil || p.OS != "unknown" || p.Status != "ambiguous" || len(p.Identities) != 2 {
		t.Fatal(p, err)
	}
	id := p.Identities[1].PDB
	if id.GUID != "0706050409080B0A0C0D0E0F10111213" || id.Age != 10 {
		t.Fatal(id)
	}
	b = append([]byte(nil), b[:1024]...)
	p, err = ProbeFile(ctx, image(t, b))
	if err != nil || p.OS != "windows" {
		t.Fatal(p, err)
	}
}

type brokenLayer struct{}

func (brokenLayer) Name() string           { return "broken" }
func (brokenLayer) Ranges() []memory.Range { return []memory.Range{{Start: 0, Length: 4096}} }
func (brokenLayer) ReadAt(context.Context, []byte, uint64) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
func TestProbeErrorsAndCancellation(t *testing.T) {
	if _, err := ProbeLayer(context.Background(), brokenLayer{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeFile(ctx, image(t, make([]byte, 128))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := ProbeFile(context.Background(), image(t, []byte("Linux version unterminated"))); err == nil {
		t.Fatal("truncated identity read was hidden")
	}
}

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func remoteBody(body []byte, calls *int) Remote {
	return Remote{Client: &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		*calls++
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}}
}
func TestExactCatalogPathsReleaseAssetsAndOffline(t *testing.T) {
	banner := "Linux version 6.1-test (compiler) #1 SMP"
	paths := []string{"Debian/a b/test+build.json.xz", "https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/linux/test.json.xz"}
	b, _ := json.Marshal(map[string][]string{banner: paths, "Linux version 6.1-other": {"Other/wrong.json.xz"}})
	calls := 0
	r := remoteBody(b, &calls)
	p := Probe{Identities: []Identity{{OS: "linux", Banner: banner + "\n"}}}
	matches, err := r.Lookup(context.Background(), p)
	if err != nil || len(matches) != 2 || calls != 1 {
		t.Fatal(matches, err, calls)
	}
	if !strings.Contains(matches[1].URL, "a%20b/test+build.json.xz") {
		t.Fatal(matches)
	}
	p.Identities[0].Banner = banner + " changed compiler"
	matches, err = r.Lookup(context.Background(), p)
	if err != nil || len(matches) != 0 {
		t.Fatal(matches, err)
	}
	r.Offline = true
	before := calls
	if _, err = r.Lookup(context.Background(), p); err == nil || calls != before {
		t.Fatal("offline request", err, calls)
	}
	b, _ = json.Marshal(map[string][]string{p.Identities[0].Banner: {"https://evil.invalid/table.json.xz"}})
	r = remoteBody(b, &calls)
	if _, err = r.Lookup(context.Background(), p); err == nil {
		t.Fatal("untrusted catalog URL accepted")
	}
	p = Probe{Identities: []Identity{{OS: "windows", PDB: &symbols.PDBIdentity{Database: "ntkrnlmp.pdb", GUID: strings.Repeat("A", 32), Age: 10}}}}
	matches, err = r.Lookup(context.Background(), p)
	if err != nil || len(matches) != 1 || !strings.Contains(matches[0].URL, strings.Repeat("A", 33)) {
		t.Fatal(matches, err)
	}
}

func TestDownloadValidatesIdentityBeforePublication(t *testing.T) {
	ctx := context.Background()
	l := Library{Root: t.TempDir()}
	calls := 0
	banner := "Linux version 6.1-test (compiler) #1 SMP\n"
	c := Candidate{Identity: Identity{OS: "linux", Banner: banner}, URL: "https://example.test/kernel.json", Name: "kernel.json"}
	r := remoteBody(tableData(t, "Linux version wrong"), &calls)
	if _, err := r.Download(ctx, l, c); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	files, err := l.List(Symbols)
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
	r = remoteBody(tableData(t, banner), &calls)
	path, err := r.Download(ctx, l, c)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, tableData(t, banner)) {
		t.Fatal(err)
	}
	if _, err = r.Download(ctx, l, c); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing table overwritten", err)
	}
	r.Offline = true
	before := calls
	if _, err = r.Download(ctx, l, c); err == nil || before != calls {
		t.Fatal(err, calls)
	}
}

func TestLibraryCopiesWithoutClobberAndRestrictsMutations(t *testing.T) {
	ctx := context.Background()
	l := Library{Root: t.TempDir()}
	source := image(t, []byte("original evidence"))
	path, err := l.Import(ctx, Images, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Import(ctx, Images, source); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if err = l.Rename(Images, filepath.Base(source), "renamed.raw"); err != nil {
		t.Fatal(err)
	}
	if err = l.Rename(Images, "renamed.raw", "../outside"); err == nil {
		t.Fatal("traversal rename accepted")
	}
	if err = l.Remove(Images, "../outside"); err == nil {
		t.Fatal("traversal delete accepted")
	}
	if err = os.Symlink(source, l.Path(Images, "link.raw")); err != nil {
		t.Fatal(err)
	}
	files, err := l.List(Images)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	if err = l.Remove(Images, "link.raw"); err == nil {
		t.Fatal("symlink deletion accepted")
	}
	if err = l.Remove(Images, "renamed.raw"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(source)
	if err != nil || string(b) != "original evidence" {
		t.Fatal("source changed", err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = l.Import(ctx, Images, source); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	files, err = l.List(Images)
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
}
