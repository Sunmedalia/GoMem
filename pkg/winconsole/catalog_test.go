package winconsole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/object"
)

func TestConsoleCatalogRejectsInvalidAcquisition(t *testing.T) {
	for _, mode := range []string{"unknown", "path", "offline", "digest", "http", "oversized", "cache-size", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch mode {
				case "http":
					w.WriteHeader(404)
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat("x", catalogMaxBytes+1)))
				default:
					_, _ = w.Write([]byte("invalid console symbols"))
				}
			}))
			defer server.Close()
			name := "consoles-win10-19041-x64"
			if mode == "unknown" {
				name = "unrecognized"
			}
			if mode == "path" {
				name = "../consoles-win10-19041-x64"
			}
			dir := t.TempDir()
			if mode == "cache-size" {
				p := filepath.Join(dir, name+"-"+catalogPins[name].sha256+".json")
				file, err := os.Create(p)
				if err != nil {
					t.Fatal(err)
				}
				if err = file.Truncate(catalogMaxBytes + 1); err != nil {
					t.Fatal(err)
				}
				file.Close()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			_, err := load(ctx, dir, name, mode == "offline" || mode == "cache-size", server.URL+"/", server.Client())
			if err == nil {
				t.Fatal("invalid acquisition succeeded")
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if (mode == "cancel" || mode == "unknown" || mode == "path" || mode == "offline" || mode == "cache-size") && calls.Load() != 0 {
				t.Fatal("unexpected network access")
			}
		})
	}
}
func TestConsoleCatalogOriginalPinnedLayouts(t *testing.T) {
	fixtureRaw, err := os.ReadFile("testdata/version-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Catalog map[string]string }
	if err = json.Unmarshal(fixtureRaw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Catalog) != len(catalogPins) {
		t.Fatal("catalog fixture drift")
	}
	root := os.Getenv("GOMEM_BASELINE_DIR")
	for name, pin := range catalogPins {
		t.Run(name, func(t *testing.T) {
			raw := []byte(fixture.Catalog[name])
			if root != "" {
				source, err := os.ReadFile(filepath.Join(root, "volatility3/framework/symbols/windows/consoles", name+".json"))
				if err != nil {
					t.Fatal(err)
				}
				if string(source) != string(raw) {
					t.Fatal("original source bytes differ from fixture")
				}
			}
			hash := sha256.Sum256(raw)
			if hex.EncodeToString(hash[:]) != pin.sha256 {
				t.Fatal("source pin drift")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/"+name+".json" {
					t.Error("wrong layout URL", r.URL.Path)
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			dir := t.TempDir()
			ctx := context.Background()
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					got, err := load(ctx, dir, name, false, server.URL+"/", server.Client())
					if err != nil {
						t.Error(err)
						return
					}
					if got.Name != name || got.SHA256 != pin.sha256 || string(got.Data) != string(raw) || got.Layout.PointerSize() != 8 {
						t.Error("layout provenance mismatch")
					}
				})
			}
			wg.Wait()
			got, err := load(ctx, dir, name, true, "http://127.0.0.1:1/", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if !got.FromCache {
				t.Fatal("offline cache not reused")
			}
			if _, err = got.Layout.Type("_SCREEN_INFORMATION"); err == nil {
				t.Fatal("screen type exposed by history adapter")
			}
			if err = os.WriteFile(got.CachePath, []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = load(ctx, dir, name, true, server.URL+"/", server.Client()); err == nil {
				t.Fatal("corrupted offline entry accepted")
			}
			if _, err = load(ctx, dir, name, false, server.URL+"/", server.Client()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func FuzzConsoleHistoryLayout(f *testing.F) {
	o := fixture(f)
	f.Add([]byte(o.Layouts[o.Cases[0].Layout].ISF))
	f.Add([]byte(`{"user_types":{}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		table, err := ParseHistoryLayout(raw)
		if err != nil {
			return
		}
		r := Reader{Objects: &object.Reader{Symbols: table, Layer: original{data: make([]byte, 4096)}}}
		_, _, _ = r.Text(context.Background(), 0)
		_, _ = r.CommandCount(context.Background(), 0)
		_ = r.WalkBucket(context.Background(), History{Begin: 0, Capacity: 4096, Maximum: 1}, nil, 32, func(uint64, Command) error { return nil })
	})
}
