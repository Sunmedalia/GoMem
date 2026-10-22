package wingui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestGUICatalogRejectsInvalidAcquisition(t *testing.T) {
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
					_, _ = w.Write([]byte("invalid GUI symbols"))
				}
			}))
			defer server.Close()
			name := "gui-win10-19041-x64"
			if mode == "unknown" {
				name = "unrecognized"
			}
			if mode == "path" {
				name = "../gui-win10-19041-x64"
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
func TestGUICatalogOriginalPinnedLayouts(t *testing.T) {
	fixture := guiVersions(t)
	if len(fixture.Catalog) != len(catalogPins) {
		t.Fatal("catalog fixture drift")
	}
	root := os.Getenv("GOMEM_BASELINE_DIR")
	for name, pin := range catalogPins {
		t.Run(name, func(t *testing.T) {
			raw := guiSource(t, name)
			if root != "" {
				source, err := os.ReadFile(filepath.Join(root, "volatility3/framework/symbols/windows/gui", name+".json"))
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
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
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
					if got.Name != name || got.SHA256 != pin.sha256 || string(got.Data) != string(raw) || got.Layout.Types.PointerSize() != 8 {
						t.Error("layout provenance mismatch")
					}
				})
			}
			wg.Wait()
			if requests.Load() != 1 {
				t.Fatal("concurrent layout downloads not coalesced", requests.Load())
			}
			got, err := load(ctx, dir, name, true, "http://127.0.0.1:1/", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if !got.FromCache {
				t.Fatal("offline cache not reused")
			}
			if _, err = got.Layout.Types.Type("tagWND"); err == nil {
				t.Fatal("unselected window type exposed by GUI projection")
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

func TestGUICatalogLockCancellationAndCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "layout.json")
	release, err := acquireCatalog(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = acquireCatalog(ctx, path); !errors.Is(err, context.Canceled) {
		release()
		t.Fatal(err)
	}
	release()
	catalogLocks.Lock()
	remaining := len(catalogLocks.entries)
	catalogLocks.Unlock()
	if remaining != 0 {
		t.Fatal("inactive catalog lock retained", remaining)
	}
	release, err = acquireCatalog(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
