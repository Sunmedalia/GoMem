package wincallbacks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func catalogKernel(t testing.TB, width int) *symbols.ISF {
	t.Helper()
	for _, c := range controls(t) {
		if c.Width == width {
			k, err := symbols.Parse(c.Kernel)
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
	}
	t.Fatal("kernel control absent")
	return nil
}

func TestCatalogFailuresAndOffline(t *testing.T) {
	for _, mode := range []string{"width", "nil-kernel", "digest", "http", "oversized", "offline", "cache-size", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "http" {
					w.WriteHeader(404)
					return
				}
				if mode == "oversized" {
					_, _ = w.Write([]byte(strings.Repeat("x", catalogMaxBytes+1)))
					return
				}
				_, _ = w.Write([]byte("corrupt callback layout"))
			}))
			defer server.Close()
			kernel := catalogKernel(t, 8)
			if mode == "width" {
				p := kernel.Bases["pointer"]
				p.Size = 16
				kernel.Bases["pointer"] = p
			}
			if mode == "nil-kernel" {
				kernel = nil
			}
			dir := t.TempDir()
			if mode == "cache-size" {
				p := filepath.Join(dir, "callbacks-x64-"+catalogPins["callbacks-x64"].sha256+".json")
				f, err := os.Create(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(catalogMaxBytes + 1); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			_, err := load(ctx, dir, kernel, mode == "offline" || mode == "cache-size", server.URL+"/", server.Client())
			if err == nil {
				t.Fatal("invalid callback catalog accepted")
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if (mode == "width" || mode == "nil-kernel" || mode == "offline" || mode == "cache-size" || mode == "cancel") && calls.Load() != 0 {
				t.Fatal("unexpected download")
			}
		})
	}
}

func TestCatalogActualPinnedAcquisition(t *testing.T) {
	root := os.Getenv("GOMEM_BASELINE_DIR")
	if root == "" {
		t.Skip("set GOMEM_BASELINE_DIR for actual pinned callback source controls")
	}
	for _, width := range []int{4, 8} {
		name := "callbacks-x86"
		if width == 8 {
			name = "callbacks-x64"
		}
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, "volatility3/framework/symbols/windows", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			kernel := catalogKernel(t, width)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/"+name+".json" {
					t.Error(r.URL.Path)
				}
				_, _ = w.Write(data)
			}))
			defer server.Close()
			dir := t.TempDir()
			first, err := load(context.Background(), dir, kernel, false, server.URL+"/", server.Client())
			if err != nil || first.FromCache || first.SHA256 != catalogPins[name].sha256 {
				t.Fatal("download", err)
			}
			cached, err := load(context.Background(), dir, kernel, true, server.URL+"/", server.Client())
			if err != nil || !cached.FromCache || calls.Load() != 1 {
				t.Fatal("offline cache", err, calls.Load())
			}
			if err := os.WriteFile(first.CachePath, []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := load(context.Background(), dir, kernel, true, server.URL+"/", server.Client()); err == nil {
				t.Fatal("corrupt cache accepted")
			}
			if _, err := load(context.Background(), dir, kernel, false, server.URL+"/", server.Client()); err != nil {
				t.Fatal("cache repair", err)
			}
			cold := t.TempDir()
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					v, err := load(context.Background(), cold, kernel, false, server.URL+"/", server.Client())
					if err != nil {
						t.Error(err)
						return
					}
					if v.SHA256 != catalogPins[name].sha256 {
						t.Error("concurrent layout drift")
					}
				}()
			}
			wg.Wait()
			if _, err := load(context.Background(), cold, kernel, true, server.URL+"/", server.Client()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCatalogActiveCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	dir := t.TempDir()
	kernel := catalogKernel(t, 8)
	go func() { _, err := load(ctx, dir, kernel, false, server.URL+"/", server.Client()); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("download not started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("download not cancelled")
	}
}

func TestCatalogOfficialPinnedServer(t *testing.T) {
	if os.Getenv("GOMEM_NETWORK_FETCH") != "1" {
		t.Skip("optional live HTTP control")
	}
	for _, width := range []int{4, 8} {
		dir := t.TempDir()
		kernel := catalogKernel(t, width)
		first, err := Load(context.Background(), dir, kernel, false)
		if err != nil {
			t.Fatal(err)
		}
		cached, err := Load(context.Background(), dir, kernel, true)
		if err != nil || !cached.FromCache || first.SHA256 != cached.SHA256 {
			t.Fatal("live source/offline replay", err)
		}
	}
}
