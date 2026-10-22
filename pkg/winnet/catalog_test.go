package winnet

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
)

const catalogTestName = "netscan-win10-19041-x64"

func TestCatalogRejectsUnknownCorruptOversizedAndFailedDownloads(t *testing.T) {
	for _, mode := range []string{"unknown", "digest", "http", "oversized", "offline", "cache-size", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "http" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if mode == "oversized" {
					_, _ = w.Write([]byte(strings.Repeat("x", catalogMaxBytes+1)))
					return
				}
				_, _ = w.Write([]byte("untrusted bytes"))
			}))
			defer server.Close()
			dir, name := t.TempDir(), catalogTestName
			if mode == "unknown" {
				name = "../untrusted"
			}
			if mode == "cache-size" {
				file, err := os.Create(filepath.Join(dir, name+"-"+catalogPins[name].sha256+".json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(catalogMaxBytes + 1); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			_, err := load(ctx, dir, name, mode == "offline" || mode == "cache-size", server.URL+"/", server.Client())
			if err == nil {
				t.Fatal("invalid layout accepted", mode)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancel lost", err)
			}
			if (mode == "offline" || mode == "cache-size" || mode == "cancel" || mode == "unknown") && calls.Load() != 0 {
				t.Fatal("unexpected network access", calls.Load())
			}
		})
	}
}

func TestCatalogCancelsActiveDownload(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	dir := t.TempDir()
	go func() { _, err := load(ctx, dir, catalogTestName, false, server.URL+"/", server.Client()); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancel lost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("download did not cancel")
	}
}

func TestCatalogActualPinnedDownloadOfflineRepairAndConcurrency(t *testing.T) {
	root := os.Getenv("GOMEM_BASELINE_DIR")
	if root == "" {
		t.Skip("requires pinned layout source; CI supplies GOMEM_BASELINE_DIR")
	}
	data, err := os.ReadFile(filepath.Join(root, "volatility3/framework/symbols/windows/netscan", catalogTestName+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/"+catalogTestName+".json" {
			t.Error("unexpected source path", r.URL.Path)
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	dir := t.TempDir()
	first, err := load(context.Background(), dir, catalogTestName, false, server.URL+"/", server.Client())
	if err != nil || first.FromCache || first.Layout.Digest() != catalogPins[catalogTestName].sha256 {
		t.Fatal("pinned download failed", first, err)
	}
	second, err := load(context.Background(), dir, catalogTestName, true, server.URL+"/", server.Client())
	if err != nil || !second.FromCache || string(second.Data) != string(data) || calls.Load() != 1 {
		t.Fatal("offline replay differs", err, calls.Load())
	}
	if err := os.WriteFile(first.CachePath, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(context.Background(), dir, catalogTestName, true, server.URL+"/", server.Client()); err == nil {
		t.Fatal("offline corrupt cache accepted")
	}
	if _, err := load(context.Background(), dir, catalogTestName, false, server.URL+"/", server.Client()); err != nil {
		t.Fatal("cache repair failed", err)
	}
	cold := t.TempDir()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := load(context.Background(), cold, catalogTestName, false, server.URL+"/", server.Client())
			if err != nil || value.SHA256 != catalogPins[catalogTestName].sha256 {
				t.Error("concurrent resolution", err)
			}
		}()
	}
	wg.Wait()
	if _, err := load(context.Background(), cold, catalogTestName, true, server.URL+"/", server.Client()); err != nil {
		t.Fatal("concurrent cache not reusable", err)
	}
}

func TestCatalogOfficialPinnedServer(t *testing.T) {
	if os.Getenv("GOMEM_NETWORK_FETCH") != "1" {
		t.Skip("optional live HTTP control")
	}
	dir := t.TempDir()
	first, err := Load(context.Background(), dir, catalogTestName, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.FromCache || first.SHA256 != catalogPins[catalogTestName].sha256 {
		t.Fatal("wrong public source")
	}
	second, err := Load(context.Background(), dir, catalogTestName, true)
	if err != nil || !second.FromCache {
		t.Fatal("live source not reusable offline", err)
	}
}
