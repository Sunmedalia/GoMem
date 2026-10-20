package symbols_test

import (
	"context"
	"errors"
	"io"
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

func cacheFixture(t *testing.T) ([]byte, symbols.PDBIdentity) {
	t.Helper()
	path := "testdata/native-x64.pdb"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	table, _, err := symbols.ConvertPDB(context.Background(), path, symbols.PDBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := table.PDBIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return data, id
}
func TestPDBDownloadVerifiedCacheOfflineAndBuildInvalidation(t *testing.T) {
	data, id := cacheFixture(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.ContentLength > 0 || r.URL.RawQuery != "" || !strings.HasSuffix(r.URL.Path, "/"+id.GUID+"1/"+id.Database) {
			t.Error("unexpected request", r.Method, r.URL, r.ContentLength)
		}
		if body, err := io.ReadAll(r.Body); err != nil || len(body) != 0 {
			t.Error("image data must never be sent")
		}
		w.Write(data)
	}))
	defer server.Close()
	opts := symbols.PDBCacheOptions{Directory: t.TempDir(), BuildSHA256: strings.Repeat("a", 64), Server: server.URL, Client: server.Client()}
	table, result, err := symbols.ResolvePDB(context.Background(), id, opts)
	if err != nil || !result.Downloaded || !result.Converted || table.Digest() != result.SymbolsSHA256 || requests.Load() != 1 {
		t.Fatal(result, err)
	}
	opts.Offline = true
	again, reused, err := symbols.ResolvePDB(context.Background(), id, opts)
	if err != nil || again.Digest() != table.Digest() || reused.Downloaded || reused.Converted || requests.Load() != 1 {
		t.Fatal(reused, err)
	}
	upper := id
	upper.Database = strings.ToUpper(id.Database)
	if _, mixed, err := symbols.ResolvePDB(context.Background(), upper, opts); err != nil || mixed.SourcePath != result.SourcePath {
		t.Fatal("case-insensitive PDB identity did not share its source file", mixed, err)
	}
	// A new executable must re-run the native converter, while reusing the raw
	// source without a network request even in offline mode.
	opts.BuildSHA256 = strings.Repeat("b", 64)
	opts.Server = "https://different-server.invalid/symbols"
	_, rebuilt, err := symbols.ResolvePDB(context.Background(), id, opts)
	if err != nil || !rebuilt.Converted || rebuilt.Downloaded || requests.Load() != 1 || rebuilt.TablePath == result.TablePath {
		t.Fatal(rebuilt, err)
	}
	if rebuilt.URL != result.URL || !strings.HasPrefix(rebuilt.URL, server.URL) {
		t.Fatal("offline conversion must preserve the actual source URL", rebuilt.URL, result.URL)
	}
	// The conversion survives interruption after the table was published and
	// before its manifest was published. Existing matching data is reused.
	if err = os.Remove(rebuilt.ManifestPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err = symbols.ResolvePDB(context.Background(), id, opts); err != nil {
		t.Fatal("interrupted publication did not recover", err)
	}
	if err = os.WriteFile(rebuilt.TablePath, []byte("corrupt ISF"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = symbols.ResolvePDB(context.Background(), id, opts); err == nil {
		t.Fatal("corrupt conversion cache reused")
	}
	opts.BuildSHA256 = strings.Repeat("a", 64)
	source, err := os.ReadFile(result.SourcePath)
	if err != nil {
		t.Fatal(err)
	}
	source[len(source)-1] ^= 1
	if err = os.WriteFile(result.SourcePath, source, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = symbols.ResolvePDB(context.Background(), id, opts); err == nil || !strings.Contains(err.Error(), "hash changed") {
		t.Fatal("corrupt raw source reused", err)
	}
}

func TestPDBCacheConcurrentAcquisition(t *testing.T) {
	data, id := cacheFixture(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write(data) }))
	defer server.Close()
	opts := symbols.PDBCacheOptions{Directory: t.TempDir(), BuildSHA256: strings.Repeat("a", 64), Server: server.URL, Client: server.Client()}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			if _, _, err := symbols.ResolvePDB(context.Background(), id, opts); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if requests.Load() != 1 {
		t.Fatal("concurrent callers downloaded more than once", requests.Load())
	}
}

func TestPDBCacheRejectsWrongIdentityOversizeNetworkAndCancellation(t *testing.T) {
	data, id := cacheFixture(t)
	for _, scenario := range []string{"offline", "wrong-identity", "oversize", "http-error", "cancel", "unsafe-server", "unsafe-name"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if scenario == "http-error" {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				w.Write(data)
			}))
			defer server.Close()
			opts := symbols.PDBCacheOptions{Directory: t.TempDir(), BuildSHA256: strings.Repeat("a", 64), Server: server.URL, Client: server.Client()}
			ctx := context.Background()
			wanted := id
			switch scenario {
			case "offline":
				opts.Offline = true
			case "wrong-identity":
				wanted.Age++
			case "oversize":
				opts.MaxDownload = 10
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "unsafe-server":
				opts.Server = "http://example.com"
			case "unsafe-name":
				wanted.Database = "..\\image.raw"
			}
			_, _, err := symbols.ResolvePDB(ctx, wanted, opts)
			if err == nil {
				t.Fatal("invalid fetch/cache operation succeeded")
			}
			if scenario == "offline" && !errors.Is(err, symbols.ErrOfflineSymbols) {
				t.Fatal(err)
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if (scenario == "offline" || scenario == "cancel" || scenario == "unsafe-server" || scenario == "unsafe-name") && requests.Load() != 0 {
				t.Fatal("unexpected network request")
			}
			if err = filepath.Walk(opts.Directory, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if info != nil && !info.IsDir() && strings.HasPrefix(info.Name(), "download-") {
					t.Error("partial download leaked", path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPDBDownloadRejectsHTTPSDowngradeAndCancelsInFlight(t *testing.T) {
	_, id := cacheFixture(t)
	var insecureRequests atomic.Int32
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { insecureRequests.Add(1) }))
	defer insecure.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, insecure.URL, http.StatusFound) }))
	_, _, err := symbols.ResolvePDB(context.Background(), id, symbols.PDBCacheOptions{Directory: t.TempDir(), BuildSHA256: strings.Repeat("a", 64), Server: redirect.URL, Client: redirect.Client()})
	redirect.Close()
	if err == nil || insecureRequests.Load() != 0 {
		t.Fatal("redirect downgraded to HTTP", err, insecureRequests.Load())
	}
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	opts := symbols.PDBCacheOptions{Directory: t.TempDir(), BuildSHA256: strings.Repeat("a", 64), Server: server.URL, Client: server.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := symbols.ResolvePDB(ctx, id, opts); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not begin")
	}
	// A waiting caller can cancel its file-lock acquisition independently.
	waiting, cancelWait := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelWait()
	if _, _, err := symbols.ResolvePDB(waiting, id, opts); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cache lock ignored cancellation", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP download ignored cancellation")
	}
}
