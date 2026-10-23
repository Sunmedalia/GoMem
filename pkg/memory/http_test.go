package memory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSourceRangesTLSAndConcurrentReads(t *testing.T) {
	data := bytes.Repeat([]byte("native-memory-evidence"), 8192)
	for _, tls := range []bool{false, true} {
		t.Run(fmt.Sprint(tls), func(t *testing.T) {
			var requests atomic.Int64
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("invalid request")
				}
				if requests.Load() > 1 && r.Header.Get("If-Match") != `"v1"` {
					t.Error("missing identity precondition")
				}
				w.Header().Set("ETag", `"v1"`)
				http.ServeContent(w, r, "memory.raw", time.Time{}, bytes.NewReader(data))
			})
			var server *httptest.Server
			if tls {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			source, err := OpenHTTP(context.Background(), server.URL+"/memory?token=secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if source.Size() != uint64(len(data)) || strings.Contains(source.Name(), "secret") {
				t.Fatal(source.Name(), source.Size())
			}
			var wg sync.WaitGroup
			for i := 0; i < 12; i++ {
				wg.Go(func() {
					b := make([]byte, 4096)
					n, err := source.ReadAt(context.Background(), b, 1000)
					if n != len(b) || err != nil || !bytes.Equal(b, data[1000:5096]) {
						t.Errorf("read %d %v", n, err)
					}
				})
			}
			wg.Wait()
			b := make([]byte, 12)
			n, err := source.ReadAt(context.Background(), b, uint64(len(data)-5))
			if n != 5 || !errors.Is(err, io.EOF) || !bytes.Equal(b[:5], data[len(data)-5:]) {
				t.Fatal(n, err)
			}
			if n, err = source.ReadAt(context.Background(), b, ^uint64(0)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatal(n, err)
			}
			if _, err = source.ReadAt(context.Background(), make([]byte, MaxRead+1), 0); err == nil {
				t.Fatal("unbounded read")
			}
			if err = source.Validate(context.Background()); err != nil {
				t.Fatal(err)
			}
			source.Close()
			if _, err = source.ReadAt(context.Background(), b, 0); err == nil {
				t.Fatal("read after close")
			}
		})
	}
}

func TestHTTPSourceRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers map[string]string
		body    string
	}{
		{"ignored-range", 200, nil, "x"},
		{"precondition", 412, nil, ""},
		{"missing-etag", 206, nil, "x"},
		{"weak-etag", 206, map[string]string{"ETag": `W/"v1"`}, "x"},
		{"bad-range", 206, map[string]string{"Content-Range": "bytes 1-1/10"}, "x"},
		{"unknown-size", 206, map[string]string{"Content-Range": "bytes 0-0/*"}, "x"},
		{"zero-size", 206, map[string]string{"Content-Range": "bytes 0-0/0"}, "x"},
		{"encoded", 206, map[string]string{"Content-Encoding": "gzip"}, "x"},
		{"short", 206, map[string]string{"Content-Length": "1"}, ""},
		{"extra", 206, map[string]string{"Content-Length": "2"}, "xx"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Range", "bytes 0-0/10")
				if test.name != "missing-etag" {
					w.Header().Set("ETag", `"v1"`)
				}
				for k, v := range test.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			source, err := OpenHTTP(context.Background(), server.URL+"/?token=do-not-log", nil)
			if err == nil {
				source.Close()
				t.Fatal("accepted invalid response")
			}
			if strings.Contains(err.Error(), "do-not-log") {
				t.Fatal("secret leaked")
			}
		})
	}
}

func TestHTTPSourceChangesAndCancellation(t *testing.T) {
	var mode atomic.Int32
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		switch mode.Load() {
		case 1:
			w.Header().Set("ETag", `"v2"`)
		case 2:
			w.Header().Set("Content-Range", "bytes 0-0/99")
			w.WriteHeader(206)
			io.WriteString(w, "x")
			return
		case 3:
			started <- struct{}{}
			<-r.Context().Done()
			return
		}
		http.ServeContent(w, r, "memory", time.Time{}, strings.NewReader("fixed bytes"))
	}))
	defer server.Close()
	source, err := OpenHTTP(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, m := range []int32{1, 2} {
		mode.Store(m)
		if err = source.Validate(context.Background()); err == nil {
			t.Fatal("accepted changed representation")
		}
	}
	mode.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- source.Validate(ctx) }()
	<-started
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	go func() { done <- source.Validate(context.Background()) }()
	<-started
	source.Close()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("close did not cancel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close blocked")
	}
}

func TestHTTPSourceOfflineAndTransportRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("offline network access") }))
	defer server.Close()
	if _, err := OpenSource(context.Background(), server.URL, true); err == nil {
		t.Fatal("offline remote accepted")
	}
	if _, err := OpenSource(context.Background(), "ftp://example.com/memory", false); err == nil {
		t.Fatal("unknown source accepted")
	}
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead.Close()
	_, err := OpenHTTP(context.Background(), strings.Replace(dead.URL, "://", "://user:private@", 1)+"/?token=secret", nil)
	if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
}

func FuzzHTTPContentRange(f *testing.F) {
	for _, s := range []string{"bytes 0-0/1", "bytes 0-4095/8192", "bytes 1-0/1", "bytes 0-0/*", "bytes 0-18446744073709551615/1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, b, total, err := parseContentRange(s)
		if err == nil && a > b {
			t.Fatalf("reversed %d %d %d", a, b, total)
		}
	})
}

func TestHTTPRedirectIdentity(t *testing.T) {
	var redirect atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "other", time.Time{}, strings.NewReader("different bytes"))
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/image", 302)
			return
		}
		if redirect.Load() {
			http.Redirect(w, r, target.URL, 302)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "image", time.Time{}, strings.NewReader("original bytes!"))
	}))
	defer origin.Close()
	source, err := OpenHTTP(context.Background(), origin.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err = source.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	redirect.Store(true)
	if err = source.Validate(context.Background()); err == nil {
		t.Fatal("ETag from different resource accepted")
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer tls.Close()
	if source, err := OpenHTTP(context.Background(), tls.URL, tls.Client()); err == nil {
		source.Close()
		t.Fatal("TLS downgrade accepted")
	}
}
