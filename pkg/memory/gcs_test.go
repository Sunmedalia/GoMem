package memory

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"golang.org/x/oauth2"
)

func TestGCSGenerationsAndConcurrentRanges(t *testing.T) {
	data := bytes.Repeat([]byte("GCS stored bytes\x00\xff"), 8192)
	server := testfixture.StartGCSServer(t, "")
	key := "folder//a +%#?.raw"
	server.Put("test-bucket", key, "123", "1", "", data)
	source, err := OpenGCS(context.Background(), "gs://test-bucket/folder//a%20+%25%23%3F.raw", GCSOptions{Endpoint: server.Endpoint(), Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if source.Size() != uint64(len(data)) || source.CloudObjectInfo().Version != "123" || source.CloudObjectInfo().Metageneration != "1" {
		t.Fatal(source.CloudObjectInfo())
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			p := make([]byte, 4096)
			n, err := source.ReadAt(context.Background(), p, 123)
			if err != nil || n != len(p) || !bytes.Equal(p, data[123:4219]) {
				t.Errorf("range %d %v", n, err)
			}
		})
	}
	wg.Wait()
	tail := make([]byte, 8)
	n, err := source.ReadAt(context.Background(), tail, uint64(len(data)-3))
	if n != 3 || !errors.Is(err, io.EOF) || !bytes.Equal(tail[:3], data[len(data)-3:]) {
		t.Fatal(n, err)
	}
	server.Put("test-bucket", key, "124", "1", "", []byte("new object"))
	if err := source.Validate(context.Background()); err != nil {
		t.Fatal("generation followed latest", err)
	}
	server.Put("test-bucket", key, "123", "2", "", data)
	if err := source.Validate(context.Background()); err == nil {
		t.Fatal("metageneration change undetected")
	}
	if _, err := source.ReadAt(context.Background(), make([]byte, 1), 0); err == nil {
		t.Fatal("read changed metadata")
	}
	if server.MissingConditions.Load() != 0 {
		t.Fatal("unconditional media read")
	}
	if _, err := source.ReadAt(context.Background(), make([]byte, MaxRead+1), 0); err == nil {
		t.Fatal("unbounded read")
	}
	source.Close()
	source.Close()
	if _, err := source.ReadAt(context.Background(), make([]byte, 1), 0); err == nil {
		t.Fatal("read after close")
	}
}
func TestGCSStoredGzipIsNotTranscoded(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Write(bytes.Repeat([]byte("forensic bytes"), 8192))
	writer.Close()
	server := testfixture.StartGCSServer(t, "")
	server.Put("test-bucket", "memory.gz", "123", "1", "gzip", compressed.Bytes())
	source, err := OpenGCS(context.Background(), "gs://test-bucket/memory.gz", GCSOptions{Endpoint: server.Endpoint(), Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, offset := range []uint64{0, 10, uint64(compressed.Len() - 8)} {
		p := make([]byte, 8)
		if _, err := source.ReadAt(context.Background(), p, offset); err != nil || !bytes.Equal(p, compressed.Bytes()[offset:offset+8]) {
			t.Fatal("gzip representation changed", err)
		}
	}
}
func TestGCSTokenRefreshAndCancellation(t *testing.T) {
	server := testfixture.StartGCSServer(t, "test-token")
	server.Put("test-bucket", "memory.raw", "123", "1", "", []byte("authenticated bytes"))
	var refresh atomic.Int64
	provider := func(ctx context.Context) (*oauth2.Token, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		refresh.Add(1)
		return &oauth2.Token{AccessToken: "test-token", Expiry: time.Now().Add(time.Hour)}, nil
	}
	source, err := OpenGCS(context.Background(), "gs://test-bucket/memory.raw", GCSOptions{Endpoint: server.Endpoint(), Token: provider})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.ReadAt(context.Background(), make([]byte, 8), 0); err != nil {
		t.Fatal(err)
	}
	if refresh.Load() != 1 || server.Authenticated.Load() != 2 {
		t.Fatal("token not cached")
	}
	// Expire the concrete cached token; refresh must use a live operation context.
	source.authLock <- struct{}{}
	source.token.Expiry = time.Now().Add(-time.Hour)
	<-source.authLock
	if err := source.Validate(context.Background()); err != nil || refresh.Load() != 2 {
		t.Fatal("refresh retained canceled opening context", err)
	}
	entered := make(chan struct{}, 1)
	stalled := func(ctx context.Context) (*oauth2.Token, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		source, err := OpenGCS(ctx, "gs://test-bucket/memory.raw", GCSOptions{Endpoint: server.Endpoint(), Token: stalled})
		if source != nil {
			source.Close()
		}
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("credential cancellation blocked")
	}
}
func TestGCSRejectsBadResponses(t *testing.T) {
	for _, mode := range []string{"bad-json", "oversized-json", "wrong-bucket", "wrong-key", "empty", "invalid-generation", "missing-tag", "unsupported-encoding", "wrong-range", "wrong-size", "wrong-generation", "wrong-metageneration", "short-body", "extra-body", "status", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("alt") != "media" {
					switch mode {
					case "bad-json":
						fmt.Fprint(w, "{")
						return
					case "oversized-json":
						fmt.Fprint(w, strings.Repeat(" ", 65537))
						return
					}
					bucket, key, size, generation, tag, encoding := "test-bucket", "memory.raw", "16", "123", "metadata-etag", ""
					switch mode {
					case "wrong-bucket":
						bucket = "other-bucket"
					case "wrong-key":
						key = "other.raw"
					case "empty":
						size = "0"
					case "invalid-generation":
						generation = "-1"
					case "missing-tag":
						tag = ""
					case "unsupported-encoding":
						encoding = "br"
					}
					fmt.Fprintf(w, `{"bucket":%q,"name":%q,"size":%q,"generation":%q,"metageneration":"1","etag":%q,"contentEncoding":%q}`, bucket, key, size, generation, tag, encoding)
					return
				}
				w.Header().Set("Content-Range", "bytes 0-3/16")
				w.Header().Set("Content-Length", "4")
				w.Header().Set("x-goog-generation", "123")
				w.Header().Set("x-goog-metageneration", "1")
				switch mode {
				case "wrong-range":
					w.Header().Set("Content-Range", "bytes 1-4/16")
				case "wrong-size":
					w.Header().Set("Content-Range", "bytes 0-3/17")
				case "wrong-generation":
					w.Header().Set("x-goog-generation", "124")
				case "wrong-metageneration":
					w.Header().Set("x-goog-metageneration", "2")
				case "extra-body":
					w.Header().Del("Content-Length")
				case "status":
					http.Error(w, "secret-response", 403)
					return
				case "redirect":
					w.Header().Set("Location", "http://invalid.example/secret")
					w.WriteHeader(307)
					return
				}
				w.WriteHeader(206)
				body := "ABCD"
				if mode == "short-body" {
					body = "A"
				}
				if mode == "extra-body" {
					body = "ABCDE"
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			source, err := OpenGCS(context.Background(), "gs://test-bucket/memory.raw", GCSOptions{Endpoint: server.URL, Anonymous: true})
			initial := map[string]bool{"bad-json": true, "oversized-json": true, "wrong-bucket": true, "wrong-key": true, "empty": true, "invalid-generation": true, "missing-tag": true, "unsupported-encoding": true}
			if initial[mode] {
				if err == nil {
					source.Close()
					t.Fatal("invalid metadata accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, err := source.ReadAt(context.Background(), make([]byte, 4), 0); err == nil {
				t.Fatal("invalid media accepted")
			}
		})
	}
}
func TestGCSReadCancellationAndClose(t *testing.T) {
	entered := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("alt") != "media" {
			fmt.Fprint(w, `{"bucket":"test-bucket","name":"memory.raw","size":"16","generation":"123","metageneration":"1","etag":"tag"}`)
			return
		}
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	source, err := OpenGCS(context.Background(), "gs://test-bucket/memory.raw", GCSOptions{Endpoint: server.URL, Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := source.ReadAt(ctx, make([]byte, 4), 0); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read cancel blocked")
	}
	go func() { _, err := source.ReadAt(context.Background(), make([]byte, 4), 0); done <- err }()
	<-entered
	source.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("close succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close blocked")
	}
}
func TestGCSURIAndOffline(t *testing.T) {
	for _, location := range []string{"gs://test-bucket/", "gs://user:secret@test-bucket/a", "gs://test-bucket/a?generation=1&generation=2", "gs://test-bucket/a?generation=0", "gs://test-bucket/a?generation=-1", "gs://test-bucket/a?generation=01", "gs://test-bucket/a?generation=9223372036854775808", "gs://test-bucket/a?token=secret", "gs://test-bucket/a#123", "gs://test-bucket/a%0d%0a", "gs://test-bucket:443/a"} {
		if _, err := parseGCSLocation(location); err == nil {
			t.Fatal("invalid GCS URI accepted")
		}
	}
	server := testfixture.StartGCSServer(t, "")
	if _, err := OpenImageSource(context.Background(), "gs://test-bucket/memory.raw", ImageSourceOptions{Offline: true, GCS: GCSOptions{Endpoint: server.Endpoint()}}); err == nil || server.Requests.Load() != 0 {
		t.Fatal("offline GCS accessed network")
	}
	for _, endpoint := range []string{"http://example.org", "https://user:secret@example.org", "https://example.org/storage/v1", "https://example.org?token=secret"} {
		if _, err := OpenGCS(context.Background(), "gs://test-bucket/a", GCSOptions{Endpoint: endpoint, Anonymous: true}); err == nil {
			t.Fatal("invalid endpoint")
		}
	}
}
func FuzzGCSURI(f *testing.F) {
	for _, location := range []string{"gs://test-bucket/a", "gs://test-bucket/a%20b?generation=123", "gs://test-bucket/a%0d%0a", "gs://test-bucket/a#123"} {
		f.Add(location)
	}
	f.Fuzz(func(t *testing.T, location string) {
		parsed, err := parseGCSLocation(location)
		if err != nil {
			return
		}
		again, err := parseGCSLocation(parsed.name)
		if err != nil || again.bucket != parsed.bucket || again.key != parsed.key {
			t.Fatal("unstable GCS identity")
		}
		if parsed.version != "" && !gcsPositiveNumber(parsed.version) {
			t.Fatal("invalid accepted generation")
		}
	})
}

func TestGCSApplicationDefaultServiceAccountRefresh(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var grants atomic.Int64
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Error("invalid JWT exchange")
			http.Error(w, "invalid", 400)
			return
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Error(err)
			return
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
			t.Error("JWT signature", err)
			http.Error(w, "invalid", 400)
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Error(err)
			return
		}
		var claims struct {
			Issuer   string `json:"iss"`
			Audience string `json:"aud"`
			Scope    string `json:"scope"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil || claims.Issuer != "gomem-test@example.invalid" || claims.Audience != issuer.URL || claims.Scope != gcsReadScope {
			t.Error("JWT claims", claims, err)
			http.Error(w, "invalid", 400)
			return
		}
		grants.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"adc-test-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer issuer.Close()
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	credentials, err := json.Marshal(map[string]string{"type": "service_account", "project_id": "gomem-test", "private_key": string(pemKey), "client_email": "gomem-test@example.invalid", "token_uri": issuer.URL})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic-credentials.json")
	if err := os.WriteFile(path, credentials, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	server := testfixture.StartGCSServer(t, "adc-test-token")
	server.Put("test-bucket", "memory.raw", "123", "1", "", []byte("ADC authenticated image"))
	source, err := OpenGCS(context.Background(), "gs://test-bucket/memory.raw", GCSOptions{Endpoint: server.Endpoint()})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.ReadAt(context.Background(), make([]byte, 4), 0); err != nil {
		t.Fatal(err)
	}
	if grants.Load() != 1 {
		t.Fatal("unnecessary credential exchange")
	}
	source.authLock <- struct{}{}
	source.token.Expiry = time.Now().Add(-time.Hour)
	<-source.authLock
	if err := source.Validate(context.Background()); err != nil || grants.Load() != 2 {
		t.Fatal("ADC refresh failed", err, grants.Load())
	}
}
func TestGCSCredentialFailuresDoNotLeakSecrets(t *testing.T) {
	server := testfixture.StartGCSServer(t, "expected-token")
	server.Put("test-bucket", "memory.raw", "123", "1", "", []byte("image"))
	for _, provider := range []func(context.Context) (*oauth2.Token, error){
		func(context.Context) (*oauth2.Token, error) { return nil, fmt.Errorf("private-token-secret") },
		func(context.Context) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "wrong-secret-token"}, nil
		},
		func(context.Context) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "injected\r\nsecret"}, nil
		},
	} {
		source, err := OpenGCS(context.Background(), "gs://test-bucket/memory.raw", GCSOptions{Endpoint: server.Endpoint(), Token: provider})
		if err == nil {
			source.Close()
			t.Fatal("invalid credentials accepted")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("secret in credential error")
		}
	}
}

func TestGCSActualPinnedCloudHandler(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	python := os.Getenv("GOMEM_CLOUD_REFERENCE_PYTHON")
	if baseline == "" || python == "" {
		t.Skip("set GOMEM_BASELINE_DIR and GOMEM_CLOUD_REFERENCE_PYTHON (gcsfs 2026.10.1) for actual locked handler")
	}
	data := bytes.Repeat([]byte("GCS actual cloud handler\x00\xff"), 8192)
	server := testfixture.StartGCSServer(t, "")
	server.Put("test-bucket", "memory.raw", "123", "1", "", data)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "../../tools/gcs_reference.py", "--source", baseline, "--endpoint", server.Endpoint(), "--url", "gs://test-bucket/memory.raw")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("reference failed: %v %s", err, output)
	}
	var reference struct {
		Baseline string `json:"baseline_commit"`
		GCSFS    string
		SHA256   string
		Size     uint64
		Reads    []struct {
			Offset uint64
			Data   []byte
		}
	}
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if reference.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || reference.GCSFS != "2026.10.1" || reference.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("baseline drift")
	}
	source, err := OpenGCS(context.Background(), "gs://test-bucket/memory.raw", GCSOptions{Endpoint: server.Endpoint(), Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if source.Size() != reference.Size {
		t.Fatal("reference size differs")
	}
	for _, read := range reference.Reads {
		actual := make([]byte, len(read.Data))
		n, err := source.ReadAt(context.Background(), actual, read.Offset)
		if err != nil || n != len(actual) || !bytes.Equal(actual, read.Data) {
			t.Fatal("reference seek/read differs", err)
		}
	}
}
