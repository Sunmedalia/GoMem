package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func testS3Options(server *testfixture.S3Server) S3Options {
	return S3Options{Region: "us-east-1", Endpoint: server.Endpoint(), PathStyle: true, Anonymous: true}
}
func TestS3VersionedAndConditionalWireReads(t *testing.T) {
	data := bytes.Repeat([]byte("native-s3-object\x00\xff"), 8192)
	for _, version := range []string{"", "null", "version/one+=="} {
		t.Run(version, func(t *testing.T) {
			server := testfixture.StartS3Server(t, "", "")
			server.Put("test-bucket", "folder/a +%#?.raw", version, data)
			source, err := OpenS3(context.Background(), server.URL("test-bucket", "folder/a +%#?.raw"), testS3Options(server))
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if source.Size() != uint64(len(data)) || source.CloudObjectInfo().Version != version {
				t.Fatal(source.CloudObjectInfo())
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Go(func() {
					p := make([]byte, 4096)
					n, err := source.ReadAt(context.Background(), p, 123)
					if err != nil || n != len(p) || !bytes.Equal(p, data[123:4219]) {
						t.Errorf("range read %d %v", n, err)
					}
				})
			}
			wg.Wait()
			tail := make([]byte, 10)
			n, err := source.ReadAt(context.Background(), tail, uint64(len(data)-3))
			if n != 3 || !errors.Is(err, io.EOF) || !bytes.Equal(tail[:3], data[len(data)-3:]) {
				t.Fatal(n, err)
			}
			if err := source.Validate(context.Background()); err != nil {
				t.Fatal(err)
			}
			server.Put("test-bucket", "folder/a +%#?.raw", func() string {
				if version == "" || version == "null" {
					return version
				}
				return "version-two"
			}(), []byte("replacement"))
			err = source.Validate(context.Background())
			if version == "" || version == "null" {
				if err == nil {
					t.Fatal("mutable object change undetected")
				}
			} else {
				if err != nil {
					t.Fatal("version pin followed latest", err)
				}
			}
			if server.MissingPrecondition.Load() != 0 {
				t.Fatal("unconditional object read")
			}
			if _, err := source.ReadAt(context.Background(), make([]byte, MaxRead+1), 0); err == nil {
				t.Fatal("unbounded read")
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			source.Close()
			if _, err := source.ReadAt(context.Background(), make([]byte, 1), 0); err == nil {
				t.Fatal("read after close")
			}
		})
	}
}
func TestS3AWSCredentialsAndSignedRequests(t *testing.T) {
	server := testfixture.StartS3Server(t, "test-access-key", "test-secret-key")
	server.Put("test-bucket", "memory.raw", "v1", []byte("signed object data"))
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test-access-key", "test-secret-key", "test-session-token"), BaseEndpoint: aws.String(server.Endpoint()), UsePathStyle: true, RetryMaxAttempts: 1})
	source, err := OpenS3(context.Background(), "s3://test-bucket/memory.raw", S3Options{Client: client})
	if err != nil {
		t.Fatal(err, server.Stats())
	}
	defer source.Close()
	if _, err := source.ReadAt(context.Background(), make([]byte, 6), 0); err != nil {
		t.Fatal(err, server.Stats())
	}
	if err := source.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if server.Signed.Load() != 3 {
		t.Fatal("unsigned requests", server.Stats())
	}
	// The default SDK chain should resolve environment credentials without a custom client.
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_SESSION_TOKEN", "test-session-token")
	opts := testS3Options(server)
	opts.Anonymous = false
	envSource, err := OpenS3(context.Background(), "s3://test-bucket/memory.raw", opts)
	if err != nil {
		t.Fatal(err)
	}
	envSource.Close()
	if server.Signed.Load() != 4 {
		t.Fatal("environment credentials not used")
	}
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wrong-secret")
	failed, err := OpenS3(context.Background(), "s3://test-bucket/memory.raw", opts)
	if err == nil {
		failed.Close()
		t.Fatal("bad signature accepted")
	}
	for _, secret := range []string{"test-access-key", "wrong-secret", "test-session-token", "secret-marker"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("credential leaked")
		}
	}
}
func TestS3ExplicitVersionAndURIControls(t *testing.T) {
	server := testfixture.StartS3Server(t, "", "")
	server.Put("test-bucket", "memory.raw", "first+version/==", []byte("first"))
	server.Put("test-bucket", "memory.raw", "second", []byte("second"))
	source, err := OpenS3(context.Background(), "s3://test-bucket/memory.raw?versionId=first%2Bversion%2F%3D%3D", testS3Options(server))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	p := make([]byte, 5)
	if _, err := source.ReadAt(context.Background(), p, 0); err != nil || string(p) != "first" {
		t.Fatal(string(p), err)
	}
	if strings.Contains(source.Name(), "versionId") {
		t.Fatal("query persisted in source name")
	}
	for _, location := range []string{"s3://test-bucket/", "s3://user:secret@test-bucket/a", "s3://test-bucket:443/a", "s3://test-bucket/a?token=secret", "s3://test-bucket/a?versionId=x&versionId=y", "s3://test-bucket/a?versionId=", "s3://test-bucket/a#x", "s3://test-bucket/a%0a", "s3://UPPER-BUCKET/a"} {
		if _, err := parseS3Location(location); err == nil {
			t.Fatal("invalid S3 URI", location)
		}
	}
	before := server.Requests.Load()
	if _, err := OpenImageSource(context.Background(), "s3://test-bucket/memory.raw", ImageSourceOptions{Offline: true, S3: testS3Options(server)}); err == nil || server.Requests.Load() != before {
		t.Fatal("offline cloud request")
	}
}
func TestS3RejectsInconsistentWireResponses(t *testing.T) {
	for _, mode := range []string{"missing-tag", "weak-tag", "empty", "changed-tag", "changed-version", "changed-size", "no-range", "wrong-range", "wrong-length", "short-body", "extra-body", "delete-marker", "status", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				w.Header().Set("x-amz-version-id", "one")
				if r.Method == http.MethodHead {
					if mode == "missing-tag" {
						w.Header().Del("ETag")
					}
					if mode == "weak-tag" {
						w.Header().Set("ETag", `W/"v1"`)
					}
					size := "16"
					if mode == "empty" {
						size = "0"
					}
					w.Header().Set("Content-Length", size)
					return
				}
				w.Header().Set("Content-Range", "bytes 0-3/16")
				w.Header().Set("Content-Length", "4")
				switch mode {
				case "changed-tag":
					w.Header().Set("ETag", `"v2"`)
				case "changed-version":
					w.Header().Set("x-amz-version-id", "two")
				case "changed-size":
					w.Header().Set("Content-Range", "bytes 0-3/17")
				case "no-range":
					w.Header().Del("Content-Range")
				case "wrong-range":
					w.Header().Set("Content-Range", "bytes 1-4/16")
				case "wrong-length":
					w.Header().Set("Content-Length", "5")
				case "extra-body":
					w.Header().Del("Content-Length")
				case "delete-marker":
					w.Header().Set("x-amz-delete-marker", "true")
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
			opts := S3Options{Region: "us-east-1", Endpoint: server.URL, PathStyle: true, Anonymous: true}
			source, err := OpenS3(context.Background(), "s3://test-bucket/memory.raw", opts)
			if mode == "missing-tag" || mode == "weak-tag" || mode == "empty" {
				if err == nil {
					source.Close()
					t.Fatal("invalid head accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, err := source.ReadAt(context.Background(), make([]byte, 4), 0); err == nil {
				t.Fatal("invalid object response accepted")
			}
		})
	}
}
func TestS3CancellationAndClose(t *testing.T) {
	started := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", "8")
		if r.Method == http.MethodHead {
			return
		}
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	source, err := OpenS3(context.Background(), "s3://test-bucket/memory.raw", S3Options{Region: "us-east-1", Endpoint: server.URL, PathStyle: true, Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := source.ReadAt(ctx, make([]byte, 4), 0); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel blocked")
	}
	go func() { _, err := source.ReadAt(context.Background(), make([]byte, 4), 0); done <- err }()
	<-started
	source.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed request succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close blocked")
	}
}
func FuzzS3URI(f *testing.F) {
	for _, seed := range []string{"s3://test-bucket/memory.raw", "s3://bucket/a%20b?versionId=abc%2B123", "s3://user:pass@bucket/a", "s3://bucket/a%0d%0a"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, location string) {
		parsed, err := parseS3Location(location)
		if err != nil {
			return
		}
		if parsed.bucket == "" || parsed.key == "" || strings.ContainsAny(parsed.key+parsed.version, "\r\n\x00") {
			t.Fatal("unsafe accepted URI")
		}
		again, err := parseS3Location(parsed.name)
		if err != nil || again.bucket != parsed.bucket || again.key != parsed.key {
			t.Fatal("unstable source identity")
		}
	})
}

func TestS3ActualPinnedCloudHandler(t *testing.T) {
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	python := os.Getenv("GOMEM_CLOUD_REFERENCE_PYTHON")
	if baseline == "" || python == "" {
		t.Skip("set GOMEM_BASELINE_DIR and GOMEM_CLOUD_REFERENCE_PYTHON (s3fs 2026.9.0) for actual locked handler")
	}
	data := bytes.Repeat([]byte("S3 actual cloud handler\x00\xff"), 8192)
	server := testfixture.StartS3Server(t, "", "")
	server.Put("test-bucket", "memory.raw", "v1", data)
	command := exec.Command(python, "../../tools/s3_reference.py", "--source", baseline, "--endpoint", server.Endpoint(), "--url", "s3://test-bucket/memory.raw")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("reference failed: %v %s", err, output)
	}
	var reference struct {
		Baseline string `json:"baseline_commit"`
		S3FS     string
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
	if reference.Baseline != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || reference.S3FS != "2026.9.0" || reference.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("baseline drift")
	}
	source, err := OpenS3(context.Background(), "s3://test-bucket/memory.raw", testS3Options(server))
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

func TestS3EndpointAndHeadCancellation(t *testing.T) {
	for _, endpoint := range []string{"http://example.org", "https://user:secret@example.org", "https://example.org?token=secret", "https://example.org/#fragment", "file:///tmp/object", "http://localhost"} {
		if _, err := newS3Client(context.Background(), S3Options{Endpoint: endpoint, Anonymous: true, Region: "us-east-1"}); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		source, err := OpenS3(ctx, "s3://test-bucket/memory.raw", S3Options{Endpoint: server.URL, Region: "us-east-1", Anonymous: true, PathStyle: true})
		if source != nil {
			source.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("head request not observed")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("head cancellation blocked")
	}
}

func TestS3SignedEscapedObjectCoordinates(t *testing.T) {
	server := testfixture.StartS3Server(t, "test-access", "test-secret")
	key := "folder//a +%#?.raw"
	version := "version/one+=="
	data := []byte("escaped signed bytes")
	server.Put("test-bucket", key, version, data)
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""), BaseEndpoint: aws.String(server.Endpoint()), UsePathStyle: true, RetryMaxAttempts: 1})
	location := server.URL("test-bucket", key) + "?versionId=version%2Fone%2B%3D%3D"
	source, err := OpenS3(context.Background(), location, S3Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	actual := make([]byte, len(data))
	if _, err := source.ReadAt(context.Background(), actual, 0); err != nil || !bytes.Equal(actual, data) {
		t.Fatal(err)
	}
	if server.Signed.Load() != 2 {
		t.Fatal("escaped coordinates not signed correctly")
	}
}
