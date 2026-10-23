package testfixture

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type S3Server struct {
	paths               map[string]string
	tags                map[string]string
	Server              *httptest.Server
	mu                  sync.Mutex
	objects             map[string]map[string][]byte
	latest              map[string]string
	AccessKey, Secret   string
	Requests            atomic.Int64
	Signed              atomic.Int64
	MissingPrecondition atomic.Int64
}

func StartS3Server(t testing.TB, access, secret string) *S3Server {
	t.Helper()
	s := &S3Server{paths: map[string]string{}, tags: map[string]string{}, objects: map[string]map[string][]byte{}, latest: map[string]string{}, AccessKey: access, Secret: secret}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Server.Close)
	return s
}
func (s *S3Server) Endpoint() string { return s.Server.URL }
func (s *S3Server) Put(bucket, key, version string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := "/" + bucket + "/" + key
	if s.objects[name] == nil {
		s.objects[name] = map[string][]byte{}
	}
	s.objects[name][version] = bytes.Clone(data)
	s.latest[name] = version
}
func (s *S3Server) serve(w http.ResponseWriter, r *http.Request) {
	s.Requests.Add(1)
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		http.Error(w, "read-only", 405)
		return
	}
	if s.AccessKey != "" {
		if !s.signatureValid(r) {
			http.Error(w, "<Error><Code>SignatureDoesNotMatch</Code><Message>secret-marker</Message></Error>", 403)
			return
		}
		s.Signed.Add(1)
	}
	s.mu.Lock()
	version := r.URL.Query().Get("versionId")
	if version == "" {
		version = s.latest[r.URL.Path]
	}
	data, exists := s.objects[r.URL.Path][version]
	diskPath := s.paths[r.URL.Path+"\x00"+version]
	diskTag := s.tags[r.URL.Path+"\x00"+version]
	s.mu.Unlock()
	if !exists {
		http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", 404)
		return
	}
	sum := sha256.Sum256(data)
	tag := `"` + hex.EncodeToString(sum[:]) + `"`
	if diskPath != "" {
		tag = diskTag
	}
	if match := r.Header.Get("If-Match"); match != "" && match != tag {
		http.Error(w, "<Error><Code>PreconditionFailed</Code></Error>", 412)
		return
	}
	if r.Method == http.MethodGet && r.Header.Get("If-Match") == "" {
		s.MissingPrecondition.Add(1)
	}
	w.Header().Set("ETag", tag)
	if version != "" {
		w.Header().Set("x-amz-version-id", version)
	}
	if diskPath != "" {
		file, err := os.Open(diskPath)
		if err != nil {
			http.Error(w, "unavailable", 500)
			return
		}
		defer file.Close()
		http.ServeContent(w, r, "object", time.Time{}, file)
		return
	}
	http.ServeContent(w, r, "object", time.Time{}, bytes.NewReader(data))
}
func s3HMAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

// Independent SigV4 calculation over the received wire request. No SDK signing
// implementation is used here; the test server never receives the client config.
func (s *S3Server) signatureValid(r *http.Request) bool {
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ")
	fields := map[string]string{}
	for _, field := range strings.Split(auth, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return false
		}
		fields[key] = value
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[0] != s.AccessKey || scope[3] != "s3" || scope[4] != "aws4_request" {
		return false
	}
	signed := strings.Split(fields["SignedHeaders"], ";")
	if len(signed) == 0 || !sort.StringsAreSorted(signed) {
		return false
	}
	var canonical strings.Builder
	for _, key := range signed {
		value := r.Header.Get(key)
		if key == "host" {
			value = r.Host
		}
		if value == "" {
			return false
		}
		canonical.WriteString(key + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	query := strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20")
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		return false
	}
	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	request := strings.Join([]string{r.Method, uri, query, canonical.String(), fields["SignedHeaders"], payload}, "\n")
	digest := sha256.Sum256([]byte(request))
	timestamp := r.Header.Get("X-Amz-Date")
	if len(timestamp) < 8 || scope[1] != timestamp[:8] {
		return false
	}
	stringToSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + strings.Join(scope[1:], "/") + "\n" + hex.EncodeToString(digest[:])
	key := s3HMAC([]byte("AWS4"+s.Secret), scope[1])
	key = s3HMAC(key, scope[2])
	key = s3HMAC(key, "s3")
	key = s3HMAC(key, "aws4_request")
	signature, err := hex.DecodeString(fields["Signature"])
	return err == nil && hmac.Equal(signature, s3HMAC(key, stringToSign))
}
func (s *S3Server) URL(bucket, key string) string {
	return "s3://" + bucket + "/" + (&url.URL{Path: key}).EscapedPath()
}
func (s *S3Server) Stats() string {
	return fmt.Sprintf("requests=%d signed=%d", s.Requests.Load(), s.Signed.Load())
}

func (s *S3Server) PutFile(t testing.TB, bucket, key, version, filePath string) {
	t.Helper()
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	s.Put(bucket, key, version, nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	name := "/" + bucket + "/" + key + "\x00" + version
	s.paths[name] = filePath
	s.tags[name] = `"` + hex.EncodeToString(hash.Sum(nil)) + `"`
}
