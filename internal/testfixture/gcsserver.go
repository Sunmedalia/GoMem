package testfixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gcsObject struct {
	Data                                            []byte
	Path, Tag, Generation, Metageneration, Encoding string
	Size                                            int64
}
type GCSServer struct {
	Server            *httptest.Server
	Token             string
	mu                sync.Mutex
	objects           map[string]map[string]gcsObject
	latest            map[string]string
	Requests          atomic.Int64
	Authenticated     atomic.Int64
	MissingConditions atomic.Int64
}

func StartGCSServer(t testing.TB, token string) *GCSServer {
	t.Helper()
	s := &GCSServer{Token: token, objects: map[string]map[string]gcsObject{}, latest: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Server.Close)
	return s
}
func (s *GCSServer) Endpoint() string { return s.Server.URL }
func (s *GCSServer) Put(bucket, key, generation, metageneration, encoding string, data []byte) {
	sum := sha256.Sum256(data)
	object := gcsObject{Data: bytes.Clone(data), Tag: base64.StdEncoding.EncodeToString(sum[:]), Generation: generation, Metageneration: metageneration, Encoding: encoding, Size: int64(len(data))}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := bucket + "\x00" + key
	if s.objects[name] == nil {
		s.objects[name] = map[string]gcsObject{}
	}
	s.objects[name][generation] = object
	s.latest[name] = generation
}
func (s *GCSServer) PutFile(t testing.TB, bucket, key, generation, filePath string) {
	t.Helper()
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	s.Put(bucket, key, generation, "1", "", nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	name := bucket + "\x00" + key
	object := s.objects[name][generation]
	object.Path = filePath
	object.Size = info.Size()
	object.Tag = base64.StdEncoding.EncodeToString(hash.Sum(nil))
	s.objects[name][generation] = object
}
func (s *GCSServer) serve(w http.ResponseWriter, r *http.Request) {
	s.Requests.Add(1)
	if r.Method != http.MethodGet {
		http.Error(w, "read-only", 405)
		return
	}
	if s.Token != "" {
		if r.Header.Get("Authorization") != "Bearer "+s.Token {
			http.Error(w, "credential-echo-secret", 401)
			return
		}
		s.Authenticated.Add(1)
	}
	escaped := strings.TrimPrefix(r.URL.EscapedPath(), "/download")
	prefix := "/storage/v1/b/"
	if !strings.HasPrefix(escaped, prefix) {
		http.NotFound(w, r)
		return
	}
	bucketEscaped, keyEscaped, ok := strings.Cut(strings.TrimPrefix(escaped, prefix), "/o/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	bucket, err := url.PathUnescape(bucketEscaped)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	key, err := url.PathUnescape(keyEscaped)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	name := bucket + "\x00" + key
	s.mu.Lock()
	generation := query.Get("generation")
	if generation == "" {
		generation = s.latest[name]
	}
	object, exists := s.objects[name][generation]
	s.mu.Unlock()
	if !exists {
		http.Error(w, `{"error":{"code":404}}`, 404)
		return
	}
	if condition := query.Get("ifGenerationMatch"); condition != "" && condition != object.Generation {
		http.Error(w, "generation changed", 412)
		return
	}
	if condition := query.Get("ifMetagenerationMatch"); condition != "" && condition != object.Metageneration {
		http.Error(w, "metadata changed", 412)
		return
	}
	w.Header().Set("x-goog-generation", object.Generation)
	w.Header().Set("x-goog-metageneration", object.Metageneration)
	if query.Get("alt") != "media" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"bucket": bucket, "name": key, "size": fmt.Sprint(object.Size), "generation": object.Generation, "metageneration": object.Metageneration, "etag": object.Tag, "contentEncoding": object.Encoding})
		return
	}
	if query.Get("ifGenerationMatch") == "" || query.Get("ifMetagenerationMatch") == "" {
		s.MissingConditions.Add(1)
	}
	if object.Encoding != "" {
		if object.Encoding == "gzip" && r.Header.Get("Accept-Encoding") != "gzip" {
			http.Error(w, "transcoding would change the byte stream", 400)
			return
		}
		w.Header().Set("Content-Encoding", object.Encoding)
	}
	// The media HTTP ETag deliberately differs from the JSON API object's ETag.
	// Generation preconditions, not an API-dependent ETag spelling, fix identity.
	sum := sha256.Sum256([]byte(object.Tag))
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	if object.Path != "" {
		file, err := os.Open(object.Path)
		if err != nil {
			http.Error(w, "unavailable", 500)
			return
		}
		defer file.Close()
		http.ServeContent(w, r, "object", time.Time{}, file)
		return
	}
	http.ServeContent(w, r, "object", time.Time{}, bytes.NewReader(object.Data))
}
