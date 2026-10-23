package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const gcsReadScope = "https://www.googleapis.com/auth/devstorage.read_only"

type GCSOptions struct {
	Endpoint  string // JSON API origin, default https://storage.googleapis.com.
	Anonymous bool
	Client    *http.Client
	Token     func(context.Context) (*oauth2.Token, error) // Optional context-aware credential provider.
}
type gcsMetadata struct {
	Bucket         string `json:"bucket"`
	Name           string `json:"name"`
	Size           string `json:"size"`
	Generation     string `json:"generation"`
	Metageneration string `json:"metageneration"`
	ETag           string `json:"etag"`
	Encoding       string `json:"contentEncoding"`
}

func parseGCSLocation(location string) (cloudLocation, error) {
	var result cloudLocation
	if len(location) > 65536 {
		return result, fmt.Errorf("GCS URL exceeds length budget")
	}
	u, err := url.Parse(location)
	if err != nil || !strings.EqualFold(u.Scheme, "gs") || u.User != nil || u.Host == "" || u.Opaque != "" || u.Fragment != "" || strings.ContainsAny(u.Host, ":[]%") || len(u.Host) > 222 {
		return result, fmt.Errorf("invalid GCS image URL")
	}
	if len(u.Host) < 3 || strings.IndexFunc(u.Host, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_')
	}) >= 0 {
		return result, fmt.Errorf("invalid GCS bucket")
	}
	key := strings.TrimPrefix(u.Path, "/")
	if key == "" || len(key) > 1024 || strings.ContainsAny(key, "\r\n\x00") {
		return result, fmt.Errorf("invalid GCS object key")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) > 1 || len(query) > 0 && len(query["generation"]) != 1 {
		return result, fmt.Errorf("GCS URL accepts only one generation")
	}
	version := query.Get("generation")
	if len(query) > 0 && !gcsPositiveNumber(version) {
		return result, fmt.Errorf("invalid GCS generation")
	}
	u.Scheme = "gs"
	u.RawQuery = ""
	u.ForceQuery = false
	return cloudLocation{bucket: u.Host, key: key, version: version, name: u.String()}, nil
}
func gcsPositiveNumber(value string) bool {
	if len(value) == 0 || len(value) > 19 || value[0] == '0' {
		return false
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return err == nil && parsed > 0
}

type GCSSource struct {
	client        *http.Client
	endpoint      string
	location      cloudLocation
	info          CloudObjectInfo
	metadata      gcsMetadata
	anonymous     bool
	tokenProvider func(context.Context) (*oauth2.Token, error)
	authLock      chan struct{}
	token         *oauth2.Token // Guarded by authLock; only concrete tokens survive request contexts.
	closed        atomic.Bool
	life          context.Context
	cancel        context.CancelFunc
}

func OpenGCS(ctx context.Context, location string, options GCSOptions) (*GCSSource, error) {
	parsed, err := parseGCSLocation(location)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpoint := strings.TrimSuffix(options.Endpoint, "/")
	if endpoint == "" {
		endpoint = "https://storage.googleapis.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid GCS JSON endpoint")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("GCS plaintext endpoint limited to loopback")
		}
	}
	client := http.Client{Timeout: 60 * time.Second}
	if options.Client != nil {
		client = *options.Client
		if client.Timeout == 0 {
			client.Timeout = 60 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return fmt.Errorf("GCS redirects not followed") }
	life, cancel := context.WithCancel(context.Background())
	source := &GCSSource{client: &client, endpoint: endpoint, location: parsed, anonymous: options.Anonymous, tokenProvider: options.Token, authLock: make(chan struct{}, 1), life: life, cancel: cancel}
	metadata, err := source.readMetadata(ctx, false)
	if err != nil {
		source.Close()
		return nil, err
	}
	source.metadata = metadata
	size, _ := strconv.ParseUint(metadata.Size, 10, 64)
	source.info = CloudObjectInfo{Schema: "gomem.cloud-object/v1", Protocol: "gs", Endpoint: endpoint, Bucket: parsed.bucket, Key: parsed.key, Version: metadata.Generation, Metageneration: metadata.Metageneration, ETag: metadata.ETag, Size: size}
	return source, nil
}
func (s *GCSSource) Name() string                     { return s.location.name }
func (s *GCSSource) Size() uint64                     { return s.info.Size }
func (s *GCSSource) CloudObjectInfo() CloudObjectInfo { return s.info }
func (s *GCSSource) Close() error                     { s.closed.Store(true); s.cancel(); return nil }
func (s *GCSSource) operation(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if s.closed.Load() {
		return nil, nil, fmt.Errorf("GCS source closed")
	}
	request, cancel := context.WithTimeout(ctx, 60*time.Second)
	stop := context.AfterFunc(s.life, cancel)
	return request, func() { stop(); cancel() }, nil
}
func (s *GCSSource) authorization(ctx context.Context) (string, error) {
	if s.anonymous {
		return "", nil
	}
	select {
	case s.authLock <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-s.authLock }()
	if s.token == nil || !s.token.Valid() {
		var token *oauth2.Token
		var err error
		if s.tokenProvider != nil {
			token, err = s.tokenProvider(ctx)
		} else {
			// A fresh provider binds credential refresh to this operation's context.
			// A concrete cached token, rather than a TokenSource retaining a canceled
			// opening context, is reused for subsequent reads.
			authClient := &http.Client{Timeout: 60 * time.Second}
			authContext := context.WithValue(ctx, oauth2.HTTPClient, authClient)
			credentials, credErr := google.FindDefaultCredentials(authContext, gcsReadScope)
			if credErr != nil {
				return "", cloudFailure(ctx, "GCS", "default credentials", credErr)
			}
			token, err = credentials.TokenSource.Token()
		}
		if err != nil {
			return "", cloudFailure(ctx, "GCS", "token refresh", err)
		}
		if token == nil || !token.Valid() {
			return "", fmt.Errorf("GCS credential provider returned invalid token")
		}
		copy := *token
		s.token = &copy
	}
	if len(s.token.AccessToken) > 1<<20 || strings.IndexFunc(s.token.AccessToken, func(r rune) bool { return r <= 0x20 || r == 0x7f }) >= 0 || !strings.EqualFold(s.token.Type(), "Bearer") {
		return "", fmt.Errorf("GCS requires a valid bearer token")
	}
	return "Bearer " + s.token.AccessToken, nil
}
func (s *GCSSource) objectURL(pinned bool, media bool) string {
	// Escape the object as one path component; slash, ?, # and % are key bytes.
	location := s.endpoint + "/storage/v1/b/" + url.PathEscape(s.location.bucket) + "/o/" + url.PathEscape(s.location.key)
	query := url.Values{}
	if pinned {
		query.Set("generation", s.metadata.Generation)
		query.Set("ifGenerationMatch", s.metadata.Generation)
		query.Set("ifMetagenerationMatch", s.metadata.Metageneration)
	} else if s.location.version != "" {
		query.Set("generation", s.location.version)
	}
	if media {
		query.Set("alt", "media")
	} else {
		query.Set("fields", "bucket,name,size,generation,metageneration,etag,contentEncoding")
	}
	return location + "?" + query.Encode()
}
func (s *GCSSource) request(ctx context.Context, pinned, media bool, extent string) (*http.Response, error) {
	authorization, err := s.authorization(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(pinned, media), nil)
	if err != nil {
		return nil, fmt.Errorf("invalid GCS object request")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Accept-Encoding", "identity")
	if media {
		req.Header.Set("Range", extent)
		// Force storage bytes for gzip objects, disabling GCS decompressive
		// transcoding and Go's automatic gzip decompression of the response.
		if s.metadata.Encoding == "gzip" {
			req.Header.Set("Accept-Encoding", "gzip")
		}
	}
	response, err := s.client.Do(req)
	if err != nil {
		return nil, cloudFailure(ctx, "GCS", "transport", err)
	}
	return response, nil
}
func (s *GCSSource) readMetadata(ctx context.Context, pinned bool) (gcsMetadata, error) {
	var metadata gcsMetadata
	request, done, err := s.operation(ctx)
	if err != nil {
		return metadata, err
	}
	defer done()
	response, err := s.request(request, pinned, false, "")
	if err != nil {
		return metadata, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Uncompressed {
		return metadata, fmt.Errorf("GCS metadata request rejected (status %d)", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return metadata, cloudFailure(request, "GCS", "metadata read", err)
	}
	if len(raw) > 64<<10 {
		return metadata, fmt.Errorf("GCS metadata exceeds budget")
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return metadata, fmt.Errorf("invalid GCS metadata JSON")
	}
	if metadata.Bucket != s.location.bucket || metadata.Name != s.location.key || !gcsPositiveNumber(metadata.Size) || !gcsPositiveNumber(metadata.Generation) || !gcsPositiveNumber(metadata.Metageneration) || len(metadata.ETag) == 0 || len(metadata.ETag) > 8192 || strings.ContainsAny(metadata.ETag, "\r\n\x00") {
		return metadata, fmt.Errorf("GCS metadata identity invalid")
	}
	if metadata.Encoding != "" && metadata.Encoding != "identity" && metadata.Encoding != "gzip" {
		return metadata, fmt.Errorf("unsupported GCS content encoding")
	}
	if !pinned && s.location.version != "" && s.location.version != metadata.Generation {
		return metadata, fmt.Errorf("GCS requested generation mismatch")
	}
	return metadata, nil
}
func (s *GCSSource) Validate(ctx context.Context) error {
	metadata, err := s.readMetadata(ctx, true)
	if err != nil {
		return err
	}
	if metadata != s.metadata {
		return fmt.Errorf("GCS object or metadata identity changed")
	}
	return nil
}
func (s *GCSSource) ReadAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	request, done, err := s.operation(ctx)
	if err != nil {
		return 0, err
	}
	defer done()
	if len(p) > MaxRead {
		return 0, fmt.Errorf("GCS read exceeds budget")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if offset >= s.Size() {
		return 0, io.EOF
	}
	length := min(uint64(len(p)), s.Size()-offset)
	end := offset + length - 1
	response, err := s.request(request, true, true, fmt.Sprintf("bytes=%d-%d", offset, end))
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	first, last, total, err := parseContentRange(response.Header.Get("Content-Range"))
	if response.StatusCode != http.StatusPartialContent || err != nil || first != offset || last != end || total != s.Size() || response.ContentLength < 0 || uint64(response.ContentLength) != length || response.Uncompressed {
		return 0, fmt.Errorf("GCS inconsistent byte-range response")
	}
	if response.Header.Get("x-goog-generation") != s.metadata.Generation || response.Header.Get("x-goog-metageneration") != s.metadata.Metageneration {
		return 0, fmt.Errorf("GCS response generation changed")
	}
	encoding := response.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" && !(encoding == "gzip" && s.metadata.Encoding == "gzip") {
		return 0, fmt.Errorf("GCS unexpected response encoding")
	}
	if s.metadata.Encoding == "gzip" && encoding != "gzip" {
		return 0, fmt.Errorf("GCS stored gzip representation was not preserved")
	}
	n, err := io.ReadFull(response.Body, p[:int(length)])
	if err != nil {
		return n, cloudFailure(request, "GCS", "body read", err)
	}
	var extra [1]byte
	k, err := response.Body.Read(extra[:])
	if k != 0 || err != io.EOF {
		return n, cloudFailure(request, "GCS", "body completion", err)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
