package memory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// HTTPSource reads a fixed HTTP representation using conditional byte ranges.
// A strong ETag is mandatory: timestamps alone cannot pin forensic evidence.
type HTTPSource struct {
	client   *http.Client
	location string
	name     string
	size     uint64
	etag     string
	closed   atomic.Bool
	life     context.Context
	cancel   context.CancelFunc
}

// OpenSource opens a local image or an HTTP(S) image. Offline forbids remote I/O.
func OpenSource(ctx context.Context, location string, offline bool) (MemorySource, error) {
	lower := strings.ToLower(location)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if offline {
			return nil, fmt.Errorf("remote image unavailable in offline mode")
		}
		return OpenHTTP(ctx, location, nil)
	}
	if strings.Contains(location, "://") {
		return nil, fmt.Errorf("unsupported image source scheme")
	}
	return OpenFile(location)
}

// OpenHTTP accepts a custom client for transports/authentication. It clones the
// client and retains TLS verification; redirects cannot downgrade HTTPS.
func OpenHTTP(ctx context.Context, location string, client *http.Client) (*HTTPSource, error) {
	u, err := url.Parse(location)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
		return nil, fmt.Errorf("invalid HTTP image URL")
	}
	if client == nil {
		client = http.DefaultClient
	}
	c := *client
	if c.Timeout == 0 {
		c.Timeout = 60 * time.Second
	}
	previous := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || (req.URL.Scheme != "http" && req.URL.Scheme != "https") || (len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https") {
			return fmt.Errorf("HTTP image redirect rejected")
		}
		if previous != nil {
			return previous(req, via)
		}
		return nil
	}
	display := *u
	display.User = nil
	display.RawQuery = ""
	display.ForceQuery = false
	life, cancel := context.WithCancel(context.Background())
	s := &HTTPSource{client: &c, location: location, name: display.String(), life: life, cancel: cancel}
	var one [1]byte
	_, err = s.read(ctx, one[:], 0, true)
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *HTTPSource) Name() string { return s.name }
func (s *HTTPSource) Size() uint64 { return s.size }
func (s *HTTPSource) Close() error { s.closed.Store(true); s.cancel(); return nil }

// Validate checks the pinned representation even when analysis reuses cached rows.
func (s *HTTPSource) Validate(ctx context.Context) error {
	var one [1]byte
	_, err := s.ReadAt(ctx, one[:], 0)
	return err
}

func (s *HTTPSource) ReadAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	return s.read(ctx, p, offset, false)
}
func (s *HTTPSource) read(ctx context.Context, p []byte, offset uint64, initial bool) (n int, err error) {
	defer func() {
		if err != nil {
			err = &ReadError{offset, len(p), s.name, err}
		}
	}()
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed.Load() {
		return 0, fmt.Errorf("HTTP source closed")
	}
	if len(p) > MaxRead {
		return 0, fmt.Errorf("read exceeds %d bytes", MaxRead)
	}
	if len(p) == 0 {
		return 0, nil
	}
	length := uint64(len(p))
	if !initial {
		if offset >= s.size {
			return 0, io.EOF
		}
		length = min(length, s.size-offset)
	}
	end, err := Add(offset, length-1)
	if err != nil {
		return 0, err
	}
	requestCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.life, cancel)
	defer func() { stop(); cancel() }()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, s.location, nil)
	if err != nil {
		return 0, fmt.Errorf("invalid HTTP image request")
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))
	req.Header.Set("Accept-Encoding", "identity")
	if !initial {
		req.Header.Set("If-Match", s.etag)
	}
	response, err := s.client.Do(req)
	if err != nil {
		// url.Error contains credentials and signed query parameters. Never persist it.
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if s.life.Err() != nil {
			return 0, fmt.Errorf("HTTP source closed")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, context.DeadlineExceeded
		}
		return 0, fmt.Errorf("HTTP image transport failed")
	}
	defer response.Body.Close()
	if !initial && response.Request.URL.String() != s.location {
		return 0, fmt.Errorf("HTTP image resource redirected after identity was pinned")
	}
	if response.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("HTTP image requires byte ranges: status %d", response.StatusCode)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return 0, fmt.Errorf("HTTP image encoded response rejected")
	}
	start, last, total, err := parseContentRange(response.Header.Get("Content-Range"))
	if err != nil || start != offset || last != end || total == 0 || last >= total || (!initial && total != s.size) {
		return 0, fmt.Errorf("HTTP image inconsistent Content-Range")
	}
	tag := response.Header.Get("ETag")
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' || strings.ContainsAny(tag[1:len(tag)-1], "\"\r\n") || strings.IndexFunc(tag[1:len(tag)-1], func(r rune) bool { return r < 0x21 || r == 0x7f }) >= 0 {
		return 0, fmt.Errorf("HTTP image requires a strong ETag")
	}
	if !initial && tag != s.etag {
		return 0, fmt.Errorf("HTTP image changed since hashing")
	}
	if response.ContentLength >= 0 && uint64(response.ContentLength) != length {
		return 0, fmt.Errorf("HTTP image inconsistent Content-Length")
	}
	n, err = io.ReadFull(response.Body, p[:int(length)])
	if err != nil {
		return n, err
	}
	var extra [1]byte
	if k, e := response.Body.Read(extra[:]); k != 0 || e != io.EOF {
		return n, fmt.Errorf("HTTP image trailing bytes or incomplete response")
	}
	if initial {
		s.size = total
		s.etag = tag
		s.location = response.Request.URL.String()
	}
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func parseContentRange(value string) (uint64, uint64, uint64, error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, fmt.Errorf("invalid range unit")
	}
	extent, totalText, ok := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !ok {
		return 0, 0, 0, fmt.Errorf("missing range total")
	}
	firstText, lastText, ok := strings.Cut(extent, "-")
	if !ok {
		return 0, 0, 0, fmt.Errorf("missing range extent")
	}
	values := [3]uint64{}
	for i, text := range []string{firstText, lastText, totalText} {
		if text == "" || strings.IndexFunc(text, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return 0, 0, 0, fmt.Errorf("invalid range number")
		}
		n, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return 0, 0, 0, err
		}
		values[i] = n
	}
	if values[0] > values[1] {
		return 0, 0, 0, fmt.Errorf("reversed range")
	}
	return values[0], values[1], values[2], nil
}
