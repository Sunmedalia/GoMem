package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jlaffaye/ftp"
)

// FTPOptions controls acquisition, not subsequent local random reads.
type FTPOptions struct {
	Directory   string
	IdleTimeout time.Duration
	MaxBytes    uint64 // Zero permits any acquisition fitting a local file.
}
type RemoteSnapshotInfo struct {
	Schema         string  `json:"schema"`
	Protocol       string  `json:"protocol"`
	SHA256         string  `json:"sha256"`
	Size           uint64  `json:"size"`
	RemoteSize     *uint64 `json:"remote_size,omitempty"`
	RemoteModified string  `json:"remote_modified,omitempty"`
}

// SnapshotSource serves an acquired byte stream through a read-only local handle.
// It never reconnects to the server during analysis or successful cache replay.
type SnapshotSource struct {
	file       *FileSource
	info       os.FileInfo
	path, name string
	capture    RemoteSnapshotInfo
	closed     atomic.Bool
	closeOnce  sync.Once
	closeErr   error
}

func (s *SnapshotSource) Name() string { return s.name }
func (s *SnapshotSource) Size() uint64 { return s.file.Size() }
func (s *SnapshotSource) SnapshotInfo() RemoteSnapshotInfo {
	info := s.capture
	if info.RemoteSize != nil {
		size := *info.RemoteSize
		info.RemoteSize = &size
	}
	return info
}
func (s *SnapshotSource) FileInfos() []os.FileInfo { return []os.FileInfo{s.info} }
func (s *SnapshotSource) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if s.closed.Load() {
		return 0, os.ErrClosed
	}
	return s.file.ReadAt(ctx, p, at)
}
func (s *SnapshotSource) Validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed.Load() {
		return os.ErrClosed
	}
	info, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("snapshot stat failed")
	}
	if info.Size() != s.info.Size() || !info.ModTime().Equal(s.info.ModTime()) {
		return fmt.Errorf("local acquisition snapshot changed")
	}
	return nil
}
func (s *SnapshotSource) Close() error {
	s.closeOnce.Do(func() { s.closed.Store(true); s.closeErr = errors.Join(s.file.Close(), os.Remove(s.path)) })
	return s.closeErr
}

type ftpLocation struct{ address, user, password, directory, file, display string }

func parseFTPLocation(location string) (ftpLocation, error) {
	var result ftpLocation
	if len(location) > 65536 {
		return result, fmt.Errorf("FTP URL exceeds length budget")
	}
	u, err := url.Parse(location)
	if err != nil || !strings.EqualFold(u.Scheme, "ftp") || u.Hostname() == "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" {
		return result, fmt.Errorf("invalid FTP image URL")
	}
	port := u.Port()
	if port == "" {
		port = "21"
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return result, fmt.Errorf("invalid FTP port")
	}
	result.address = net.JoinHostPort(u.Hostname(), port)
	result.user, result.password = "anonymous", "gomem@"
	if u.User != nil {
		result.user = u.User.Username()
		result.password, _ = u.User.Password()
	}
	if result.user == "" || strings.ContainsAny(result.user+result.password, "\r\n\x00") {
		return result, fmt.Errorf("invalid FTP credentials")
	}
	// One URI slash selects the login directory; an escaped slash can select root.
	escaped := strings.TrimPrefix(u.EscapedPath(), "/")
	if strings.HasSuffix(strings.ToLower(escaped), ";type=i") {
		escaped = escaped[:len(escaped)-7]
	} else if strings.Contains(strings.ToLower(escaped), ";type=") {
		return result, fmt.Errorf("FTP image must use binary transfer")
	}
	path, err := url.PathUnescape(escaped)
	if err != nil || path == "" || strings.ContainsAny(path, "\r\n\x00") {
		return result, fmt.Errorf("invalid FTP image path")
	}
	at := strings.LastIndex(path, "/")
	if at >= 0 {
		result.directory = path[:at]
		if at == 0 {
			result.directory = "/"
		}
		result.file = path[at+1:]
	} else {
		result.file = path
	}
	if result.file == "" || result.file == "." || result.file == ".." {
		return result, fmt.Errorf("FTP image URL must select a file")
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	result.display = u.String()
	return result, nil
}

// A socket idle deadline covers replies, passive setup and transfer stalls.
// Cancellation closes all sockets, including a control connection blocked at login.
type ftpIdleConn struct {
	net.Conn
	timeout   time.Duration
	remaining int64 // Negative means data socket, which is streamed to disk.
}

func (c *ftpIdleConn) Read(p []byte) (int, error) {
	if c.remaining == 0 {
		return 0, fmt.Errorf("FTP reply budget exceeded")
	}
	if c.remaining > 0 && int64(len(p)) > c.remaining {
		p = p[:int(c.remaining)]
	}
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if c.remaining > 0 {
		c.remaining -= int64(n)
	}
	return n, err
}
func (c *ftpIdleConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type ftpSockets struct {
	mu          sync.Mutex
	connections []net.Conn
	closed      bool
}

func (s *ftpSockets) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, conn := range s.connections {
		conn.Close()
	}
	s.connections = nil
}
func (s *ftpSockets) add(conn net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		conn.Close()
		return context.Canceled
	}
	s.connections = append(s.connections, conn)
	return nil
}
func ftpOptionalMetadata(err error) bool {
	var status *textproto.Error
	return errors.As(err, &status) && (status.Code == 500 || status.Code == 502 || status.Code == 504 || status.Code == 550)
}

// Server reply strings are untrusted and may echo credentials or paths. Return
// operation names only, preserving context cancellation without those strings.
func ftpFailure(ctx context.Context, operation string, cause error) error {
	var network net.Error
	if errors.As(cause, &network) && network.Timeout() {
		return errors.Join(fmt.Errorf("FTP %s timed out", operation), os.ErrDeadlineExceeded, ctx.Err())
	}
	var status *textproto.Error
	if errors.As(cause, &status) {
		return errors.Join(fmt.Errorf("FTP %s failed (status %d)", operation, status.Code), ctx.Err())
	}
	return errors.Join(fmt.Errorf("FTP %s failed", operation), ctx.Err())
}

// OpenFTP captures one binary RETR into a private local snapshot. SIZE and MDTM
// are consistency checks when available, not remote atomic-version guarantees.
func OpenFTP(ctx context.Context, location string, options FTPOptions) (source *SnapshotSource, err error) {
	parsed, err := parseFTPLocation(location)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := options.IdleTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if timeout < 0 {
		return nil, fmt.Errorf("FTP idle timeout must be positive")
	}
	sockets := &ftpSockets{}
	stop := context.AfterFunc(ctx, sockets.close)
	defer stop()
	defer sockets.close()
	dialer := net.Dialer{Timeout: timeout}
	var dialCount atomic.Uint64
	dial := func(network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		remaining := int64(-1)
		if dialCount.Add(1) == 1 {
			remaining = 1 << 20
		}
		wrapped := &ftpIdleConn{Conn: conn, timeout: timeout, remaining: remaining}
		if err := sockets.add(wrapped); err != nil {
			return nil, err
		}
		return wrapped, nil
	}
	client, err := ftp.Dial(parsed.address, ftp.DialWithDialFunc(dial), ftp.DialWithShutTimeout(timeout))
	if err != nil {
		return nil, ftpFailure(ctx, "connection", err)
	}
	defer client.Quit()
	if err := client.Login(parsed.user, parsed.password); err != nil {
		return nil, ftpFailure(ctx, "login", err)
	}
	if parsed.directory != "" {
		if err := client.ChangeDir(parsed.directory); err != nil {
			return nil, ftpFailure(ctx, "directory selection", err)
		}
	}
	beforeSize, sizeErr := client.FileSize(parsed.file)
	if sizeErr != nil && !ftpOptionalMetadata(sizeErr) {
		return nil, ftpFailure(ctx, "size query", sizeErr)
	}
	if sizeErr == nil && beforeSize < 0 {
		return nil, fmt.Errorf("FTP reported a negative size")
	}
	if options.MaxBytes != 0 && sizeErr == nil && uint64(beforeSize) > options.MaxBytes {
		return nil, fmt.Errorf("FTP acquisition exceeds byte limit")
	}
	var beforeTime time.Time
	if client.IsGetTimeSupported() {
		beforeTime, err = client.GetTime(parsed.file)
		if err != nil && !ftpOptionalMetadata(err) {
			return nil, ftpFailure(ctx, "modification time query", err)
		}
	}
	response, err := client.Retr(parsed.file)
	if err != nil {
		return nil, ftpFailure(ctx, "retrieval", err)
	}
	responseClosed := false
	defer func() {
		if !responseClosed {
			response.Close()
		}
	}()
	if options.Directory != "" {
		if err := os.MkdirAll(options.Directory, 0700); err != nil {
			return nil, fmt.Errorf("FTP snapshot directory unavailable")
		}
	}
	target, err := os.CreateTemp(options.Directory, "gomem-ftp-*.snapshot")
	if err != nil {
		return nil, fmt.Errorf("FTP snapshot creation failed")
	}
	path := target.Name()
	retained := false
	defer func() {
		target.Close()
		if !retained {
			os.Remove(path)
		}
	}()
	hash := sha256.New()
	writer := io.MultiWriter(target, hash)
	buffer := make([]byte, 1<<20)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count, readErr := response.Read(buffer)
		if count > 0 {
			if uint64(count) > uint64(^uint64(0)>>1)-total || options.MaxBytes != 0 && uint64(count) > options.MaxBytes-total {
				return nil, fmt.Errorf("FTP acquisition exceeds byte limit")
			}
			if _, err := writer.Write(buffer[:count]); err != nil {
				return nil, fmt.Errorf("FTP snapshot write failed")
			}
			total += uint64(count)
			if sizeErr == nil && total > uint64(beforeSize) {
				return nil, fmt.Errorf("FTP transfer exceeds reported size")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, ftpFailure(ctx, "data transfer", readErr)
		}
	}
	closeErr := response.Close()
	responseClosed = true
	if closeErr != nil {
		return nil, ftpFailure(ctx, "transfer completion", closeErr)
	}
	if total == 0 {
		return nil, fmt.Errorf("FTP image is empty")
	}
	if sizeErr == nil {
		if total != uint64(beforeSize) {
			return nil, fmt.Errorf("FTP transfer is truncated")
		}
		afterSize, err := client.FileSize(parsed.file)
		if err != nil {
			return nil, ftpFailure(ctx, "final size query", err)
		}
		if afterSize != beforeSize {
			return nil, fmt.Errorf("FTP size changed during acquisition")
		}
	}
	if !beforeTime.IsZero() {
		afterTime, err := client.GetTime(parsed.file)
		if err != nil {
			return nil, ftpFailure(ctx, "final modification time query", err)
		}
		if !afterTime.Equal(beforeTime) {
			return nil, fmt.Errorf("FTP modification time changed during acquisition")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := target.Sync(); err != nil {
		return nil, fmt.Errorf("FTP snapshot sync failed")
	}
	info, err := target.Stat()
	if err != nil {
		return nil, fmt.Errorf("FTP snapshot stat failed")
	}
	if err := target.Close(); err != nil {
		return nil, fmt.Errorf("FTP snapshot close failed")
	}
	file, err := OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("FTP snapshot reopening failed")
	}
	reopened, err := file.Stat()
	if err != nil || !os.SameFile(info, reopened) || reopened.Size() != int64(total) {
		file.Close()
		return nil, fmt.Errorf("FTP snapshot changed during acquisition")
	}
	capture := RemoteSnapshotInfo{Schema: "gomem.remote-snapshot/v1", Protocol: "ftp", SHA256: hex.EncodeToString(hash.Sum(nil)), Size: total}
	if sizeErr == nil {
		size := uint64(beforeSize)
		capture.RemoteSize = &size
	}
	if !beforeTime.IsZero() {
		capture.RemoteModified = beforeTime.Format(time.RFC3339Nano)
	}
	retained = true
	return &SnapshotSource{file: file, info: reopened, path: path, name: parsed.display, capture: capture}, nil
}
