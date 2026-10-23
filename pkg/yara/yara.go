// Package yara provides bounded access to an optional native YARA-X C library.
// It is independent of Python and does not implement rule syntax itself.
package yara

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxSource = 1 << 20
const MaxScan = 32 << 20

var ErrTimeout = errors.New("YARA-X scan timeout")
var ErrLimit = errors.New("YARA-X result budget exhausted")

type Options struct {
	TimeoutSeconds uint64
	MaxMatches     uint32
	MaxOutputBytes uint64
}
type Match struct {
	Namespace string `json:"namespace"`
	Rule      string `json:"rule"`
	Pattern   string `json:"pattern,omitempty"`
	Offset    uint64 `json:"offset"`
	Length    uint64 `json:"length"`
	Bytes     []byte `json:"bytes,omitempty"`
	// RuleOnly preserves matching rules that have no reported pattern instance.
	RuleOnly bool `json:"rule_only,omitempty"`
}
type CompileError struct{ Diagnostics json.RawMessage }

func (e *CompileError) Error() string {
	return "YARA-X rule compilation failed (structured diagnostics available)"
}

type nativeRules interface {
	Scan([]byte, Options) ([]Match, error)
	Warnings() json.RawMessage
	Close()
}
type Rules struct {
	mu       sync.Mutex
	native   nativeRules
	closed   bool
	digest   string
	warnings json.RawMessage
}

func Compile(ctx context.Context, library string, source []byte) (*Rules, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(library) || strings.ContainsRune(library, 0) || !utf8.ValidString(library) {
		return nil, fmt.Errorf("YARA-X requires an absolute UTF-8 library path")
	}
	if len(source) == 0 || len(source) > MaxSource || !utf8.Valid(source) || strings.ContainsRune(string(source), 0) {
		return nil, fmt.Errorf("YARA-X source must be 1..%d UTF-8 bytes without NUL", MaxSource)
	}
	native, err := compileNative(library, source)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		native.Close()
		return nil, err
	}
	sum := sha256.Sum256(source)
	return &Rules{native: native, digest: hex.EncodeToString(sum[:]), warnings: append(json.RawMessage(nil), native.Warnings()...)}, nil
}
func (r *Rules) Warnings() json.RawMessage { return append(json.RawMessage(nil), r.warnings...) }
func (r *Rules) Digest() string            { return r.digest }
func (r *Rules) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.native.Close()
	}
	return nil
}
func (r *Rules) Scan(ctx context.Context, data []byte, options Options) ([]Match, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) > MaxScan {
		return nil, fmt.Errorf("YARA-X scan input exceeds %d bytes", MaxScan)
	}
	if options.TimeoutSeconds == 0 {
		options.TimeoutSeconds = 5
	}
	if options.MaxMatches == 0 {
		options.MaxMatches = 10000
	}
	if options.MaxOutputBytes == 0 {
		options.MaxOutputBytes = 8 << 20
	}
	if options.TimeoutSeconds > 60 || options.MaxMatches > 100000 || options.MaxOutputBytes > 64<<20 {
		return nil, fmt.Errorf("invalid YARA-X timeout or output budget")
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		seconds := uint64((remaining + time.Second - 1) / time.Second)
		options.TimeoutSeconds = min(options.TimeoutSeconds, seconds)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.closed {
		return nil, fmt.Errorf("YARA-X rules closed")
	}
	matches, err := r.native.Scan(data, options)
	// Cancellation is checked after the synchronous native call. C API lacks
	// a general force-cancel primitive; do not claim prompt Go cancellation.
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, err
	}
	for n := range matches {
		m := &matches[n]
		if m.Rule == "" || !utf8.ValidString(m.Rule) || !utf8.ValidString(m.Namespace) || !utf8.ValidString(m.Pattern) {
			return nil, fmt.Errorf("invalid native YARA-X match identity")
		}
		if m.RuleOnly {
			continue
		}
		if m.Offset > uint64(len(data)) || m.Length > uint64(len(data))-m.Offset {
			return nil, fmt.Errorf("YARA-X returned match outside input")
		}
		m.Bytes = append([]byte(nil), data[m.Offset:m.Offset+m.Length]...)
	}
	return matches, nil
}
