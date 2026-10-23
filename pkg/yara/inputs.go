package yara

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const MaxCompiled = 64 << 20

type Source struct {
	Namespace string `json:"namespace"`
	Text      []byte `json:"text"`
}
type CompileConfig struct {
	Sources []Source `json:"sources"`
	// Raw JSON preserves signed 64-bit integers and float syntax without a
	// float64 round trip. Native YARA-X validates complex global types.
	Globals map[string]json.RawMessage `json:"globals,omitempty"`
}

func CompileWithOptions(ctx context.Context, library string, config CompileConfig) (*Rules, error) {
	return compileConfig(ctx, library, config, false)
}

func prepareConfig(config CompileConfig) (CompileConfig, error) {
	if len(config.Sources) == 0 || len(config.Sources) > 128 || len(config.Globals) > 256 {
		return CompileConfig{}, fmt.Errorf("YARA-X requires 1..128 sources and at most 256 externals")
	}
	out := CompileConfig{Sources: make([]Source, len(config.Sources)), Globals: make(map[string]json.RawMessage, len(config.Globals))}
	total := 0
	valid := func(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
	for n, source := range config.Sources {
		if len(source.Namespace) > 1024 || !valid(source.Namespace) || len(source.Text) == 0 || len(source.Text) > MaxSource-total || !utf8.Valid(source.Text) || strings.ContainsRune(string(source.Text), 0) {
			return out, fmt.Errorf("invalid YARA-X namespace or UTF-8 source")
		}
		total += len(source.Namespace) + len(source.Text)
		if total > MaxSource {
			return out, fmt.Errorf("YARA-X sources and external values exceed %d bytes", MaxSource)
		}
		out.Sources[n] = Source{Namespace: source.Namespace, Text: append([]byte(nil), source.Text...)}
	}
	for name, value := range config.Globals {
		if len(name) == 0 || len(name) > 1024 || !valid(name) || len(value) > MaxSource-total || !utf8.Valid(value) || !json.Valid(value) {
			return out, fmt.Errorf("invalid YARA-X external name or JSON value")
		}
		total += len(name) + len(value)
		if total > MaxSource {
			return out, fmt.Errorf("YARA-X sources and external values exceed %d bytes", MaxSource)
		}
		out.Globals[name] = append(json.RawMessage(nil), value...)
	}
	if total > MaxSource {
		return out, fmt.Errorf("YARA-X sources and external values exceed %d bytes", MaxSource)
	}
	return out, nil
}

func (r *Rules) Serialize(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.closed {
		return nil, fmt.Errorf("YARA-X rules closed")
	}
	data, err := r.native.Serialize()
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	return data, err
}

// LoadCompiled is explicit because serialized rules are native engine inputs,
// not text source. The caller must select the intended rules format.
func LoadCompiled(ctx context.Context, library string, data []byte) (*Rules, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(library) || !utf8.ValidString(library) || strings.ContainsRune(library, 0) {
		return nil, fmt.Errorf("YARA-X requires an absolute UTF-8 library path")
	}
	if len(data) == 0 || len(data) > MaxCompiled {
		return nil, fmt.Errorf("compiled YARA-X rules must be 1..%d bytes", MaxCompiled)
	}
	native, err := deserializeNative(library, data)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		native.Close()
		return nil, err
	}
	input := append([]byte("gomem.yarax-serialized/v1\x00"), data...)
	sum := sha256.Sum256(input)
	return &Rules{native: native, digest: hex.EncodeToString(sum[:])}, nil
}
