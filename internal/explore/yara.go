package explore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/yara"
)

func readYaraInput(ctx context.Context, path string, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > int64(limit) {
		return nil, fmt.Errorf("YARA input must be a nonempty regular file of at most %d bytes", limit)
	}
	source, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if int64(len(source)) != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("YARA source changed while reading")
	}
	return source, ctx.Err()
}

func (s *Session) loadYaraRules(ctx context.Context, path, mode string) (*yara.Rules, error) {
	limit := yara.MaxSource
	if mode == "compiled" {
		limit = yara.MaxCompiled
	}
	source, err := readYaraInput(ctx, path, limit)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "compiled":
		return yara.LoadCompiled(ctx, s.Engine.Config.YaraXLibrary, source)
	case "config":
		var config struct {
			Schema  string `json:"schema"`
			Sources []struct {
				Namespace string `json:"namespace"`
				Source    string `json:"source"`
			} `json:"sources"`
			Globals map[string]json.RawMessage `json:"globals"`
		}
		decoder := json.NewDecoder(bytes.NewReader(source))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return nil, fmt.Errorf("YARA config: %w", err)
		}
		if config.Schema != "gomem.yarax-source/v1" {
			return nil, fmt.Errorf("unsupported YARA config schema")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, fmt.Errorf("YARA config must contain one JSON object")
		}
		prepared := yara.CompileConfig{Globals: config.Globals}
		for _, item := range config.Sources {
			prepared.Sources = append(prepared.Sources, yara.Source{Namespace: item.Namespace, Text: []byte(item.Source)})
		}
		return yara.CompileWithOptions(ctx, s.Engine.Config.YaraXLibrary, prepared)
	default:
		return yara.Compile(ctx, s.Engine.Config.YaraXLibrary, source)
	}
}

func (s *Session) scanYara(ctx context.Context, args []string, w io.Writer) error {
	if len(args) < 4 || len(args) > 5 {
		return fmt.Errorf("yara ADDRESS BYTE_LENGTH RULEFILE [TIMEOUT_SECONDS]")
	}
	if s.Engine.Config.YaraXLibrary == "" {
		return fmt.Errorf("yara requires an explicit --yarax-library")
	}
	address, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return err
	}
	length, err := strconv.ParseUint(args[2], 0, 32)
	if err != nil {
		return err
	}
	if length > yara.MaxScan {
		return fmt.Errorf("YARA scan byte length must be 0..%d", yara.MaxScan)
	}
	if _, err := memory.Add(address, length); err != nil {
		return err
	}
	seconds := uint64(5)
	if len(args) == 5 {
		seconds, err = strconv.ParseUint(args[4], 10, 64)
		if err != nil {
			return err
		}
	}
	if seconds == 0 || seconds > 60 {
		return fmt.Errorf("YARA scan timeout must be 1..60 seconds")
	}
	mode := "source"
	if args[0] == "yara-config" {
		mode = "config"
	} else if args[0] == "yara-compiled" {
		mode = "compiled"
	}
	rules, err := s.loadYaraRules(ctx, args[3], mode)
	encoder := json.NewEncoder(w)
	if err != nil {
		var compileErr *yara.CompileError
		if errors.As(err, &compileErr) && len(compileErr.Diagnostics) != 0 {
			writeErr := encoder.Encode(struct {
				Kind        string          `json:"kind"`
				Diagnostics json.RawMessage `json:"diagnostics"`
			}{"interactive_yara_compile_error", compileErr.Diagnostics})
			return errors.Join(err, writeErr)
		}
		return err
	}
	defer rules.Close()
	if warnings := rules.Warnings(); len(warnings) != 0 && string(warnings) != "[]" {
		if err := encoder.Encode(struct {
			Kind        string          `json:"kind"`
			RulesSHA256 string          `json:"rules_sha256"`
			Diagnostics json.RawMessage `json:"diagnostics"`
		}{"interactive_yara_compile_warnings", rules.Digest(), warnings}); err != nil {
			return err
		}
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	// Preserve the complete requested range as one YARA input. Splitting into
	// independent scans changes filesize/offset/count and global conditions.
	data := make([]byte, int(length))
	for offset := uint64(0); offset < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(length-offset, uint64(memory.MaxRead))
		got, err := s.Layer.ReadAt(ctx, data[offset:offset+n], address+offset)
		if err != nil {
			return err
		}
		if got != int(n) {
			return io.ErrUnexpectedEOF
		}
		offset += n
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	matches, scanErr := rules.Scan(ctx, data, yara.Options{TimeoutSeconds: seconds})
	if scanErr == nil {
		scanErr = s.Engine.ValidateSource(ctx)
	}
	if scanErr != nil {
		writeErr := encoder.Encode(struct {
			Kind        string `json:"kind"`
			Complete    bool   `json:"complete"`
			RulesSHA256 string `json:"rules_sha256"`
			Error       string `json:"error"`
		}{"interactive_yara_summary", false, rules.Digest(), scanErr.Error()})
		return errors.Join(scanErr, writeErr)
	}
	for _, match := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		var sources []memory.BackingMapping
		if !match.RuleOnly {
			for offset := uint64(0); offset < match.Length; {
				virtual := address + match.Offset + offset
				m := memory.BackingMapping{Virtual: virtual, Offset: virtual, Length: match.Length - offset, Layer: s.Layer}
				if v, ok := s.Layer.(*memory.Virtual); ok {
					backing, err := v.Resolve(ctx, virtual)
					if err != nil {
						return err
					}
					if backing.Available == 0 {
						return fmt.Errorf("zero YARA match backing extent")
					}
					m.Offset = backing.Offset
					m.Pagefile = backing.Pagefile
					m.Layer = backing.Layer
					m.Length = min(m.Length, backing.Available)
				}
				sources = append(sources, m)
				offset += m.Length
			}
		}
		sum := sha256.Sum256(match.Bytes)
		row := struct {
			Kind        string                  `json:"kind"`
			ImageSHA256 string                  `json:"image_sha256"`
			RulesSHA256 string                  `json:"rules_sha256"`
			Layer       string                  `json:"layer"`
			Address     string                  `json:"address,omitempty"`
			Namespace   string                  `json:"namespace"`
			Rule        string                  `json:"rule"`
			Pattern     string                  `json:"pattern,omitempty"`
			RuleOnly    bool                    `json:"rule_only,omitempty"`
			Length      *uint64                 `json:"length,omitempty"`
			Bytes       *[]byte                 `json:"bytes,omitempty"`
			SHA256      string                  `json:"sha256,omitempty"`
			Sources     []memory.BackingMapping `json:"sources,omitempty"`
		}{Kind: "interactive_yara_match", ImageSHA256: s.Engine.Hash, RulesSHA256: rules.Digest(), Layer: s.Layer.Name(), Namespace: match.Namespace, Rule: match.Rule, Pattern: match.Pattern, RuleOnly: match.RuleOnly, Sources: sources}
		if !match.RuleOnly {
			length := match.Length
			raw := append([]byte{}, match.Bytes...)
			row.Length = &length
			row.Bytes = &raw
			row.Address = fmt.Sprintf("0x%016x", address+match.Offset)
			row.SHA256 = hex.EncodeToString(sum[:])
		}
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	return encoder.Encode(struct {
		Kind        string `json:"kind"`
		Complete    bool   `json:"complete"`
		ImageSHA256 string `json:"image_sha256"`
		RulesSHA256 string `json:"rules_sha256"`
		Address     string `json:"address"`
		Length      uint64 `json:"length"`
		Matches     int    `json:"matches"`
	}{"interactive_yara_summary", true, s.Engine.Hash, rules.Digest(), fmt.Sprintf("0x%016x", address), length, len(matches)})
}
