package explore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (s *Session) saveYara(ctx context.Context, args []string, w io.Writer) error {
	if len(args) != 3 {
		return fmt.Errorf("yara-save[-config] INPUT OUTPUT_NAME")
	}
	if s.Engine.Config.YaraXLibrary == "" {
		return fmt.Errorf("YARA serialization requires --yarax-library")
	}
	if s.Engine.Config.CaseDir == "" {
		return fmt.Errorf("YARA serialization requires a persistent --case directory")
	}
	name := args[2]
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\:\x00") {
		return fmt.Errorf("YARA output must be a plain filename")
	}
	mode := "source"
	if args[0] == "yara-save-config" {
		mode = "config"
	}
	rules, err := s.loadYaraRules(ctx, args[1], mode)
	if err != nil {
		return err
	}
	defer rules.Close()
	data, err := rules.Serialize(ctx)
	if err != nil {
		return err
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	root, err := os.OpenRoot(s.Engine.Config.CaseDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll("exports/rules", 0700); err != nil {
		return err
	}
	path := "exports/rules/" + name
	f, err := root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	writeErr = errors.Join(writeErr, f.Close(), ctx.Err())
	if writeErr != nil {
		return errors.Join(writeErr, root.Remove(path))
	}
	sum := sha256.Sum256(data)
	// The file is a reproducible rule artifact, not a sealed extraction task.
	return json.NewEncoder(w).Encode(struct {
		Kind        string `json:"kind"`
		Path        string `json:"case_relative_path"`
		RulesSHA256 string `json:"source_rules_sha256"`
		SHA256      string `json:"serialized_sha256"`
		Size        int    `json:"size"`
	}{"interactive_yara_serialized", path, rules.Digest(), hex.EncodeToString(sum[:]), len(data)})
}
