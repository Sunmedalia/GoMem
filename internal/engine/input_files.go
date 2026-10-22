package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func inputFilePath(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("required input file is absent")
	}
	if !strings.Contains(value, "://") {
		return value, nil
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if u.Scheme != "file" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return "", fmt.Errorf("input requires a local path or file URI")
	}
	path := u.Path
	if u.Host != "" && u.Host != "localhost" {
		if runtime.GOOS != "windows" {
			return "", fmt.Errorf("nonlocal file URI host is unsupported")
		}
		path = "//" + u.Host + path
	} else if runtime.GOOS == "windows" && len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		path = path[1:]
	}
	return filepath.FromSlash(path), nil
}

func snapshotInputs(ctx context.Context, spec plugin.Spec, params map[string]string) (inputs map[string]plugin.Input, cleanup func() error, err error) {
	inputs = make(map[string]plugin.Input)
	var files []*os.File
	var paths []string
	dispose := func() error {
		var failures []error
		for _, file := range files {
			failures = append(failures, file.Close())
		}
		for _, path := range paths {
			failures = append(failures, os.Remove(path))
		}
		return errors.Join(failures...)
	}
	cleanup = dispose
	defer func() {
		if err != nil {
			err = errors.Join(err, dispose())
		}
	}()
	for _, declared := range spec.InputFiles {
		if declared.Name == "" || declared.MaxBytes == 0 || declared.MaxBytes > 1<<32 {
			return nil, nil, fmt.Errorf("invalid input declaration %q", declared.Name)
		}
		if _, exists := inputs[declared.Name]; exists {
			return nil, nil, fmt.Errorf("duplicate input declaration %q", declared.Name)
		}
		path, cause := inputFilePath(params[declared.Name])
		if cause != nil {
			return nil, nil, fmt.Errorf("%s: %w", declared.Name, cause)
		}
		input, file, temporary, cause := snapshotInput(ctx, path, declared.MaxBytes)
		if cause != nil {
			return nil, nil, fmt.Errorf("%s: %w", declared.Name, cause)
		}
		files = append(files, file)
		paths = append(paths, temporary)
		inputs[declared.Name] = input
	}
	return inputs, cleanup, nil
}

func snapshotInput(ctx context.Context, path string, max uint64) (input plugin.Input, reader *os.File, temporary string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return input, nil, "", err
	}
	if !info.Mode().IsRegular() {
		return input, nil, "", fmt.Errorf("input must be a regular file")
	}
	source, err := os.Open(path)
	if err != nil {
		return input, nil, "", err
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil {
		return input, nil, "", err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || uint64(before.Size()) > max {
		return input, nil, "", fmt.Errorf("input must be a regular file of at most %d bytes", max)
	}
	file, err := os.CreateTemp("", "gomem-input-*")
	if err != nil {
		return input, nil, "", err
	}
	temporary = file.Name()
	defer func() {
		if err != nil {
			file.Close()
			if reader != nil {
				reader.Close()
			}
			os.Remove(temporary)
		}
	}()
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return
		}
		var n int
		n, err = source.Read(buffer)
		if n > 0 {
			if uint64(input.Size)+uint64(n) > max {
				err = fmt.Errorf("input grew beyond %d bytes", max)
				return
			}
			if _, cause := file.Write(buffer[:n]); cause != nil {
				err = cause
				return
			}
			hash.Write(buffer[:n])
			input.Size += int64(n)
		}
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return
		}
	}
	after, cause := source.Stat()
	if cause != nil {
		err = cause
		return
	}
	if before.Size() != input.Size || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		err = fmt.Errorf("input changed while being snapshotted")
		return
	}
	if err = file.Close(); err != nil {
		return
	}
	reader, err = os.Open(temporary)
	if err != nil {
		return
	}
	input.Reader = reader
	input.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return
}
