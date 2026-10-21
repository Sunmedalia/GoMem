package library

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const Images = "images"
const Symbols = "sysmbols" // User-facing directory name, intentionally preserved.

type Library struct{ Root string }
type File struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (l Library) Directory(kind string) string  { return filepath.Join(l.Root, kind) }
func (l Library) Path(kind, name string) string { return filepath.Join(l.Directory(kind), name) }
func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00") && filepath.Base(name) == name
}
func (l Library) open(kind string) (*os.Root, error) {
	if kind != Images && kind != Symbols {
		return nil, fmt.Errorf("invalid library kind")
	}
	dir := l.Directory(kind)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("library directory must not be a symlink")
	}
	return os.OpenRoot(dir)
}
func (l Library) List(kind string) ([]File, error) {
	r, err := l.open(kind)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	d, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	files := []File{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		files = append(files, File{e.Name(), info.Size()})
	}
	return files, nil
}
func (l Library) Import(ctx context.Context, kind, source string) (string, error) {
	f, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", fmt.Errorf("import requires a nonempty regular file")
	}
	return l.save(ctx, kind, filepath.Base(source), f)
}

type cancelReader struct {
	ctx context.Context
	r   io.Reader
}

func (r cancelReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

func (l Library) save(ctx context.Context, kind, name string, src io.Reader) (string, error) {
	if !validName(name) {
		return "", fmt.Errorf("invalid filename")
	}
	r, err := l.open(kind)
	if err != nil {
		return "", err
	}
	defer r.Close()
	// A hidden staging file is never listed. Publish by hard link so concurrent
	// imports and downloads cannot overwrite existing evidence or symbol files.
	tmp, err := os.CreateTemp(l.Directory(kind), ".import-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	_, copyErr := io.Copy(tmp, cancelReader{ctx, src})
	closeErr := tmp.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err = r.Link(filepath.Base(tmp.Name()), name); err != nil {
		return "", err
	}
	return l.Path(kind, name), nil
}
func (l Library) Rename(kind, old, name string) error {
	if !validName(old) || !validName(name) {
		return fmt.Errorf("invalid filename")
	}
	r, err := l.open(kind)
	if err != nil {
		return err
	}
	defer r.Close()
	info, err := r.Lstat(old)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	if err = r.Link(old, name); err != nil {
		return err
	}
	if err = r.Remove(old); err != nil {
		r.Remove(name)
		return err
	}
	return nil
}
func (l Library) Remove(kind, name string) error {
	if !validName(name) {
		return fmt.Errorf("invalid filename")
	}
	r, err := l.open(kind)
	if err != nil {
		return err
	}
	defer r.Close()
	info, err := r.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	return r.Remove(name)
}
