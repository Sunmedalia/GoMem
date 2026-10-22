package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func TestInputSnapshotsBoundsEmptyCleanupAndCancellation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	path := filepath.Join(t.TempDir(), "input")
	for _, size := range []int{0, 8, 9} {
		if err := os.WriteFile(path, make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
		input, file, temporary, err := snapshotInput(context.Background(), path, 8)
		if size > 8 {
			if err == nil {
				t.Fatal("oversize accepted")
			}
			continue
		}
		if err != nil || input.Size != int64(size) || len(input.SHA256) != 64 {
			t.Fatal(input, err)
		}
		if _, err = file.Write([]byte("x")); err == nil {
			t.Fatal("snapshot reader is writable")
		}
		if _, err = io.ReadAll(io.NewSectionReader(input.Reader, 0, input.Size)); err != nil {
			t.Fatal(err)
		}
		file.Close()
		os.Remove(temporary)
	}
	os.WriteFile(path, []byte("1234"), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := snapshotInput(ctx, path, 8); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, definitions := range [][]plugin.FileInput{
		{{Name: "file", MaxBytes: 8}, {Name: "missing", MaxBytes: 8}},
		{{Name: "file", MaxBytes: 8}, {Name: "file", MaxBytes: 8}},
		{{Name: "file", MaxBytes: 0}},
	} {
		if _, _, err := snapshotInputs(context.Background(), plugin.Spec{InputFiles: definitions}, map[string]string{"file": path}); err == nil {
			t.Fatal("invalid input declarations accepted", definitions)
		}
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatal("snapshot leaked on failed preparation", entries, err)
	}
	for _, value := range []string{"", "https://example.com/input", "file:///input?query=1", "file:///input#fragment"} {
		if _, err := inputFilePath(value); err == nil {
			t.Fatal("unsupported URI accepted", value)
		}
	}
}
