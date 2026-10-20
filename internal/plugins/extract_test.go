package plugins

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type partialExtractionLayer struct{ cancel context.CancelFunc }

func (p partialExtractionLayer) Name() string           { return "partial-source" }
func (p partialExtractionLayer) Ranges() []memory.Range { return nil }
func (p partialExtractionLayer) ReadAt(ctx context.Context, b []byte, address uint64) (int, error) {
	if p.cancel != nil {
		if address >= 4096 {
			p.cancel()
			return 0, context.Canceled
		}
		for i := range b {
			b[i] = 'A'
		}
		return len(b), nil
	}
	for i := 0; i < 100; i++ {
		b[i] = 'B'
	}
	return 100, io.ErrUnexpectedEOF
}

func TestExtractionRetainsCapturedPrefixesAndCanceledFiles(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial-read", true: "cancel"}[canceled], func(t *testing.T) {
			s, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			task, err := s.Begin(ctx, "test", "test", evidence.Provenance{ImageSHA256: "synthetic", Plugin: "test"})
			if err != nil {
				t.Fatal(err)
			}
			sink := s.TaskArtifacts(task)
			e := plugin.Environment{Artifacts: sink}
			layer := partialExtractionLayer{}
			size := uint64(4096)
			if canceled {
				layer.cancel = cancel
				size = 8192
			}
			cell, err := extractRegion(ctx, e, layer, "partial.bin", 0, size)
			a := cell.Data.(evidence.Artifact)
			if canceled {
				if !errors.Is(err, context.Canceled) || a.State != "partial" || a.Size != "4096" {
					t.Fatal(a, err)
				}
			} else {
				if err != nil || a.State != "completed_with_gaps" || a.MissingBytes != "3996" {
					t.Fatal(a, err)
				}
				data, err := os.ReadFile(filepath.Join(s.Dir, filepath.FromSlash(a.Path)))
				if err != nil || data[99] != 'B' || data[100] != 0 || data[4095] != 0 {
					t.Fatal(data, err)
				}
			}
		})
	}
}

func TestNoncontiguousExtractionCancellationRetainsOnlyCapturedSpan(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	task, err := s.Begin(ctx, "test", "test", evidence.Provenance{Plugin: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cell, err := extractRanges(ctx, plugin.Environment{Artifacts: s.TaskArtifacts(task)}, partialExtractionLayer{cancel: cancel}, "ranges.bin", 0, []extractionRange{{0, 4096}, {0x7000, 4096}})
	a := cell.Data.(evidence.Artifact)
	if !errors.Is(err, context.Canceled) || a.State != "partial" || a.Size != "4096" || a.MissingBytes != "0" {
		t.Fatal(a, err)
	}
}
