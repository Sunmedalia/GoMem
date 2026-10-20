package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type extractionProbe struct{ forgotten bool }

func (p extractionProbe) Spec() plugin.Spec { return plugin.Spec{Name: "test.extract"} }
func (p extractionProbe) Run(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	w, err := e.Artifacts.Create(ctx, evidence.ArtifactRequest{Name: "probe.bin", Size: 4, Layer: e.Physical.Name(), Offset: "0x18000"})
	if err != nil {
		return err
	}
	if _, err = w.Write([]byte("ABCD")); err != nil {
		return err
	}
	if p.forgotten {
		return nil
	}
	a, err := w.Finish(ctx, nil)
	if err != nil {
		return err
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{"File": {Kind: "artifact", Data: a}}})
}

func TestEngineExtractionBindingCacheIntegrityAndFinalization(t *testing.T) {
	for _, forgotten := range []bool{false, true} {
		t.Run(fmt.Sprint(forgotten), func(t *testing.T) {
			e, _ := openFixture(t, "linux")
			if err := e.Registry.Register(extractionProbe{forgotten}); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			result, err := e.Run(ctx, "test.extract", nil, engine.RunOptions{})
			if forgotten {
				if err == nil || result.Task.State != "failed" {
					t.Fatal("unclosed extraction became success", result, err)
				}
				return
			}
			if err != nil || result.Task.Rows != 1 {
				t.Fatal(result, err)
			}
			artifacts, err := e.Store.Artifacts(ctx, result.Task.ID)
			if err != nil || len(artifacts) != 1 {
				t.Fatal(artifacts, err)
			}
			a := artifacts[0]
			if a.Provenance.ImageSHA256 != e.Hash || a.Provenance.EngineBuild != e.Build || a.TaskID != result.Task.ID {
				t.Fatal("unbound artifact provenance", a)
			}
			if cached, err := e.Run(ctx, "test.extract", nil, engine.RunOptions{}); err != nil || !cached.Reused {
				t.Fatal(cached, err)
			}
			if err = os.WriteFile(filepath.Join(e.Store.Dir, filepath.FromSlash(a.Path)), []byte("WXYZ"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Run(ctx, "test.extract", nil, engine.RunOptions{}); err == nil {
				t.Fatal("cached task hid modified extraction")
			}
			fresh, err := e.Run(ctx, "test.extract", nil, engine.RunOptions{Fresh: true})
			if err != nil || fresh.Reused || fresh.Task.ID == result.Task.ID {
				t.Fatal(fresh, err)
			}
		})
	}
}
