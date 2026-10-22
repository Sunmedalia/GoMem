package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type inputProbe struct{ declarations []plugin.FileInput }

func (p inputProbe) Spec() plugin.Spec {
	return plugin.Spec{Name: "input-probe", Parameters: []plugin.Parameter{{Name: "file", Kind: "string"}}, InputFiles: p.declarations}
}
func (p inputProbe) Run(ctx context.Context, env plugin.Environment, _ map[string]string, out plugin.Emit) error {
	input := env.Inputs["file"]
	data, err := io.ReadAll(io.NewSectionReader(input.Reader, 0, input.Size))
	if err != nil {
		return err
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{"Raw": evidence.Bytes(data), "Digest": evidence.Text(input.SHA256)}})
}

func TestInputSnapshotContentCacheAndRunIsolation(t *testing.T) {
	e, _ := openFixture(t, "linux")
	if err := e.Registry.Register(inputProbe{[]plugin.FileInput{{Name: "file", MaxBytes: 8}}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "input with spaces.txt")
	original, changed := []byte("before"), []byte("after!")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(path)
	params := map[string]string{"file": (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()}
	// A Windows file URI requires /C:/... rather than file://C:/...
	if filepath.VolumeName(path) != "" {
		params["file"] = (&url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(path)}).String()
	}
	var first, second, replay bytes.Buffer
	emit := func(b *bytes.Buffer) plugin.Emit {
		return func(row evidence.Row) error {
			if err := row.Verify(); err != nil {
				t.Fatal(err)
			}
			return json.NewEncoder(b).Encode(row)
		}
	}
	one, err := e.Run(context.Background(), "input-probe", params, engine.RunOptions{OnStart: func(evidence.Task) {
		if err := os.WriteFile(path, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, stat.ModTime(), stat.ModTime()); err != nil {
			t.Fatal(err)
		}
	}, Emit: emit(&first)})
	if err != nil || one.Reused {
		t.Fatal(one, err)
	}
	var row evidence.Row
	if err := json.Unmarshal(first.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(original)
	if row.Cells["Digest"].String() != hex.EncodeToString(hash[:]) || row.Provenance.Parameters["engine.input.file.sha256"] != hex.EncodeToString(hash[:]) || row.Provenance.Parameters["engine.input.file.size"] != "6" {
		t.Fatal("original snapshot lost", row)
	}
	two, err := e.Run(context.Background(), "input-probe", params, engine.RunOptions{Emit: emit(&second)})
	if err != nil || two.Reused || two.Task.ID == one.Task.ID || bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("same-size/same-mtime content change reused stale evidence", two, err)
	}
	three, err := e.Run(context.Background(), "input-probe", params, engine.RunOptions{Emit: emit(&replay)})
	if err != nil || !three.Reused || three.Task.ID != two.Task.ID || !bytes.Equal(second.Bytes(), replay.Bytes()) {
		t.Fatal("unchanged content failed sealed cache replay", three, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), "input-probe", params, engine.RunOptions{}); err == nil {
		t.Fatal("missing input replayed a cached task")
	}
}
