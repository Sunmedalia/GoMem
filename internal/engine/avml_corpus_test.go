package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
)

func TestOfficialLinuxReencodedAVML(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional official Linux corpus reencoded by locked Microsoft source; not a separate acquisition or full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.avml"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Format != "avml" || e.Hash != "5b4d1fb2174127c3922af8ca623d00a4d37757c48154f0eb0a5c660f4551d324" || e.Config.DTB != "0x1605000" {
		t.Fatal("format, image or verified DTB drift", e.Format, e.Hash, e.Config.DTB)
	}
	for _, tc := range []struct {
		name   string
		params map[string]string
		count  int64
		failed bool
	}{{"linux.pslist", nil, 133, false}, {"linux.lsmod", nil, 79, true}, {"linux.maps", map[string]string{"include-past-eof": "false"}, 13990, false}, {"linux.psaux", nil, 133, true}} {
		result, err := e.Run(ctx, tc.name, tc.params, engine.RunOptions{})
		if (err != nil) != tc.failed || result.Task.Rows != tc.count {
			t.Fatal(tc.name, result, err)
		}
	}
	r, err := e.Run(ctx, "linux.maps", map[string]string{"pid": "1", "address": "0x400000", "dump": "true"}, engine.RunOptions{})
	if err != nil || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	files, err := e.Store.Artifacts(ctx, r.Task.ID)
	if err != nil || len(files) != 1 || files[0].Size != "36864" || files[0].MissingBytes != "12288" || files[0].SHA256 != "def8ca5ec5a3ca9b1c4e6ad8e856fd5f3f13d501aea628b7d3eb2aa66fcd6246" || files[0].Provenance.ImageSHA256 != e.Hash {
		t.Fatal(files, err)
	}
	if err = e.Store.VerifyTaskArtifacts(ctx, r.Task.ID); err != nil {
		t.Fatal(err)
	}
}
