package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxInodePageCache(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional locked legacy Linux page cache; full capability acceptance pending")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, sample := range []struct {
		label, inode string
		count        int
	}{{"syslog", "0xffff88001a87e518", 3}, {"messages", "0xffff88001cc27940", 1}, {"authlog", "0xffff88001cc26598", 3}, {"utmp", "0xffff88001b63daf0", 2}} {
		t.Run(sample.label, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-inodepages-"+sample.label+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var ref []map[string]any
			if err = json.Unmarshal(raw, &ref); err != nil || len(ref) != sample.count {
				t.Fatal(len(ref), err)
			}
			n := 0
			result, err := e.Run(ctx, "linux.inodepages", map[string]string{"inode": sample.inode, "dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
				c := row.Cells
				if c["RecordType"].String() == "summary" {
					if c["Error"].Kind != "missing" || c["Error"].Error != "" {
						t.Fatal(c)
					}
					return nil
				}
				if n >= len(ref) {
					t.Fatal("extra page")
				}
				want := ref[n]
				n++
				for _, name := range []string{"PageVAddr", "PagePAddr", "MappingAddr"} {
					v, er := c[name].Uint()
					if er != nil {
						t.Fatal(er)
					}
					if name != "PagePAddr" {
						v &= 0xffffffffffff
					}
					if v != uint64(want[name].(float64)) {
						t.Fatal(name, c[name], want[name])
					}
				}
				for _, name := range []string{"Index", "Flags", "DumpSafe"} {
					if c[name].String() != fmt.Sprint(want[name]) {
						t.Fatal(name, c[name], want[name])
					}
				}
				if c["Captured"].Data != true || c["Error"].Error != "" {
					t.Fatal(c)
				}
				return nil
			}})
			if err != nil || n != sample.count || result.Task.Rows != int64(n+1) {
				t.Fatal(result, n, err)
			}
			manifestRaw, err := os.ReadFile(filepath.Join(dir, "reference-linux-inodepages-"+sample.label+".manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Image     string `json:"image_sha256"`
				Extracted []struct {
					Size string `json:"size"`
					SHA  string `json:"sha256"`
				} `json:"extracted_files"`
			}
			if err = json.Unmarshal(manifestRaw, &manifest); err != nil || manifest.Image != e.Hash || len(manifest.Extracted) != 1 {
				t.Fatal(manifest, err)
			}
			files, err := e.Store.Artifacts(ctx, result.Task.ID)
			if err != nil || len(files) != 1 || files[0].SHA256 != manifest.Extracted[0].SHA || files[0].Size != manifest.Extracted[0].Size {
				t.Fatal(files, manifest, err)
			}
			if err = e.Store.VerifyTaskArtifacts(ctx, result.Task.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
