package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxELFExtraction(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected legacy x64 ELF comparison, not full capability acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("corpus hash drift")
	}
	for _, layout := range []string{"mapped", "reference"} {
		var main evidence.Artifact
		entities, diagnostics, files := 0, 0, 0
		r, err := e.Run(ctx, "linux.elfs", map[string]string{"pid": "3476", "dump": "true", "elf-layout": layout}, engine.RunOptions{Emit: func(row evidence.Row) error {
			c := row.Cells
			if c["RecordType"].String() == "diagnostic" {
				diagnostics++
				return nil
			}
			entities++
			if c["FileOutput"].Kind == "artifact" {
				files++
				a := c["FileOutput"].Data.(evidence.Artifact)
				start, _ := c["Start"].Uint()
				if start == 0x400000 {
					main = a
				}
			}
			return nil
		}})
		if err == nil || r.Task.State != "failed" || r.Task.Rows != 19 || entities != 9 || diagnostics != 10 {
			t.Fatal(layout, r, entities, diagnostics, err)
		}
		wantFiles, wantHash, wantMissing := 9, "0aefd962d02d5bffa10b8097edf7bb45ab132ee023597bfd55e998cf2e62af55", "32768"
		if layout == "reference" {
			wantFiles, wantHash, wantMissing = 8, "61d9e6520ef1b93e440f9c235baca40cac8a44cd938a93019acb62f220d02cb9", "45056"
		}
		if files != wantFiles || main.Size != "45056" || main.SHA256 != wantHash || main.MissingBytes != wantMissing {
			t.Fatal(layout, files, main)
		}
		if err = e.Store.VerifyTaskArtifacts(ctx, r.Task.ID); err != nil {
			t.Fatal(err)
		}
		var process evidence.Row
		result, err := e.Run(ctx, "linux.pslist", map[string]string{"pid": "3476", "dump": "true", "elf-layout": layout}, engine.RunOptions{Emit: func(row evidence.Row) error { process = row; return nil }})
		if err != nil || result.Task.Rows != 1 || process.Cells["FileOutput"].Kind != "artifact" {
			t.Fatal(result, process, err)
		}
		a := process.Cells["FileOutput"].Data.(evidence.Artifact)
		if a.SHA256 != main.SHA256 || a.MissingBytes != main.MissingBytes {
			t.Fatal(a, main)
		}
	}
}
