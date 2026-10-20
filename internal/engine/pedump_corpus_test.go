package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
)

func TestOfficialPEReconstruction(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected PE reconstruction; not full acceptance")
	}
	for _, tc := range []struct {
		base                  string
		kernel                bool
		size, missing, digest string
	}{
		{"0x7ff8271d0000", false, "204800", "200704", "fa7c00d5763a114adb4a6e572fe1c0efa241f1b77c74e1bed159ce6400d6e351"},
		{"0xfffff8043601f000", true, "17063936", "8347648", "ef644d9319a50413a914e42be14c3a2b78fc03a37650010ba7115cee00cd80bc"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			ctx := context.Background()
			e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
				t.Fatal("image drift", e.Hash)
			}
			parameters := map[string]string{"base": tc.base, "pid": "4"}
			if tc.kernel {
				parameters = map[string]string{"base": tc.base, "kernel-module": "true"}
			}
			r, err := e.Run(ctx, "windows.pedump", parameters, engine.RunOptions{})
			if err != nil || r.Task.Rows != 1 {
				t.Fatal(r, err)
			}
			files, err := e.Store.Artifacts(ctx, r.Task.ID)
			if err != nil || len(files) != 1 {
				t.Fatal(files, err)
			}
			a := files[0]
			if a.Size != tc.size || a.MissingBytes != tc.missing || a.SHA256 != tc.digest || a.State != "completed_with_gaps" {
				t.Fatal(a)
			}
			if err = e.Store.VerifyTaskArtifacts(ctx, r.Task.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOfficialDLLPEReconstruction(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected DLL PE extraction; not full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	r, err := e.Run(ctx, "windows.dlllist", map[string]string{"pid": "488", "base": "0x7ff66e1d0000", "dump": "true"}, engine.RunOptions{})
	if err != nil || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	files, err := e.Store.Artifacts(ctx, r.Task.ID)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	a := files[0]
	if a.Size != "28672" || a.MissingBytes != "16384" || a.SHA256 != "abdc0769d35ed4f36912e5d4f5823e22abec4ccd3139db57bde9ee511bb6c269" {
		t.Fatal(a)
	}
	if err = e.Store.VerifyTaskArtifacts(ctx, r.Task.ID); err != nil {
		t.Fatal(err)
	}
}
