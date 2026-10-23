package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestHTTPImageAnalysisAndCacheIdentity(t *testing.T) {
	fixture, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture.Image)
	if err != nil {
		t.Fatal(err)
	}
	var changed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := `"snapshot1"`
		if changed.Load() {
			tag = `"snapshot2"`
		}
		w.Header().Set("ETag", tag)
		http.ServeContent(w, r, "memory.raw", time.Time{}, bytes.NewReader(data))
	}))
	defer server.Close()
	config := engine.Config{Image: server.URL + "/memory.raw?token=sensitive", CaseDir: t.TempDir(), Symbols: fixture.Symbols, OS: "linux", DTB: fixture.DTB, Arch: "x64", KernelBase: fixture.KernelBase}
	e, err := engine.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	sum := sha256.Sum256(data)
	if e.Hash != hex.EncodeToString(sum[:]) {
		t.Fatal("remote digest mismatch")
	}
	rows := 0
	first, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{Emit: func(evidence.Row) error { rows++; return nil }})
	if err != nil || rows == 0 {
		t.Fatal(first, rows, err)
	}
	cached, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != first.Task.ID {
		t.Fatal(cached, err)
	}
	verification, err := e.Store.VerifyCase(context.Background(), "")
	if err != nil {
		t.Fatal(verification, err)
	}
	changed.Store(true)
	if _, err = e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{}); err == nil {
		t.Fatal("replayed cache after HTTP image changed")
	}
	changed.Store(false)
	cached, err = e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{Emit: func(evidence.Row) error { changed.Store(true); return nil }})
	if err == nil || !cached.Reused {
		t.Fatal("version changed during cache replay", cached, err)
	}
	changed.Store(false)
	partial, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{Fresh: true, Emit: func(evidence.Row) error { changed.Store(true); return nil }})
	if err == nil || partial.Task.State != "failed" || partial.Task.Rows == 0 {
		t.Fatal("version changed during analysis", partial, err)
	}
	verification, err = e.Store.VerifyCase(context.Background(), "")
	if err != nil || !verification.Verified {
		t.Fatal(verification, err)
	}
	config.Offline = true
	if offline, err := engine.Open(context.Background(), config); err == nil {
		offline.Close()
		t.Fatal("opened remote offline")
	}
}

// This checks transport equivalence on the real acquisition, not upstream parity.
func TestOfficialHTTPSource(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional real acquisition HTTP/local transport comparison")
	}
	image := filepath.Join(dir, "linux-sample-1.bin")
	const digest = "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, err := os.Open(image)
		if err != nil {
			t.Error(err)
			http.Error(w, "unavailable", 500)
			return
		}
		defer file.Close()
		w.Header().Set("ETag", `"`+digest+`"`)
		http.ServeContent(w, r, "acquisition.raw", time.Time{}, file)
	}))
	defer server.Close()
	var reference [][]byte
	for _, location := range []string{image, server.URL + "/acquisition.raw"} {
		e, err := engine.Open(context.Background(), engine.Config{Image: location, Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz", CaseDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if e.Hash != digest {
			e.Close()
			t.Fatal("corpus drift", e.Hash)
		}
		var rows [][]byte
		result, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{Emit: func(row evidence.Row) error { b, err := json.Marshal(row.Cells); rows = append(rows, b); return err }})
		if err != nil {
			e.Close()
			t.Fatal(err)
		}
		if len(rows) != 133 {
			e.Close()
			t.Fatal("process count", len(rows))
		}
		if reference == nil {
			reference = rows
		} else {
			for i := range rows {
				if !bytes.Equal(rows[i], reference[i]) {
					t.Errorf("HTTP/local cells differ at %d", i)
				}
			}
		}
		cached, err := e.Run(context.Background(), "linux.pslist", nil, engine.RunOptions{})
		if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
			e.Close()
			t.Fatal(cached, err)
		}
		verification, err := e.Store.VerifyCase(context.Background(), "")
		e.Close()
		if err != nil || !verification.Verified {
			t.Fatal(verification, err)
		}
	}
	t.Log("512MiB acquisition SHA-256 and all 133 ordered process cells match local transport; sealed case and cache verified")
}
