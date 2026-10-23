package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// This test-only reader exercises the shared virtual layer, not a new shipped
// analysis plugin. It retains actual backing coordinates with captured bytes.
type pagefileReader struct{}

func (pagefileReader) Spec() plugin.Spec {
	return plugin.Spec{Name: "test.pagefile-reader", NeedsTranslation: true, Columns: []evidence.Column{{Name: "Bytes", Kind: "bytes"}}}
}
func (pagefileReader) Run(ctx context.Context, e plugin.Environment, _ map[string]string, out plugin.Emit) error {
	v := e.Kernel.(*memory.Virtual)
	t, err := v.Resolve(ctx, 0x123)
	if err != nil {
		return err
	}
	b, err := memory.Read(ctx, v, 0x123, 8)
	if err != nil {
		return err
	}
	return out(evidence.Row{Cells: map[string]evidence.Value{"Bytes": evidence.Bytes(b), "Backing": evidence.Text(t.Layer.Name()), "BackingOffset": evidence.Address(t.Offset), "Entry": evidence.Address(t.Entry), "EntryAddress": evidence.Address(t.EntryAddress)}})
}

func pagefileConfig(t *testing.T) engine.Config {
	t.Helper()
	dir := t.TempDir()
	ram := make([]byte, 0x10000)
	for n := 1; n <= 3; n++ {
		binary.LittleEndian.PutUint64(ram[n*4096:], uint64((n+1)*4096)|3)
	}
	binary.LittleEndian.PutUint64(ram[0x4000:], uint64(2)<<32|128)
	file := make([]byte, 0x3000)
	copy(file[0x2123:], "EXTERNAL")
	image := filepath.Join(dir, "memory.raw")
	path := filepath.Join(dir, "captured pagefile.sys")
	if err := os.WriteFile(image, ram, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	return engine.Config{Image: image, Pagefiles: []string{"0=" + path}, OS: "windows", Arch: "x64", DTB: "0x1000", CaseDir: t.TempDir(), Offline: true}
}

func TestPagefileAcquisitionEvidenceCacheAndMutation(t *testing.T) {
	ctx := context.Background()
	cfg := pagefileConfig(t)
	e, err := engine.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Registry.Register(pagefileReader{}); err != nil {
		t.Fatal(err)
	}
	var rows []evidence.Row
	result, err := e.Run(ctx, "test.pagefile-reader", nil, engine.RunOptions{Emit: func(r evidence.Row) error { rows = append(rows, r); return nil }})
	if err != nil || len(rows) != 1 {
		t.Fatal(result, rows, err)
	}
	r := rows[0]
	if err := r.Verify(); err != nil {
		t.Fatal(err)
	}
	if r.Cells["Backing"].String() != "pagefile:0" || r.Cells["BackingOffset"].String() != "0x0000000000002123" {
		t.Fatal(r)
	}
	filePath := cfg.Pagefiles[0][2:]
	file, _ := os.ReadFile(filePath)
	sum := sha256.Sum256(file)
	if r.Provenance.Parameters["engine.pagefiles.0.sha256"] != hex.EncodeToString(sum[:]) || r.Provenance.Parameters["engine.pagefiles.schema"] != "gomem.pagefile-acquisition/v1" || r.Provenance.ImageSHA256 != e.Hash {
		t.Fatal("missing backing identity", r.Provenance)
	}
	data, _ := os.ReadFile(cfg.Image)
	ramSum := sha256.Sum256(data)
	if e.Hash == hex.EncodeToString(ramSum[:]) {
		t.Fatal("pagefile excluded from acquisition identity")
	}
	cached, err := e.Run(ctx, "test.pagefile-reader", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
		t.Fatal(cached, err)
	}
	var cachedRows []evidence.Row
	_, err = e.Run(ctx, "test.pagefile-reader", nil, engine.RunOptions{Emit: func(r evidence.Row) error { cachedRows = append(cachedRows, r); return nil }})
	firstWire, _ := json.Marshal(rows)
	cachedWire, _ := json.Marshal(cachedRows)
	if err != nil || len(cachedRows) != 1 || !bytes.Equal(firstWire, cachedWire) {
		t.Fatal("cached pagefile evidence changed", cachedRows, err)
	}
	verification, err := e.Store.VerifyCase(ctx, "")
	if err != nil || !verification.Verified {
		t.Fatal(verification, err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filePath, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := memory.Read(ctx, e.Env.Kernel, 0x123, 8); err == nil {
		t.Fatal("interactive read exposed changed pagefile bytes")
	}
	if _, err := e.Run(ctx, "test.pagefile-reader", nil, engine.RunOptions{}); err == nil {
		t.Fatal("reused changed pagefile cache")
	}
	oldHash := e.Hash
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	file[0x2123] ^= 1
	if err := os.WriteFile(filePath, file, 0600); err != nil {
		t.Fatal(err)
	}
	newEngine, err := engine.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer newEngine.Close()
	if newEngine.Hash == oldHash {
		t.Fatal("changed pagefile content reused acquisition identity")
	}
	if err := newEngine.Registry.Register(pagefileReader{}); err != nil {
		t.Fatal(err)
	}
	fresh, err := newEngine.Run(ctx, "test.pagefile-reader", nil, engine.RunOptions{})
	if err != nil || fresh.Reused || fresh.Task.ID == result.Task.ID {
		t.Fatal("reused cache across pagefile identities", fresh, err)
	}
}

func TestPagefileInputsValidationAndReadOnlyAliases(t *testing.T) {
	for _, value := range []string{"missing", "16=file", "-1=file", "0=", "0x1=file", "0=file\x00bad"} {
		cfg := pagefileConfig(t)
		cfg.Pagefiles = []string{value}
		if e, err := engine.Open(context.Background(), cfg); err == nil {
			e.Close()
			t.Fatal("accepted", value)
		}
	}
	cfg := pagefileConfig(t)
	cfg.Pagefiles = append(cfg.Pagefiles, cfg.Pagefiles[0])
	if e, err := engine.Open(context.Background(), cfg); err == nil {
		e.Close()
		t.Fatal("duplicate pagefile accepted")
	}
	for _, osName := range []string{"linux", "mac", ""} {
		cfg := pagefileConfig(t)
		cfg.OS = osName
		if e, err := engine.Open(context.Background(), cfg); err == nil {
			e.Close()
			t.Fatal("pagefile applied outside Windows")
		}
	}
	for _, name := range []string{"case.db", "case.db-wal", "case.db-shm", "case.db-journal", "case.lock"} {
		cfg := pagefileConfig(t)
		path := filepath.Join(cfg.CaseDir, name)
		before := []byte("preserve captured pagefile bytes")
		if err := os.WriteFile(path, before, 0600); err != nil {
			t.Fatal(err)
		}
		cfg.Pagefiles = []string{fmt.Sprintf("0=%s", path)}
		if e, err := engine.Open(context.Background(), cfg); err == nil {
			e.Close()
			t.Fatal("pagefile/output alias accepted")
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatal("pagefile modified")
		}
	}
}
