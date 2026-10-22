package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialWindowsSuspendedThreads(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Windows suspended-thread negative control, not positive acceptance")
	}
	reference, err := os.ReadFile(filepath.Join(dir, "reference-windows-suspended-threads.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(reference)
	if hex.EncodeToString(sum[:]) != "a3cbe01dad52836a7ac8efc91954cf64867f4dee8a6f046c4bb0838d11f48589" {
		t.Fatal("reference drift")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
		t.Fatal("image drift")
	}
	reads, findings := 0, 0
	var coverage any
	result, err := e.Run(ctx, "windows.suspended_threads", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "thread":
			findings++
		case "memory_read":
			reads++
			at, err := row.Cells["Offset"].Uint()
			if err != nil {
				t.Fatal(err)
			}
			n, err := row.Cells["Requested"].Uint()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := memory.Read(ctx, e.Env.Kernel, at, int(n))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, row.Cells["Raw"].Data.([]byte)) {
				t.Fatal("capture reread drift")
			}
		case "summary":
			coverage = row.Cells["Coverage"].Data
		}
		return nil
	}})
	if err != nil || findings != 0 || reads == 0 {
		t.Fatal(result, err, reads, findings)
	}
	t.Logf("pinned negative control: %d threads reported, %d metadata reads independently reread; summary %+v", findings, reads, coverage)
}
