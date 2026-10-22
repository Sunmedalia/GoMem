package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"encoding/json"
	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsDebugRegisters(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Windows debug-register negative control, not positive acceptance")
	}
	reference, err := os.ReadFile(filepath.Join(dir, "reference-windows-debugregisters.json"))
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
	reads, findings, faults := 0, 0, 0
	var coverage any
	result, err := e.Run(ctx, "windows.debugregisters", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
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
			raw := make([]byte, int(n))
			captured, err := e.Env.Kernel.ReadAt(ctx, raw, at)
			if captured < 0 || captured > len(raw) {
				t.Fatal("invalid reread")
			}
			raw = raw[:captured]
			failed := row.Cells["Error"].Kind != "missing"
			if (err != nil || captured != int(n)) != failed {
				t.Fatal("reread error drift", err, row.Cells["Error"])
			}
			if failed {
				faults++
			}
			if !bytes.Equal(raw, row.Cells["Raw"].Data.([]byte)) {
				t.Fatal("capture reread drift")
			}
		case "summary":
			coverage = row.Cells["Coverage"].Data
		}
		return nil
	}})
	if (err != nil && faults == 0) || findings != 0 || reads == 0 {
		t.Fatal(result, err, reads, findings)
	}
	encoded, _ := json.Marshal(coverage)
	t.Logf("pinned negative control: %d threads reported, %d metadata reads independently reread, %d faults; summary %s", findings, reads, faults, encoded)
}
