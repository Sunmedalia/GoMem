package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialWindowsPESymbolCommand(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional exact kernel-symbol command control; not broad version acceptance")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-windows-pe-symbols-kernel.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "9ea5473da90c02727700d9a37a6d65491a5b45698bc7aeb16ef45536ba9c89c9" {
		t.Fatal("reference drift")
	}
	var ref []struct {
		Module, Symbol string
		Address        uint64
	}
	if err = json.Unmarshal(raw, &ref); err != nil || len(ref) != 1 {
		t.Fatal(err, len(ref))
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
	p := map[string]string{"source": "kernel", "module": "ntoskrnl.exe", "symbols": `["PsActiveProcessHead"]`}
	var findings []evidence.Row
	reads := 0
	faults := 0
	var captured uint64
	result, err := e.Run(ctx, "windows.pe_symbols", p, engine.RunOptions{Emit: func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "symbol":
			findings = append(findings, row)
		case "memory_read":
			at, _ := row.Cells["Offset"].Uint()
			n, _ := row.Cells["Requested"].Uint()
			layer := e.Env.Kernel
			if row.Provenance.Layer != layer.Name() {
				// Every retained session mapping on this control shares the
				// kernel mapping; rereading the kernel independently checks bytes.
				if at < 0xffff800000000000 {
					t.Fatal("unexpected session user read", at)
				}
			}
			actual, cause := memory.Read(ctx, layer, at, int(n))
			if !bytes.Equal(actual, row.Cells["Raw"].Data.([]byte)) || (cause == nil) != (row.Cells["Error"].Kind == "missing") {
				t.Fatal("independent capture reread", cause)
			}
			if cause != nil {
				faults++
			}
			reads++
			captured += uint64(len(actual))
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || len(findings) != 1 || reads == 0 || faults == 0 {
		t.Fatal(result, err, len(findings), reads)
	}
	got := findings[0]
	at, _ := got.Cells["Address"].Uint()
	if got.Cells["Module"].String() != ref[0].Module || got.Cells["Symbol"].String() != ref[0].Symbol || at&0x0000ffffffffffff != ref[0].Address {
		t.Fatal(got, ref)
	}
	var persisted int
	for offset := 0; ; offset += 1000 {
		rows, cause := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Offset: offset, Limit: 1000})
		if cause != nil {
			t.Fatal(cause)
		}
		for _, row := range rows {
			if cause := row.Verify(); cause != nil {
				t.Fatal(cause)
			}
			persisted++
		}
		if len(rows) < 1000 {
			break
		}
	}
	if int64(persisted) != result.Task.Rows {
		t.Fatal("persisted result count")
	}
	again, err := e.Run(ctx, "windows.pe_symbols", p, engine.RunOptions{})
	if err == nil || again.Reused || again.Task.ID == result.Task.ID {
		t.Fatal("dynamic dependency task replayed", again, err)
	}
	t.Logf("one exact kernel symbol matched with explicit partial task; %d captures / %d bytes / %d read faults independently reread; sealed store and fresh execution verified", reads, captured, faults)
}
