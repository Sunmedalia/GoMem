package wingui_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/wingui"
)

// This optional control consumes original plugin addresses. It verifies names,
// not native pool discovery, ordering, completeness, or plugin integration.
func verifyGUINameCorpus(t *testing.T, table symbols.SymbolTable, base uint64, spaces map[uint64]memory.MemoryLayer, imageHash string) {
	t.Helper()
	path := os.Getenv("GOMEM_GUI_NAMES_REFERENCE")
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline     struct{ Commit string }
		ImageSHA256  string `json:"image_sha256"`
		OutputSHA256 string `json:"output_sha256"`
		Plugin       string
	}
	data, err := os.ReadFile(strings.TrimSuffix(path, ".json") + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.ImageSHA256 != imageHash || manifest.OutputSHA256 != hex.EncodeToString(digest[:]) || manifest.Plugin != "windows.windowstations" {
		t.Fatal("GUI names reference identity mismatch")
	}
	var rows []struct {
		Offset, SessionID uint64
		Name              string
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("positive GUI name control requires original rows")
	}
	selection, err := wingui.Select(table)
	if err != nil {
		t.Fatal(err)
	}
	baseline := os.Getenv("GOMEM_BASELINE_DIR")
	if baseline == "" {
		t.Fatal("GOMEM_BASELINE_DIR required for original GUI layout")
	}
	data, err = os.ReadFile(filepath.Join(baseline, "volatility3/framework/symbols/windows/gui", selection.Name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := wingui.ParseLayout(data)
	if err != nil {
		t.Fatal(err)
	}
	// Check the same bytes through the compiled catalog digest, using its offline
	// cache contract; never silently accept an edited baseline layout.
	sum := sha256.Sum256(data)
	cache := t.TempDir()
	if err = os.WriteFile(filepath.Join(cache, selection.Name+"-"+hex.EncodeToString(sum[:])+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = wingui.Load(context.Background(), cache, selection.Name, true); err != nil {
		t.Fatal(err)
	}
	var reads, failures, bytes uint64
	for _, row := range rows {
		layer, ok := spaces[row.SessionID]
		if !ok {
			t.Fatalf("no session %d for original station", row.SessionID)
		}
		audit := &guiSessionCorpusAudit{MemoryLayer: layer, t: t}
		reader := wingui.Reader{Layer: audit, KernelSymbols: table, Layout: layout, KernelBase: base}
		at := row.Offset
		if at&(1<<47) != 0 {
			at |= 0xffff000000000000
		}
		info, cause := reader.StationInfo(context.Background(), at)
		if cause != nil || info.Name == nil || info.Session == nil || *info.Name != row.Name || *info.Session != row.SessionID {
			t.Fatalf("GUI station 0x%x differs: %+v, %v; want %q session %d", at, info, cause, row.Name, row.SessionID)
		}
		reads += audit.Reads
		failures += audit.Failures
		bytes += audit.Bytes
	}
	audit := map[string]any{"reference_sha256": hex.EncodeToString(digest[:]), "image_sha256": imageHash, "layout": selection.Name, "layout_sha256": layout.SHA256, "rows": len(rows), "session_reads_verified": reads, "session_bytes_verified": bytes, "session_read_failures": failures, "scope": "Original-selected station names/session IDs only; no native pool discovery or sealed evidence"}
	data, err = json.MarshalIndent(audit, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if path := os.Getenv("GOMEM_GUI_NAMES_AUDIT"); path != "" {
		if err = os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
