package wingui_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/wingui"
)

type guiSessionCorpusRow struct {
	Session    uint64 `json:"session"`
	CR3        string `json:"cr3"`
	Probe      string `json:"probe,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}
type guiSessionCorpusAudit struct {
	memory.MemoryLayer
	t                      *testing.T
	Reads, Bytes, Failures uint64
}

func (a *guiSessionCorpusAudit) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	n, err := a.MemoryLayer.ReadAt(ctx, p, at)
	a.Reads++
	a.Bytes += uint64(max(n, 0))
	if err != nil || n != len(p) {
		a.Failures++
	}
	other := make([]byte, len(p))
	count, cause := a.MemoryLayer.ReadAt(ctx, other, at)
	if n < 0 || n > len(p) || n != count || (err == nil) != (cause == nil) || !bytes.Equal(p[:n], other[:count]) {
		a.t.Fatalf("independent GUI source reread differs at 0x%x", at)
	}
	return n, err
}
func TestGUISessionsCorpusOriginalMapAndReadAudit(t *testing.T) {
	imagePath := os.Getenv("GOMEM_GUI_SESSION_IMAGE")
	symbolPath := os.Getenv("GOMEM_GUI_SESSION_SYMBOLS")
	referencePath := os.Getenv("GOMEM_GUI_SESSION_REFERENCE")
	if imagePath == "" || symbolPath == "" || referencePath == "" {
		t.Skip("set GOMEM_GUI_SESSION_IMAGE, GOMEM_GUI_SESSION_SYMBOLS and GOMEM_GUI_SESSION_REFERENCE; see docs/windows-gui-sessions.md")
	}
	raw, err := os.ReadFile(referencePath)
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		Commit        string
		ImageSHA256   string `json:"image_sha256"`
		SymbolsSHA256 string `json:"symbols_sha256"`
		KernelDTB     string `json:"kernel_dtb"`
		KernelBase    string `json:"kernel_base"`
		ProbeAddress  string `json:"probe_address"`
		Rows          []guiSessionCorpusRow
		Error         string
	}
	if err = json.Unmarshal(raw, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" {
		t.Fatal("reference baseline mismatch")
	}
	file, err := os.Open(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, hashErr := io.Copy(hash, file)
	_ = file.Close()
	if hashErr != nil || hex.EncodeToString(hash.Sum(nil)) != reference.ImageSHA256 {
		t.Fatal("reference image digest mismatch", hashErr)
	}
	symbolBytes, err := os.ReadFile(symbolPath)
	if err != nil {
		t.Fatal(err)
	}
	symbolHash := sha256.Sum256(symbolBytes)
	if hex.EncodeToString(symbolHash[:]) != reference.SymbolsSHA256 {
		t.Fatal("reference symbols differ")
	}
	table, err := symbols.Parse(symbolBytes)
	if err != nil {
		t.Fatal(err)
	}
	source, err := memory.OpenFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	physical, format, err := memory.Detect(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	dtb, err := strconv.ParseUint(reference.KernelDTB, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	base, err := strconv.ParseUint(reference.KernelBase, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := strconv.ParseUint(reference.ProbeAddress, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	physicalAudit := &guiSessionCorpusAudit{MemoryLayer: physical, t: t}
	translator, err := memory.NewIntelForOS(physicalAudit, dtb, "x64", "windows", 1024)
	if err != nil {
		t.Fatal(err)
	}
	kernel := &memory.Virtual{Physical: physicalAudit, Translator: translator, ID: "gui-session:" + reference.ImageSHA256 + ":kernel"}
	kernelAudit := &guiSessionCorpusAudit{MemoryLayer: kernel, t: t}
	reader := wingui.SessionReader{Kernel: &object.Reader{Layer: kernelAudit, Symbols: table}, Physical: physicalAudit, KernelBase: base}
	rows := []guiSessionCorpusRow{}
	selected := []map[string]any{}
	runErr := reader.Visit(context.Background(), wingui.SessionOptions{MaxProcesses: 131072, MaxSessions: 4096}, func(space wingui.SessionSpace) error {
		row := guiSessionCorpusRow{Session: space.SessionID, CR3: fmt.Sprintf("0x%x", space.RawCR3)}
		selected = append(selected, map[string]any{"session": space.SessionID, "process": fmt.Sprintf("0x%x", space.Process), "pid": space.PID, "session_pointer": fmt.Sprintf("0x%x", space.SessionPointer), "method": space.Method, "raw_cr3": fmt.Sprintf("0x%x", space.RawCR3), "normalized_cr3": fmt.Sprintf("0x%x", space.CR3), "layer": space.Layer.Name()})
		original := &guiSessionCorpusAudit{MemoryLayer: space.Layer, t: t}
		data, cause := memory.Read(context.Background(), original, probe, 16)
		if cause != nil {
			row.ProbeError = "unavailable"
		} else {
			row.Probe = hex.EncodeToString(data)
		}
		rows = append(rows, row)
		return nil
	})
	if !reflect.DeepEqual(rows, reference.Rows) {
		t.Fatalf("native session map differs: %+v vs %+v; native %v; original %s", rows, reference.Rows, runErr, reference.Error)
	}
	if reference.Error != "" && runErr == nil {
		t.Fatal("original failure lost")
	}
	audit := map[string]any{"image_sha256": reference.ImageSHA256, "symbols_sha256": reference.SymbolsSHA256, "format": format, "sessions": len(rows), "rows": rows, "selected": selected, "physical_reads_verified": physicalAudit.Reads, "physical_bytes_verified": physicalAudit.Bytes, "physical_read_failures": physicalAudit.Failures, "kernel_reads_verified": kernelAudit.Reads, "kernel_read_failures": kernelAudit.Failures, "reference_error": reference.Error, "native_error": "", "scope": "Session selection and shared kernel probes; no GUI object or sealed store acceptance"}
	if runErr != nil {
		audit["native_error"] = runErr.Error()
	}
	data, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if path := os.Getenv("GOMEM_GUI_SESSION_AUDIT"); path != "" {
		if err = os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
