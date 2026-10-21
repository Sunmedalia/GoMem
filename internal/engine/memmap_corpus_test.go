package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsMemmap(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 process memory map; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-memmap-pid2968.json")
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.memmap", map[string]string{"pid": "2968"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, len(rows), err)
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	out, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(out)
	maps := 0
	var coverage map[string]any
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "summary" {
			coverage, _ = row.Cells["Coverage"].Data.(map[string]any)
			if err = enc.Encode(row); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if row.Cells["RecordType"].String() != "map" {
			t.Fatalf("unexpected %s", row.Cells["RecordType"])
		}
		maps++
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.memmap.json"), "--output", reportPath)
	if output, err := cmd.CombinedOutput(); err != nil && len(output) > 0 {
		t.Logf("%s", output)
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Matched       bool             `json:"matched"`
		NativeRows    int              `json:"native_rows"`
		ReferenceRows int              `json:"reference_rows"`
		Missing       []map[string]any `json:"missing"`
		Extra         []map[string]any `json:"extra"`
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Matched {
		limit := 2
		if len(report.Missing) < limit {
			limit = len(report.Missing)
		}
		extraLimit := 2
		if len(report.Extra) < extraLimit {
			extraLimit = len(report.Extra)
		}
		t.Fatalf("maps %d coverage %v native %d reference %d missing %d extra %d\nmissing %v\nextra %v", maps, coverage, report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra), report.Missing[:limit], report.Extra[:extraLimit])
	}
	if maps != 74969 || coverage["selected"] != "1" || coverage["rows"] != "74969" || coverage["bytes"] != "415870976" || coverage["pid"] != "2968" || coverage["empty"] != "0" || coverage["dtb_unreadable"] != "0" || coverage["dump_errors"] != "0" || coverage["name_unreadable"] != "0" || coverage["pid_unreadable"] != "0" {
		t.Fatalf("maps %d coverage %v", maps, coverage)
	}
	t.Logf("maps %d coverage %v", maps, coverage)
}

func TestOfficialWindowsMemmapDump(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 process memory map; not full capability acceptance")
	}
	reference := filepath.Join(dir, "reference-windows-memmap-pid2968-dump.json")
	caseDir := t.TempDir()
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: caseDir, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var rows []evidence.Row
	result, err := e.Run(ctx, "windows.memmap", map[string]string{"pid": "2968", "dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		rows = append(rows, row)
		return nil
	}})
	if err != nil || result.Task.State != "completed" {
		t.Fatal(result.Task.State, len(rows), err)
	}
	native := filepath.Join(t.TempDir(), "native.jsonl")
	out, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(out)
	for _, row := range rows {
		if err = enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	cmd := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference, "--mapping", filepath.Join("..", "..", "docs", "diff", "windows.memmap.json"), "--output", reportPath)
	if output, err := cmd.CombinedOutput(); err != nil && len(output) > 0 {
		t.Logf("%s", output)
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Matched       bool             `json:"matched"`
		NativeRows    int              `json:"native_rows"`
		ReferenceRows int              `json:"reference_rows"`
		Missing       []map[string]any `json:"missing"`
		Extra         []map[string]any `json:"extra"`
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Matched {
		t.Fatalf("native %d reference %d missing %d extra %d", report.NativeRows, report.ReferenceRows, len(report.Missing), len(report.Extra))
	}
	var dumped string
	err = filepath.Walk(caseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if info.Name() == "pid.2968.dmp" {
			dumped = path
		}
		return nil
	})
	if err != nil || dumped == "" {
		t.Fatal(dumped, err)
	}
	f, err := os.Open(dumped)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sum := sha256.New()
	n, err := io.Copy(sum, f)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	const want = "09f08a08628f23c88482e50920ee474711f2c855d8498fdac8e2094aab32ba50"
	if n != 415870976 || got != want {
		t.Fatalf("dump bytes %d sha256 %s", n, got)
	}
}
