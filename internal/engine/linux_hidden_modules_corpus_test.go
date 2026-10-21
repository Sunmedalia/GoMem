package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxHiddenModules(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	reference := os.Getenv("GOMEM_HIDDEN_MODULES_REFERENCE")
	if dir == "" || reference == "" {
		t.Skip("optional hidden-module corpus requires GOMEM_CORPUS_DIR and GOMEM_HIDDEN_MODULES_REFERENCE; not full acceptance")
	}
	raw, err := os.ReadFile(reference + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline struct{ Commit string }
		Image    string `json:"image_sha256"`
		Plugin   string
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.malware.hidden_modules" {
		t.Fatal(manifest, err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash, manifest.Image)
	}
	var fresh, replay bytes.Buffer
	check := func(rows []evidence.Row) {
		if len(rows) != 1 || rows[0].Cells["RecordType"].String() != "hidden_scan_summary" {
			t.Fatal(len(rows), rows)
		}
		if err := rows[0].Verify(); err != nil {
			t.Fatal(err)
		}
		fields := bashProofFields(t, rows[0].Cells["Coverage"])
		hidden, _ := fields["hidden"].Uint()
		known, _ := fields["known_modules"].Uint()
		excluded, _ := fields["excluded"].Uint()
		step, _ := fields["step"].Uint()
		low, _ := fields["low"].Uint()
		high, _ := fields["high"].Uint()
		positions, _ := fields["positions"].Uint()
		if hidden != 0 || known != 79 || excluded != 79 || step != 8 || high <= low || positions != (high-low-1)/step+1 || fields["rejected"].String() != "22" || fields["unreadable"].String() != "79919" || fields["self_matches"].String() != "22" {
			t.Fatal(fields)
		}
	}
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "linux.hidden_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		rows = append(rows, row)
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || result.Task.Rows != 1 {
		t.Fatal(result, err)
	}
	check(rows)
	native := filepath.Join(t.TempDir(), "native.jsonl")
	if err = os.WriteFile(native, nil, 0600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "diff.json")
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", reference+".json", "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.hidden_modules.json"), "--output", reportPath).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	reportRaw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct{ Matched bool }
	if err = json.Unmarshal(reportRaw, &report); err != nil || !report.Matched {
		t.Fatal(string(reportRaw), err)
	}
	rows = nil
	cached, err := e.Run(context.Background(), "linux.hidden_modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		rows = append(rows, row)
		return json.NewEncoder(&replay).Encode(row)
	}})
	if err != nil || !cached.Reused || !bytes.Equal(fresh.Bytes(), replay.Bytes()) {
		t.Fatal(cached, err)
	}
	check(rows)
}
