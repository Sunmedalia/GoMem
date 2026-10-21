package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxProcessSpoofing(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Linux x64 process-spoofing differential; not full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("corpus drift", e.Hash)
	}
	for _, filtered := range []bool{false, true} {
		t.Run(fmt.Sprint(filtered), func(t *testing.T) {
			params := map[string]string{}
			reference := "reference-linux-process-spoofing.json"
			wantRows := 133
			if filtered {
				params["pid"] = "1,2388,2575,3754,8503"
				reference = "reference-linux-process-spoofing-filtered.json"
				wantRows = 5
			}
			result, err := e.Run(ctx, "linux.process_spoofing", params, engine.RunOptions{})
			if err != nil || result.Task.State != "completed" {
				t.Fatal(result, err)
			}
			rows, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 500})
			if err != nil || len(rows) != wantRows+1 {
				t.Fatal(len(rows), err)
			}
			native := filepath.Join(t.TempDir(), "native.jsonl")
			file, err := os.Create(native)
			if err != nil {
				t.Fatal(err)
			}
			enc := json.NewEncoder(file)
			errorsByStage := map[string]int{}
			cmd, comm := 0, 0
			for _, row := range rows {
				if err = row.Verify(); err != nil {
					t.Fatal(err)
				}
				if row.Cells["Cmdline_Spoofed"].Data == true {
					cmd++
				}
				if row.Cells["Comm_Spoofed"].Data == true {
					comm++
				}
				if row.Cells["Error"].Kind == "structure" {
					raw, _ := json.Marshal(row.Cells["Error"].Data)
					var issues []evidence.Value
					if err = json.Unmarshal(raw, &issues); err != nil {
						t.Fatal(err)
					}
					for _, issue := range issues {
						if issue.Error == "" {
							t.Fatal(issue)
						}
						errorsByStage[issue.Reason]++
					}
				}
				if err = enc.Encode(row); err != nil {
					t.Fatal(err)
				}
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			reportPath := filepath.Join(t.TempDir(), "diff.json")
			command := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, reference), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.process_spoofing.json"), "--output", reportPath)
			output, cmdErr := command.CombinedOutput()
			raw, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(cmdErr, string(output), err)
			}
			var report struct {
				Matched       bool `json:"matched"`
				NativeRows    int  `json:"native_rows"`
				ReferenceRows int  `json:"reference_rows"`
			}
			if err = json.Unmarshal(raw, &report); err != nil {
				t.Fatal(err)
			}
			if !report.Matched || report.NativeRows != wantRows || report.ReferenceRows != wantRows {
				t.Fatal(string(raw), string(output), cmdErr)
			}
			coverage := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
			expected := map[string]string{"processes": "133", "cmdline_compared": "92", "comm_compared": "94", "cmdline_mismatches": "9", "comm_mismatches": "2", "diagnostics": "2"}
			if filtered {
				expected = map[string]string{"processes": "5", "cmdline_compared": "4", "comm_compared": "5", "cmdline_mismatches": "4", "comm_mismatches": "2", "diagnostics": "1"}
			}
			for key, want := range expected {
				if coverage[key] != want {
					t.Fatal(key, coverage)
				}
			}
			if cmd != 9 && !filtered || comm != 2 || errorsByStage["argument_prefix_only"] != 2 && !filtered {
				t.Fatal(cmd, comm, errorsByStage)
			}
			again, err := e.Run(ctx, "linux.process_spoofing", params, engine.RunOptions{})
			if err != nil || !again.Reused {
				t.Fatal(again, err)
			}
			t.Logf("coverage %v diagnostics %v", coverage, errorsByStage)
		})
	}
}
