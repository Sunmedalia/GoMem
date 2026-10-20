package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxEnvars(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional locked legacy Linux environments; full capability acceptance pending")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-envars.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref []struct {
		PID, PPID        int
		COMM, KEY, VALUE string
	}
	if err = json.Unmarshal(raw, &ref); err != nil || len(ref) != 1402 {
		t.Fatal(len(ref), err)
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{
		Image:   filepath.Join(dir, "linux-sample-1.bin"),
		Symbols: filepath.Join(dir, "linux.zip") + "#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz",
		CaseDir: t.TempDir(),
		OS:      "linux",
		DTB:     "0x1605000",
		Offline: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var got [][5]string
	var summary evidence.Row
	var diagnostics int
	result, err := e.Run(ctx, "linux.envars", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "summary":
			summary = row
		case "variable":
			got = append(got, [5]string{row.Cells["PID"].String(), row.Cells["PPID"].String(), row.Cells["COMM"].String(), row.Cells["Key"].String(), row.Cells["Value"].String()})
		case "diagnostic":
			diagnostics++
		default:
			t.Fatal(row.Cells["RecordType"])
		}
		return nil
	}})
	if err == nil || result.Task.State != "failed" || diagnostics != 11 || len(got) != len(ref) {
		t.Fatal(result.Task.State, diagnostics, len(got), err)
	}
	for i, want := range ref {
		if got[i] != [5]string{strconv.Itoa(want.PID), strconv.Itoa(want.PPID), want.COMM, want.KEY, want.VALUE} {
			t.Fatal(i, got[i], want)
		}
	}
	coverage, _ := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["variables"] != "1402" || coverage["kernel_threads"] != "39" || coverage["user_tasks"] != "94" || coverage["diagnostics"] != "11" {
		t.Fatal(coverage)
	}
}
