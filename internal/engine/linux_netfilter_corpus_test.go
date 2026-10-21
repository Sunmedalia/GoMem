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
)

func TestOfficialLinuxNetfilter(t *testing.T) {
	dir, ref := os.Getenv("GOMEM_CORPUS_DIR"), os.Getenv("GOMEM_NETFILTER_REFERENCE")
	if dir == "" || ref == "" {
		t.Skip("requires GOMEM_CORPUS_DIR and GOMEM_NETFILTER_REFERENCE; not acceptance")
	}
	raw, err := os.ReadFile(ref + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Baseline struct{ Commit string }
		Image    string `json:"image_sha256"`
		Output   string `json:"output_sha256"`
		Plugin   string
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Baseline.Commit != "881e970121c16f0932fb9d16fbd5fb258cbcbf75" || manifest.Plugin != "linux.malware.netfilter" {
		t.Fatal(manifest, err)
	}
	raw, err = os.ReadFile(ref + ".json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	var reference []json.RawMessage
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 0 || hex.EncodeToString(sum[:]) != manifest.Output {
		t.Fatal(string(raw), err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != manifest.Image || e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	var fresh, replay bytes.Buffer
	heads, hooks, captures := 0, 0, 0
	result, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			t.Fatal(err)
		}
		switch row.Cells["RecordType"].String() {
		case "netfilter_hook":
			hooks++
		case "netfilter_list":
			heads++
			captures += verifyModuleParameterWireCaptures(t, e, row.Cells["FieldEvidence"])
		}
		return json.NewEncoder(&fresh).Encode(row)
	}})
	if err != nil || result.Task.State != "completed" || heads != 25 || hooks != 0 || captures != 25 {
		t.Fatal(result, err, heads, hooks, captures)
	}
	cached, err := e.Run(context.Background(), "linux.netfilter", nil, engine.RunOptions{Emit: func(row evidence.Row) error { return json.NewEncoder(&replay).Encode(row) }})
	if err != nil || !cached.Reused || !bytes.Equal(fresh.Bytes(), replay.Bytes()) {
		t.Fatal(cached, err)
	}
	t.Logf("25 empty heads reread; zero hooks match pinned negative control; %d total source/list rows", result.Task.Rows)
}
