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
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestOfficialLinuxIDT(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian IDT differential; not full capability acceptance")
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
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-idt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected []struct {
		Index, Address uint64
		Module, Symbol string
	}
	if err = json.Unmarshal(raw, &expected); err != nil || len(expected) != 21 {
		t.Fatal(err, len(expected))
	}
	selected, captures, records := 0, 0, 0
	native := filepath.Join(t.TempDir(), "native.jsonl")
	file, err := os.Create(native)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	result, err := e.Run(ctx, "linux.check_idt", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		records++
		if err := encoder.Encode(r); err != nil {
			return err
		}
		if r.Cells["Error"].Reason != "not_applicable" {
			t.Fatal(r.Cells["Error"])
		}
		switch r.Cells["RecordType"].String() {
		case "idt_entry":
			if selected >= len(expected) {
				t.Fatal("extra IDT entry")
			}
			want := expected[selected]
			selected++
			idx, _ := r.Cells["Index"].Uint()
			at, _ := r.Cells["Address"].Uint()
			if idx != want.Index || at != want.Address || r.Cells["Module"].String() != want.Module || r.Cells["Symbol"].String() != want.Symbol {
				t.Fatal(want, idx, at, r.Cells["Module"], r.Cells["Symbol"])
			}
			if r.Cells["DescriptorType"].String() != "gate_struct64" {
				t.Fatal(r.Cells["DescriptorType"])
			}
			entry, _ := r.Cells["EntryAddress"].Uint()
			if entry != 0xffffffff8172e000+idx*16 {
				t.Fatal(entry)
			}
		case "summary":
			coverage := r.Cells["Coverage"].Data.(map[string]any)
			for k, v := range map[string]string{"checked_entries": "21", "zero_entries": "0", "unattributed_entries": "0", "missing_exact_symbols": "0", "unreadable_entries": "0", "read_layout_errors": "0", "descriptor_size": "16", "overlapping_matches": "0"} {
				if coverage[k] != v {
					t.Fatal(k, coverage)
				}
			}
		case "module_observation", "sysfs_candidate", "source_selection", "scan_candidate", "source_observation":
		default:
			t.Fatal("unexpected record", r.Cells["RecordType"])
		}
		if fields, ok := r.Cells["FieldEvidence"].Data.(map[string]evidence.Value); ok {
			for key, proof := range fields {
				if c, ok := proof.Data.(map[string]evidence.Value); ok && c["Raw"].Kind == "bytes" {
					at, err := c["Address"].Uint()
					raw := c["Raw"].Data.([]byte)
					actual, readErr := memory.Read(ctx, e.Env.Kernel, at, len(raw))
					if err != nil || readErr != nil || !bytes.Equal(raw, actual) || c["ReadComplete"].Data != true {
						t.Fatal(key, err, readErr)
					}
					captures++
				}
			}
		}
		return nil
	}})
	if err != nil || result.Task.State != "completed" || selected != 21 || records != 570 || captures != 1899 {
		t.Fatal(result, err, selected, records)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("python3", filepath.Join("..", "..", "tools", "diff_results.py"), "--native", native, "--reference", filepath.Join(dir, "reference-linux-idt.json"), "--mapping", filepath.Join("..", "..", "docs", "diff", "linux.check_idt.json")).CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	stored, err := e.Store.Query(ctx, evidence.Query{TaskID: result.Task.ID, Limit: 1000})
	if err != nil || len(stored) != records {
		t.Fatal(err, len(stored), records)
	}
	for _, r := range stored {
		if err = r.Verify(); err != nil {
			t.Fatal(err)
		}
	}
	cached, err := e.Run(ctx, "linux.check_idt", nil, engine.RunOptions{})
	if err != nil || !cached.Reused || cached.Task.ID != result.Task.ID {
		t.Fatal(cached, err)
	}
	t.Logf("21 IDT entries match four fields and order; %d raw captures independently reread; all handlers attributed to kernel with exact symbols; sealed rows and cache reused", captures)
}
