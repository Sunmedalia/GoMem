package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

// The six unavailable parameter displays are deliberate diagnostic differences,
// not successful parity. Compare sequence separately from the multiset tooling.
func TestOfficialLinuxLsmodDisplay(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Debian module display differential; not full acceptance")
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal(e.Hash)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-lsmod.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reference []map[string]json.RawMessage
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 79 {
		t.Fatal(err, len(reference))
	}
	failed := map[string]bool{"parport_pc": true, "snd_ens1371": true, "snd_rawmidi": true, "snd_seq": true, "snd": true, "usbhid": true}
	rows, matched, captures, positive := 0, 0, 0, 0
	run := func(r evidence.Row) error {
		if rows >= len(reference) {
			t.Fatal("extra module", r)
		}
		ref := reference[rows]
		rows++
		var offset, size uint64
		var name, taints, args string
		for _, v := range []struct {
			key    string
			target any
		}{{"Offset", &offset}, {"Code Size", &size}, {"Module Name", &name}, {"Taints", &taints}, {"Load Arguments", &args}} {
			if err := json.Unmarshal(ref[v.key], v.target); err != nil {
				t.Fatal(err)
			}
		}
		at, err := r.Cells["Offset"].Uint()
		if err != nil || at&0xffffffffffff != offset {
			t.Fatal("ordered offset", r, err)
		}
		code, err := r.Cells["Code Size"].Uint()
		if err != nil || code != size {
			t.Fatal("code size", r, err)
		}
		if r.Cells["Name"].String() != name || r.Cells["Module Name"].String() != name || r.Cells["Taints"].String() != taints || r.Cells["File Output"].Reason != "not_requested" {
			t.Fatal("display difference", r)
		}
		if failed[name] {
			if r.Cells["Load Arguments"].Reason != "module_arguments_unreadable" || r.Cells["Error"].Error == "" {
				t.Fatal("failure lost", r)
			}
			fields := bashProofFields(t, r.Cells["FieldEvidence"])
			if fields["LoadArgumentsPartial"].Kind != "string" {
				t.Fatal("partial display lost", fields)
			}
		} else {
			if r.Cells["Load Arguments"].Kind != "string" || r.Cells["Load Arguments"].String() != args {
				t.Fatal("arguments", r, args)
			}
			matched++
			if args != "" {
				positive++
			}
			captures += verifyModuleParameterWireCaptures(t, e, r.Cells["FieldEvidence"])
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		rows, matched, captures, positive = 0, 0, 0, 0
		result, err := e.Run(context.Background(), "linux.lsmod", nil, engine.RunOptions{Emit: run})
		if err == nil || result.Task.State != "failed" || result.Reused || rows != 79 || matched != 73 || captures < 500 || positive < 1 {
			t.Fatal(result, err, rows, matched, captures, positive)
		}
	}
	t.Log(fmt.Sprintf("79 ordered module identities/code sizes/taints; 73 exact displays (%d positive arguments); 6 explicit failures; %d raw captures reread; failed task rerun", positive, captures))
}
