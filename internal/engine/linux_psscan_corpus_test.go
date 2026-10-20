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

func TestOfficialLinuxPhysicalTaskScan(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected legacy x64 task scan; not full capability acceptance")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-psscan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reference []map[string]json.RawMessage
	if err = json.Unmarshal(raw, &reference); err != nil || len(reference) != 321 {
		t.Fatal("reference drift", len(reference), err)
	}
	byAddress := map[uint64]map[string]json.RawMessage{}
	for _, r := range reference {
		var at uint64
		if err = json.Unmarshal(r["OFFSET (P)"], &at); err != nil {
			t.Fatal(err)
		}
		byAddress[at] = r
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("image hash drift")
	}
	tasks, summary, zombies := 0, 0, 0
	active := map[uint64]bool{}
	_, err = e.Run(ctx, "linux.pslist", map[string]string{"threads": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error {
		a, err := row.Cells["PhysicalOffset"].Uint()
		if err != nil {
			return err
		}
		active[a] = true
		return nil
	}})
	if err != nil || len(active) != 316 {
		t.Fatal(len(active), err)
	}
	result, err := e.Run(ctx, "linux.psscan", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		c := row.Cells
		if c["RecordType"].String() == "scan_summary" {
			summary++
			meta := c["Scan"].Data.(map[string]any)
			if meta["pointer_hits"] != "373" || meta["accepted_candidates"] != "321" || meta["complete"] != true {
				t.Fatal(meta)
			}
			return nil
		}
		if c["RecordType"].String() != "task" {
			t.Fatal(row)
		}
		tasks++
		at, _ := c["Offset"].Uint()
		ref := byAddress[at]
		if ref == nil {
			t.Fatal("extra physical candidate", at)
		}
		delete(byAddress, at)
		for _, pair := range [][2]string{{"PID", "PID"}, {"TID", "TID"}, {"PPID", "PPID"}, {"Name", "COMM"}, {"ExitState", "EXIT_STATE"}} {
			want := string(ref[pair[1]])
			if pair[0] == "Name" || pair[0] == "ExitState" {
				if err := json.Unmarshal(ref[pair[1]], &want); err != nil {
					t.Fatal(err)
				}
			} else {
				var n uint64
				if err := json.Unmarshal(ref[pair[1]], &n); err != nil {
					t.Fatal(err)
				}
				want = strconv.FormatUint(n, 10)
			}
			if c[pair[0]].String() != want {
				t.Fatal("candidate field differs", pair, c[pair[0]], want)
			}
		}
		if !active[at] {
			if c["ExitState"].String() != "EXIT_ZOMBIE" {
				t.Fatal("unexpected unlinked running candidate", row)
			}
			zombies++
		}
		return nil
	}})
	if err != nil || result.Task.Rows != 322 || tasks != 321 || summary != 1 || len(byAddress) != 0 || zombies != 5 {
		t.Fatal(result, tasks, summary, zombies, len(byAddress), err)
	}
}
