package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxLsof(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional legacy Linux/x64 descriptors; full capability acceptance pending")
	}
	file, err := os.Open(filepath.Join(dir, "reference-linux-lsof.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.UseNumber()
	var reference []map[string]any
	if err = decoder.Decode(&reference); err != nil || len(reference) != 3795 {
		t.Fatal("reference drift", len(reference), err)
	}
	key := func(pid, tid, fd string) string { return pid + ":" + tid + ":" + fd }
	byKey := map[string]map[string]any{}
	for _, r := range reference {
		byKey[key(fmt.Sprint(r["PID"]), fmt.Sprint(r["TID"]), fmt.Sprint(r["FD"]))] = r
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("image hash drift")
	}
	common, extra, spaces := 0, 0, 0
	result, err := e.Run(context.Background(), "linux.lsof", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		c := row.Cells
		ref := byKey[key(c["PID"].String(), c["TID"].String(), c["FD"].String())]
		if c["RecordType"].String() != "file" || c["FileExtent"].Data.(map[string]any)["readable"] != true {
			t.Fatal("unexpected partial descriptor", row)
		}
		if ref == nil {
			if c["PID"].String() != "1" || c["FD"].String() != "10" || c["Path"].String() != "/run/initctl" {
				t.Fatal("unexpected additional descriptor", row)
			}
			extra++
			return nil
		}
		delete(byKey, key(c["PID"].String(), c["TID"].String(), c["FD"].String()))
		common++
		for _, name := range []string{"PID", "TID", "Process", "FD", "Device", "Inode", "Type", "Mode", "Size"} {
			if ref[name] == nil {
				if c[name].Kind != "missing" || c[name].Reason != "unknown_inode_type" {
					t.Fatal(name, c[name])
				}
			} else if c[name].String() != fmt.Sprint(ref[name]) {
				t.Fatal(name, c[name], ref[name])
			}
		}
		path := ref["Path"].(string)
		if strings.HasPrefix(path, " /") && strings.HasSuffix(path, " (deleted)") {
			path = path[1:]
			spaces++
		}
		if c["Path"].String() != path {
			t.Fatal("unexpected path difference", c["Path"], ref["Path"])
		}
		for _, name := range []string{"Changed", "Modified", "Accessed"} {
			if c[name].Kind != "string" || c[name+"Raw"].Kind != "structure" {
				t.Fatal("missing exact timestamp proof", c[name], c[name+"Raw"])
			}
		}
		return nil
	}})
	if err != nil || result.Task.Rows != 3796 || common != 3795 || extra != 1 || spaces != 24 || len(byKey) != 0 {
		t.Fatal(result, common, extra, spaces, len(byKey), err)
	}
}
