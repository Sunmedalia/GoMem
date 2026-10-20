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

func TestOfficialLinuxSockstat(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected legacy x64 socket corpus; no full capability acceptance")
	}
	file, err := os.Open(filepath.Join(dir, "reference-linux-sockstat.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	dec.UseNumber()
	var reference []map[string]any
	if err = dec.Decode(&reference); err != nil || len(reference) != 1021 {
		t.Fatal("reference drift", len(reference), err)
	}
	key := func(pid, tid, fd string) string { return pid + ":" + tid + ":" + fd }
	bykey := map[string]map[string]any{}
	for _, r := range reference {
		bykey[key(fmt.Sprint(r["PID"]), fmt.Sprint(r["TID"]), fmt.Sprint(r["FD"]))] = r
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("image drift")
	}
	gaps, filters, ipv6, abstract := 0, 0, 0, 0
	r, err := e.Run(context.Background(), "linux.sockstat", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		c := row.Cells
		ref := bykey[key(c["PID"].String(), c["TID"].String(), c["FD"].String())]
		if ref == nil {
			t.Fatal("extra socket", row)
		}
		delete(bykey, key(c["PID"].String(), c["TID"].String(), c["FD"].String()))
		if c["RecordType"].String() != "socket" {
			t.Fatal(row)
		}
		for _, pair := range [][2]string{{"PID", "PID"}, {"TID", "TID"}, {"FD", "FD"}, {"Process", "Process Name"}, {"Family", "Family"}, {"Type", "Type"}, {"Proto", "Proto"}, {"SourcePort", "Source Port"}, {"DestinationPort", "Destination Port"}, {"State", "State"}, {"Filter", "Filter"}} {
			if ref[pair[1]] == nil {
				if c[pair[0]].Kind != "missing" || c[pair[0]].Error != "" {
					t.Fatal(pair, c[pair[0]])
				}
			} else if c[pair[0]].String() != fmt.Sprint(ref[pair[1]]) {
				t.Fatal(pair, c[pair[0]], ref[pair[1]])
			}
		}
		at, _ := c["Offset"].Uint()
		if fmt.Sprint(at&0xffffffffffff) != fmt.Sprint(ref["Sock Offset"]) {
			t.Fatal("socket address differs")
		}
		if c["Error"].Error != "" {
			if c["Family"].String() != "AF_BLUETOOTH" || c["Source"].Reason != "bluetooth_layout_unavailable" {
				t.Fatal(row)
			}
			gaps++
		}
		if c["Filter"].Kind == "string" {
			filters++
		}
		if c["Family"].String() == "AF_INET6" {
			ipv6++
			if c["Source"].Kind != "string" || c["Destination"].Kind != "string" || len(c["SourceRaw"].Data.([]byte)) != 16 {
				t.Fatal("IPv6 bytes lost", row)
			}
		}
		for _, name := range []string{"SourceEncoding", "DestinationEncoding"} {
			if c[name].String() == "abstract" {
				abstract++
			}
		}
		return nil
	}})
	if err == nil || r.Task.State != "failed" || r.Task.Rows != 1021 || len(bykey) != 0 || gaps != 5 || filters != 52 || ipv6 != 72 || abstract != 341 {
		t.Fatal(r, len(bykey), gaps, filters, ipv6, abstract, err)
	}
}
