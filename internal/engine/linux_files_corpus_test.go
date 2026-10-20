package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxFilesystemCensusAndPathLookup(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional locked legacy filesystem census; full acceptance pending")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reference-linux-files.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reference []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&reference); err != nil || len(reference) != 9434 {
		t.Fatal(len(reference), err)
	}
	u := func(v any) uint64 {
		n, err := strconv.ParseUint(fmt.Sprint(v), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	byInode := map[uint64]map[string]any{}
	for _, r := range reference {
		byInode[u(r["InodeAddr"])] = r
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	checked, displays := 0, 0
	result, err := e.Run(context.Background(), "linux.files", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		c := row.Cells
		if c["RecordType"].String() == "summary" {
			coverage := c["Coverage"].Data.(map[string]any)
			for k, v := range map[string]any{"superblocks": "11", "mount_records": "13", "dentry_visits": "11619", "negative_dentries": "2185", "unique_inodes": "9434", "aliases": "0", "traversal_complete": true} {
				if coverage[k] != v {
					t.Fatal(k, coverage)
				}
			}
			return nil
		}
		if c["RecordType"].String() != "file" || c["Error"].Error != "" {
			t.Fatal(c)
		}
		address, err := c["InodeAddr"].Uint()
		if err != nil {
			t.Fatal(err)
		}
		key := address & 0xffffffffffff
		r := byInode[key]
		if r == nil {
			t.Fatal("extra inode", c)
		}
		delete(byInode, key)
		checked++
		for _, name := range []string{"SuperblockAddr", "InodeAddr"} {
			v, err := c[name].Uint()
			if err != nil || v&0xffffffffffff != u(r[name]) {
				t.Fatal(name, c[name], r[name])
			}
		}
		for _, name := range []string{"Device", "InodeNum", "FileType", "InodePages", "CachedPages", "FileMode", "InodeSize"} {
			if c[name].String() != fmt.Sprint(r[name]) {
				t.Fatal(name, c[name], r[name])
			}
		}
		expectedPath, expectedMount := c["FilePath"].String(), c["MountPoint"].String()
		if expectedMount != r["MountPoint"] {
			if c["MountAttachmentDeleted"].Data != true {
				t.Fatal("unexplained mount display", c)
			}
			expectedMount = " " + expectedMount + " (deleted)"
			expectedPath = expectedMount + c["FilePath"].String()[len(c["MountPoint"].String()):]
			displays++
		}
		if expectedPath != r["FilePath"] || expectedMount != r["MountPoint"] {
			t.Fatal("unexplained path difference", c, r)
		}
		for _, key := range []string{"AccessTimeRaw", "ModificationTimeRaw", "ChangeTimeRaw"} {
			if c[key].Kind != "structure" {
				t.Fatal(key, c[key])
			}
		}
		return nil
	}})
	if err != nil || result.Task.Rows != 9435 || checked != 9434 || displays != 7 || len(byInode) != 0 {
		t.Fatal(result, checked, displays, len(byInode), err)
	}
	var lookup evidence.Row
	r, err := e.Run(context.Background(), "linux.inodepages", map[string]string{"find": "/var/log/syslog", "dump": "true"}, engine.RunOptions{Emit: func(row evidence.Row) error { lookup = row; return nil }})
	if err != nil || r.Task.Rows != 4 || lookup.Cells["InodeOffset"].String() != "0xffff88001a87e518" || lookup.Cells["InodeLookup"].Kind != "structure" {
		t.Fatal(r, lookup, err)
	}
	artifacts, err := e.Store.Artifacts(context.Background(), r.Task.ID)
	if err != nil || len(artifacts) != 1 || artifacts[0].SHA256 != "39301d85a3087a5f5736512ccbfe986c606976280e52487594b93f93d949cd8f" || artifacts[0].MissingBytes != "20480" {
		t.Fatal(artifacts, err)
	}
	if err = e.Store.VerifyTaskArtifacts(context.Background(), r.Task.ID); err != nil {
		t.Fatal(err)
	}
}
