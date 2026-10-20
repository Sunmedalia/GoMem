package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxMapsBothViews(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional official corpus; not full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("official image drift", e.Hash)
	}
	f, err := os.Open(filepath.Join(dir, "reference-linux-maps.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	var reference []map[string]any
	err = decoder.Decode(&reference)
	f.Close()
	if err != nil || len(reference) != 13990 {
		t.Fatal("reference drift", len(reference), err)
	}
	key := func(pid, start, end string) string { return pid + "/" + start + "/" + end }
	want := map[string]map[string]any{}
	for _, r := range reference {
		k := key(r["PID"].(json.Number).String(), r["Start"].(json.Number).String(), r["End"].(json.Number).String())
		if want[k] != nil {
			t.Fatal("duplicate reference mapping", k)
		}
		want[k] = r
	}
	for _, include := range []bool{true, false} {
		seen := map[string]bool{}
		outliers, global, labels := 0, 0, 0
		result, err := e.Run(ctx, "linux.maps", map[string]string{"include-past-eof": strconv.FormatBool(include)}, engine.RunOptions{Emit: func(row evidence.Row) error {
			if err := row.Verify(); err != nil {
				return err
			}
			start, err := row.Cells["Start"].Uint()
			if err != nil {
				return err
			}
			end, err := row.Cells["End"].Uint()
			if err != nil {
				return err
			}
			k := key(row.Cells["PID"].String(), strconv.FormatUint(start, 10), strconv.FormatUint(end, 10))
			if seen[k] {
				return fmt.Errorf("duplicate mapping %s", k)
			}
			seen[k] = true
			ref := want[k]
			if row.Cells["FileOffsetPastEOF"].String() == "true" {
				size, err := row.Cells["InodeSize"].Int()
				if err != nil {
					return err
				}
				offset, err := row.Cells["PgOff"].Uint()
				if err != nil {
					return err
				}
				if !include || ref != nil || size <= 0 || offset <= uint64(size) {
					return fmt.Errorf("unexplained mapping outlier %s", k)
				}
				outliers++
				return nil
			}
			if ref == nil {
				return fmt.Errorf("unexpected mapping %s", k)
			}
			for native, column := range map[string]string{"PgOff": "PgOff", "Major": "Major", "Minor": "Minor", "Inode": "Inode"} {
				actual, err := row.Cells[native].Uint()
				if err != nil {
					return err
				}
				expected, err := strconv.ParseUint(ref[column].(json.Number).String(), 10, 64)
				if err != nil || actual != expected {
					return fmt.Errorf("mapping %s %s differs", k, native)
				}
			}
			if row.Cells["Process"].String() != ref["Process"] || row.Cells["Protection"].String() != ref["Flags"] {
				return fmt.Errorf("mapping %s name or protection differs", k)
			}
			path := ref["File Path"].(string)
			if strings.HasPrefix(path, " /") && strings.HasSuffix(path, " (deleted)") {
				path = path[1:]
			}
			if row.Cells["Path"].Kind != "string" || row.Cells["Path"].String() != path {
				return fmt.Errorf("mapping %s path differs", k)
			}
			switch row.Cells["PathScope"].String() {
			case "global_root":
				global++
			case "dentry_label":
				labels++
			}
			return nil
		}})
		n := int64(13990)
		expectedOutliers := 0
		if include {
			n = 14045
			expectedOutliers = 55
		}
		if err != nil || result.Task.Rows != n || outliers != expectedOutliers || global != 135 || labels != 8 {
			t.Fatal(result, outliers, global, labels, err)
		}
		for k := range want {
			if !seen[k] {
				t.Fatal("missing mapping", k)
			}
		}
	}
}
