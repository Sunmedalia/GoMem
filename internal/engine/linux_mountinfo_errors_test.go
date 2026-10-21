package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestLinuxMountInfoDiagnosticsFailAndRerun(t *testing.T) {
	for _, tc := range []struct {
		name      string
		at, value uint64
		reason    string
	}{
		{"null-root", 0x21028, 0, "mount_root_absent"},
		{"null-superblock", 0x21030, 0, "superblock_absent"},
		{"partial-superblock", 0x21030, 0x2fff8, "superblock_unreadable"},
		{"unreadable-fstype", 0x25008, 0x300000, "filesystem_type_unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := mountInfoLayout(t)
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			binary.LittleEndian.PutUint64(data[tc.at:], tc.value)
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Offline: true, CaseDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			for i := 0; i < 2; i++ {
				found, summary := false, false
				result, err := e.Run(context.Background(), "linux.mountinfo", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
					if r.Cells["Error"].Reason == tc.reason {
						found = true
						if r.Cells["Error"].Error == "" {
							t.Fatal(r)
						}
					}
					if r.Cells["RecordType"].String() == "summary" {
						summary = true
						raw, err := json.Marshal(r.Cells["Coverage"].Data)
						var coverage map[string]string
						if err != nil {
							t.Fatal(err)
						}
						if err = json.Unmarshal(raw, &coverage); err != nil {
							t.Fatal(err)
						}
						if coverage["read_layout_errors"] != "1" {
							t.Fatal(r)
						}
					}
					return nil
				}})
				if err == nil || result.Task.State != "failed" || result.Reused || !found || !summary {
					t.Fatal(result, err, found, summary)
				}
			}
		})
	}
}

func TestLinuxMountInfoOutputFailureStops(t *testing.T) {
	f := mountInfoLayout(t)
	e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Offline: true, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	sentinel := errors.New("output stopped")
	calls := 0
	_, err = e.Run(context.Background(), "linux.mountinfo", nil, engine.RunOptions{Emit: func(evidence.Row) error {
		calls++
		if calls == 1 {
			return sentinel
		}
		return nil
	}})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, err = e.Run(ctx, "linux.mountinfo", nil, engine.RunOptions{Emit: func(evidence.Row) error { calls++; cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
}
