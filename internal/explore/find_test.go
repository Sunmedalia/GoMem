package explore_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/explore"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func findSession(t *testing.T) (*explore.Session, string) {
	t.Helper()
	dir := t.TempDir()
	ram := make([]byte, 0x10000)
	for n := 1; n < 4; n++ {
		binary.LittleEndian.PutUint64(ram[n*4096:], uint64((n+1)*4096)|3)
	}
	binary.LittleEndian.PutUint64(ram[0x4000:], 0x8003)
	binary.LittleEndian.PutUint64(ram[0x4008:], uint64(2)<<32|128)
	binary.LittleEndian.PutUint64(ram[0x4010:], 0x9003)
	binary.LittleEndian.PutUint64(ram[0x4018:], 0xa003)
	copy(ram[0x8ffe:], "AB")
	file := make([]byte, 0x4000)
	copy(file[0x2000:], "QZ")
	copy(file[0x2100:], "EXTERNAL")
	image, path := filepath.Join(dir, "ram.raw"), filepath.Join(dir, "pagefile.sys")
	if err := os.WriteFile(image, ram, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Pagefiles: []string{"0=" + path}, CaseDir: t.TempDir(), OS: "windows", Arch: "x64", DTB: "0x1000", Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	s := explore.New(e)
	s.Layer = e.Env.Kernel
	return s, path
}

func TestFindCurrentSpaceCrossSourceAndNoHits(t *testing.T) {
	s, _ := findSession(t)
	for _, tc := range []struct {
		command, address string
		sourceCount      int
		hits             int
	}{
		{`find 0 8192 "ABQZ"`, "0x0000000000000ffe", 2, 1},
		{`find 0x1100 8 "EXTERNAL"`, "0x0000000000001100", 1, 1},
		{`find 0x1100 8 "not present"`, "", 0, 0},
	} {
		var out bytes.Buffer
		if err := s.Execute(context.Background(), tc.command, &out); err != nil {
			t.Fatal(&out, err)
		}
		dec := json.NewDecoder(&out)
		count := 0
		for dec.More() {
			var row struct {
				Kind, Address string
				Complete      bool
				Hits          int
				ImageSHA256   string `json:"image_sha256"`
				Sources       []struct {
					Source, Offset string
					Pagefile       *uint8
				}
			}
			if err := dec.Decode(&row); err != nil {
				t.Fatal(err)
			}
			if row.ImageSHA256 != s.Engine.Hash {
				t.Fatal("missing acquisition identity")
			}
			if row.Kind == "interactive_literal_hit" {
				count++
				if row.Address != tc.address || len(row.Sources) != tc.sourceCount {
					t.Fatal(row)
				}
				last := row.Sources[len(row.Sources)-1]
				if last.Source != "pagefile" || last.Pagefile == nil || *last.Pagefile != 0 {
					t.Fatal(row)
				}
			} else if row.Kind != "interactive_literal_summary" || !row.Complete || row.Hits != tc.hits {
				t.Fatal(row)
			}
		}
		if count != tc.hits {
			t.Fatal(count)
		}
	}
}

func TestFindFailuresAndLimits(t *testing.T) {
	s, path := findSession(t)
	for _, command := range []string{`find`, `find -1 1 a`, `find 0 0 a`, `find 0 1073741825 a`, `find 0 1 ""`, `find 0xffffffffffffffff 8 a`} {
		if err := s.Execute(context.Background(), command, io.Discard); err == nil {
			t.Fatal("invalid find accepted", command)
		}
	}
	sentinel := errors.New("find output stopped")
	if err := s.Execute(context.Background(), `find 0 8192 "ABQZ"`, disWriter{fail: sentinel}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Execute(ctx, `find 0 8192 a`, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	s.Layer = s.Engine.Env.Physical
	if err := s.Execute(context.Background(), `find 0 1 a`, io.Discard); err == nil {
		t.Fatal("physical space silently selected for virtual search")
	}
	s.Layer = s.Engine.Env.Kernel
	// Repeated overlapping matches stop with an incomplete summary at the cap.
	var out bytes.Buffer
	err := s.Execute(context.Background(), "find 0 16384 \"\x00\"", &out)
	if err == nil || !strings.Contains(err.Error(), "hit limit") || !strings.Contains(out.String(), `"complete":false`) || !strings.Contains(out.String(), `"hits":10000`) {
		t.Fatal("hit cap did not fail coverage", err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if err := s.Execute(context.Background(), `find 0 8192 a`, io.Discard); err == nil {
		t.Fatal("searched changed captured source")
	}
}

func TestFindMissingBackingIsIncomplete(t *testing.T) {
	s, _ := findSession(t)
	// Deliberately hide the acquisition's pagefile provider while retaining RAM.
	physical := struct{ memory.MemoryLayer }{s.Engine.Env.Physical}
	tr, err := memory.NewIntelForOS(physical, 0x1000, "x64", "windows", 8)
	if err != nil {
		t.Fatal(err)
	}
	s.Layer = &memory.Virtual{Physical: physical, Translator: tr, ID: "without-pagefile"}
	var out bytes.Buffer
	err = s.Execute(context.Background(), `find 0 8192 "ABQZ"`, &out)
	if !errors.Is(err, memory.ErrUnmapped) || !strings.Contains(out.String(), `"complete":false`) || strings.Contains(out.String(), `"kind":"interactive_literal_hit"`) {
		t.Fatal(&out, err)
	}
}
