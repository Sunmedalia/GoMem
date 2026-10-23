package explore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/explore"
	"github.com/Sunmedalia/GoMem/pkg/disasm"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestDisassemblyCapstoneSelectedLayerAndFailures(t *testing.T) {
	library := os.Getenv("GOMEM_CAPSTONE_LIBRARY")
	if library == "" || !disasm.Supported() {
		t.Skip("set GOMEM_CAPSTONE_LIBRARY for native shell tests")
	}
	for _, tc := range []struct {
		code          []byte
		command, want string
	}{
		{[]byte{0xe8, 0xfb, 0xff, 0xff, 0xff}, "dis 0x8100 5 x64", "call 0x8100"},
		{[]byte{0x70, 0x47}, "dis 0x8100 2 thumb", "bx lr"},
	} {
		s := disSession(t, tc.code, "x64")
		s.Engine.Config.CapstoneLibrary = library
		layer, err := memory.NewMapped(s.Engine.Source, "native-selected-process", []memory.Range{{Start: 0x8000, Length: 4096}})
		if err != nil {
			t.Fatal(err)
		}
		s.Layer = layer
		var out bytes.Buffer
		if err := s.Execute(context.Background(), tc.command, &out); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{tc.want, "native-selected-process @ 0x8100", "Capstone 5.", "0x0000000000008100"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("missing %q: %s", want, &out)
			}
		}
	}
	s := disSession(t, []byte{0x90, 0x0f}, "x64")
	s.Engine.Config.CapstoneLibrary = library
	var out bytes.Buffer
	if err := s.Execute(context.Background(), "dis 0x100 2", &out); err == nil || !strings.Contains(err.Error(), "0x101") || !strings.Contains(out.String(), "nop") {
		t.Fatal(&out, err)
	}
	for _, command := range []string{"dis 0x101 2 thumb", "dis 0x100 1 thumb"} {
		if err := s.Execute(context.Background(), command, io.Discard); err == nil {
			t.Fatal("unaligned Thumb accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Execute(ctx, "dis 0x100 1", disWriter{cancel: cancel}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	sentinel := errors.New("native output stopped")
	if err := s.Execute(context.Background(), "dis 0x100 1", disWriter{fail: sentinel}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	s.Engine.Config.CapstoneLibrary = filepath.Join(t.TempDir(), "missing-capstone")
	out.Reset()
	if err := s.Execute(context.Background(), "dis 0x100 1", &out); err == nil || out.Len() != 0 {
		t.Fatal("silently fell back", &out, err)
	}
	s.Engine.Config.CapstoneLibrary = library
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(s.Engine.Config.Image, future, future); err != nil {
		t.Fatal(err)
	}
	if err := s.Execute(context.Background(), "dis 0x100 1", io.Discard); err == nil {
		t.Fatal("disassembled changed source")
	}
}

func disSession(t *testing.T, code []byte, arch string) *explore.Session {
	t.Helper()
	raw := make([]byte, 4096)
	copy(raw[256:], code)
	image := filepath.Join(t.TempDir(), "code.raw")
	if err := os.WriteFile(image, raw, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := engine.Open(context.Background(), engine.Config{Image: image, Arch: arch, CaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return explore.New(e)
}

func TestDisassemblyArchitecturesAndCurrentLayer(t *testing.T) {
	cases := []struct {
		arch string
		code []byte
		want []string
	}{
		{"x64", []byte{0x48, 0x89, 0xd8, 0xc3}, []string{"mov rax, rbx", "ret"}},
		{"x86", []byte{0x48, 0x89, 0xd8, 0xc3}, []string{"dec eax", "mov eax, ebx", "ret"}},
		{"pae", []byte{0x48, 0x89, 0xd8, 0xc3}, []string{"dec eax", "mov eax, ebx", "ret"}},
		{"arm64", []byte{0xc0, 0x03, 0x5f, 0xd6}, []string{"ret"}},
	}
	for _, test := range cases {
		t.Run(test.arch, func(t *testing.T) {
			s := disSession(t, test.code, test.arch)
			layer, err := memory.NewMapped(s.Engine.Source, "selected-process", []memory.Range{{Start: 0x8000, Length: 4096}})
			if err != nil {
				t.Fatal(err)
			}
			s.Layer = layer
			var out bytes.Buffer
			if err = s.Execute(context.Background(), "dis 0x8100 4", &out); err != nil {
				t.Fatal(err)
			}
			for _, want := range append(test.want, "selected-process @ 0x8100", "0x0000000000008100") {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q: %s", want, &out)
				}
			}
		})
	}
	arm := disSession(t, []byte{0x1e, 0xff, 0x2f, 0xe1}, "x64")
	var armOut bytes.Buffer
	if err := arm.Execute(context.Background(), "dis 0x100 4 arm", &armOut); err != nil || !strings.Contains(armOut.String(), "bx lr") {
		t.Fatal(&armOut, err)
	}
	s := disSession(t, []byte{0xe8, 0xfb, 0xff, 0xff, 0xff}, "x64")
	var out bytes.Buffer
	if err := s.Execute(context.Background(), "disasm 0x100 5", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "call 0x100") {
		t.Fatal("branch address", &out)
	}
}

func TestDisassemblyErrorsAndOverrides(t *testing.T) {
	s := disSession(t, []byte{0x48, 0x89, 0xd8, 0xc3}, "x64")
	for _, command := range []string{"dis", "dis -1", "dis 0 0", "dis 0 65537", "dis 0 4 mips", "dis 1 4 arm64", "dis 0 3 arm64", "dis 0xffffffffffffffff 4", "dis 4095 4", "dis 0x100 1 x64"} {
		var out bytes.Buffer
		if err := s.Execute(context.Background(), command, &out); err == nil {
			t.Errorf("accepted %q: %s", command, &out)
		}
	}
	var out bytes.Buffer
	if err := s.Execute(context.Background(), "dis 0x100 4 x86", &out); err != nil || !strings.Contains(out.String(), "dec eax") {
		t.Fatal(&out, err)
	}
	// No mapped data is silently replaced with zeros.
	layer, err := memory.NewMapped(s.Engine.Source, "hole", []memory.Range{{Start: 0x1000, Length: 16}})
	if err != nil {
		t.Fatal(err)
	}
	s.Layer = layer
	out.Reset()
	if err = s.Execute(context.Background(), "dis 0 4", &out); !errors.Is(err, memory.ErrUnmapped) || out.Len() != 0 {
		t.Fatal(&out, err)
	}
}

type disWriter struct {
	cancel context.CancelFunc
	fail   error
}

func (w disWriter) Write(p []byte) (int, error) {
	if w.cancel != nil {
		w.cancel()
	}
	if w.fail != nil {
		return 0, w.fail
	}
	return len(p), nil
}
func TestDisassemblyCancellationOutputAndImageChange(t *testing.T) {
	s := disSession(t, []byte{0x90, 0x90, 0xc3}, "x64")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Execute(ctx, "dis 0x100 3", disWriter{cancel: cancel}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	sentinel := errors.New("output stopped")
	if err := s.Execute(context.Background(), "dis 0x100 3", disWriter{fail: sentinel}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(s.Engine.Config.Image, future, future); err != nil {
		t.Fatal(err)
	}
	if err := s.Execute(context.Background(), "dis 0x100 3", io.Discard); err == nil {
		t.Fatal("disassembled changed acquisition")
	}
}
