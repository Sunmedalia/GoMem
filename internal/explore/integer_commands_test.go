package explore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func TestIntegerCommandsCurrentLayerEndianTailAndAliases(t *testing.T) {
	s := disSession(t, []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49}, "x64")
	layer, err := memory.NewMapped(s.Engine.Source, "integer-selected", []memory.Range{{Start: 0x8000, Length: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	s.Layer = layer
	for _, tc := range []struct{ command, want string }{
		{"db 0x8100 9", "41 42 43 44 45 46 47 48 49"},
		{"dw 0x8100 9", "4241 4443 4645 4847"},
		{"dd 0x8100 9", "44434241 48474645"},
		{"dq 0x8100 9", "4847464544434241"},
		{"dq 0x8100 8 be", "4142434445464748"},
		{"dw 0x8101 2 be", "4243"},
		{"display_bytes 0x8100 2", "41 42"},
		{"display_words 0x8100 2 <", "4241"},
		{"display_doublewords 0x8100 4 !", "41424344"},
		{"display_quadwords 0x8100 8 native", "8-byte integers; native"},
	} {
		var out bytes.Buffer
		if err := s.Execute(context.Background(), tc.command, &out); err != nil {
			t.Fatal(tc.command, err)
		}
		if !strings.Contains(out.String(), tc.want) || !strings.Contains(out.String(), "integer-selected @") {
			t.Fatal(tc.command, &out)
		}
		if strings.Contains(tc.command, " 9") && !strings.HasPrefix(tc.command, "db") && !strings.Contains(out.String(), "trailing bytes cannot form") {
			t.Fatal("partial integer bytes lost", &out)
		}
	}
	var out bytes.Buffer
	if err := s.Execute(context.Background(), "dq 0x8100", &out); err != nil || !strings.Contains(out.String(), "128 bytes requested") {
		t.Fatal(&out, err)
	}
	out.Reset()
	if err := s.Execute(context.Background(), "dq 0x8100 0", &out); err != nil || !strings.Contains(out.String(), "0 bytes requested") {
		t.Fatal(&out, err)
	}
}

func TestIntegerCommandsFailuresAndCancellation(t *testing.T) {
	s := disSession(t, []byte{0x41}, "x64")
	for _, command := range []string{"dw", "db -1", "dq 0 65537", "dd 0 4 middle", "dq 0xffffffffffffffff 8", "db 4095 2"} {
		var out bytes.Buffer
		if err := s.Execute(context.Background(), command, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid read produced output", command, &out, err)
		}
	}
	sentinel := errors.New("integer output stopped")
	if err := s.Execute(context.Background(), "dq 0x100 32", disWriter{fail: sentinel}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Execute(ctx, "dq 0x100 32", disWriter{cancel: cancel}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(s.Engine.Config.Image, future, future); err != nil {
		t.Fatal(err)
	}
	if err := s.Execute(context.Background(), "dw 0x100 2", io.Discard); err == nil {
		t.Fatal("read changed acquisition")
	}
}
