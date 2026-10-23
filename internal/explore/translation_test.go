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

func TestTranslateCurrentLayerAndFailures(t *testing.T) {
	s := disSession(t, []byte{0x90}, "x64")
	var out bytes.Buffer
	if err := s.Execute(context.Background(), "translate 0x100", &out); err != nil || !strings.Contains(out.String(), "physical layer coordinate") {
		t.Fatal(&out, err)
	}
	for _, command := range []string{"translate", "translate -1", "translate 0 1"} {
		if err := s.Execute(context.Background(), command, io.Discard); err == nil {
			t.Fatal("invalid translation command accepted")
		}
	}
	sentinel := errors.New("stopped translation output")
	if err := s.Execute(context.Background(), "translate 0x100", disWriter{fail: sentinel}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	// An existing translator failure remains explicit, including cancellation.
	tr, err := memory.NewIntelForOS(s.Engine.Env.Physical, 0, "x64", "windows", 4)
	if err != nil {
		t.Fatal(err)
	}
	s.Layer = &memory.Virtual{Physical: s.Engine.Env.Physical, Translator: tr, ID: "selected"}
	if err := s.Execute(context.Background(), "translate 0x100", io.Discard); !errors.Is(err, memory.ErrUnmapped) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Execute(ctx, "translate 0x100", io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(s.Engine.Config.Image, future, future); err != nil {
		t.Fatal(err)
	}
	if err := s.Execute(context.Background(), "translate 0x100", io.Discard); err == nil {
		t.Fatal("translated changed image")
	}
}
