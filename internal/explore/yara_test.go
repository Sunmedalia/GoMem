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

	"github.com/Sunmedalia/GoMem/pkg/yara"
)

func TestYaraCurrentSpaceCrossBackingAndRuleOnly(t *testing.T) {
	library := os.Getenv("GOMEM_YARAX_LIBRARY")
	if library == "" || !yara.Supported() {
		t.Skip("set GOMEM_YARAX_LIBRARY for actual shell YARA-X")
	}
	s, _ := findSession(t)
	s.Engine.Config.YaraXLibrary = library
	path := filepath.Join(t.TempDir(), "规则 source.yar")
	source := `rule cross {strings:$a="ABQZ" condition:$a} rule always {condition:true}`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := `yara 0 8192 "` + filepath.ToSlash(path) + `"`
	var out bytes.Buffer
	if err := s.Execute(context.Background(), command, &out); err != nil {
		t.Fatal(&out, err)
	}
	for _, want := range []string{`"address":"0x0000000000000ffe"`, `"rule":"cross"`, `"pattern":"$a"`, `"rule_only":true`, `"source":"physical"`, `"source":"pagefile"`, `"pagefile":0`, `"offset":"0x0000000000002000"`, `"complete":true`, `"rules_sha256"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("missing", want, &out)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Execute(ctx, command, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	sentinel := errors.New("YARA output stopped")
	if err := s.Execute(context.Background(), command, disWriter{fail: sentinel}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`rule broken {condition:}`), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := s.Execute(context.Background(), command, &out); err == nil || !strings.Contains(out.String(), `"kind":"interactive_yara_compile_error"`) {
		t.Fatal(&out, err)
	}
}

func TestYaraShellRejectsMissingExtension(t *testing.T) {
	s, _ := findSession(t)
	if err := s.Execute(context.Background(), `yara 0 4 rules.yar`, io.Discard); err == nil {
		t.Fatal("silently substituted a non-YARA scanner")
	}
}
