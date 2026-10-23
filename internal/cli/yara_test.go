package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/yara"
)

func TestYaraNativeShellCLI(t *testing.T) {
	library := os.Getenv("GOMEM_YARAX_LIBRARY")
	if library == "" || !yara.Supported() {
		t.Skip("set GOMEM_YARAX_LIBRARY for native CLI YARA-X")
	}
	dir := t.TempDir()
	image := filepath.Join(dir, "memory.raw")
	rules := filepath.Join(dir, "规则 source.yar")
	data := make([]byte, 4096)
	copy(data[0x123:], "YARA-CONTROL")
	if err := os.WriteFile(image, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte(`rule control {strings:$a="YARA-CONTROL" condition:$a}`), 0600); err != nil {
		t.Fatal(err)
	}
	input := `yara 0 4096 "` + filepath.ToSlash(rules) + `"` + "\nquit\n"
	out, stderr, err := run(t, input, "shell", "--image", image, "--yarax-library", library, "--offline", "--case", t.TempDir())
	if err != nil || strings.Contains(stderr, "error:") {
		t.Fatal(out, stderr, err)
	}
	for _, want := range []string{`"address":"0x0000000000000123"`, `"rule":"control"`, `"source":"physical"`, `"offset":"0x0000000000000123"`, `"complete":true`} {
		if !strings.Contains(out, want) {
			t.Fatal("missing", want, out)
		}
	}
}
