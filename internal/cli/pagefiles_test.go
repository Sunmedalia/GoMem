package cli

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPagefileShellCLI(t *testing.T) {
	dir := t.TempDir()
	ram := make([]byte, 0x10000)
	for n := 1; n <= 3; n++ {
		binary.LittleEndian.PutUint64(ram[n*4096:], uint64((n+1)*4096)|3)
	}
	binary.LittleEndian.PutUint64(ram[0x4000:], uint64(2)<<32|128|6)
	file := make([]byte, 0x3000)
	copy(file[0x2123:], "EXTERNAL")
	copy(file[0x2100:], []byte{0x90, 0xc3})
	image := filepath.Join(dir, "ram.raw")
	path := filepath.Join(dir, "捕获 pagefile.sys")
	if err := os.WriteFile(image, ram, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"shell", "--image", image, "--pagefile", "3=" + path, "--os", "windows", "--arch", "x64", "--dtb", "0x1000", "--case", t.TempDir(), "--offline"}
	out, stderr, err := run(t, "use kernel\ntranslate 0x123\nhex 0x123 8\ndis 0x100 2\nfind 0x123 8 EXTERNAL\ndq 0x123 8 be\nquit\n", args...)
	if err != nil || strings.Contains(stderr, "error:") {
		t.Fatal(out, stderr, err)
	}
	for _, want := range []string{"pagefile:3 offset=0x2123", "entry-address=0x4000", "permissions-known=false", "EXTERNAL", "nop", "ret", `"kind":"interactive_literal_hit"`, `"pagefile":3`, `"offset":"0x0000000000002123"`, `"complete":true`, "45585445524e414c"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q: %s", want, out)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, file) {
		t.Fatal("CLI modified pagefile")
	}
	_, stderr, err = run(t, "use kernel\nhex 0x123 8\nquit\n", "shell", "--image", image, "--os", "windows", "--arch", "x64", "--dtb", "0x1000", "--offline", "--case", t.TempDir())
	if err != nil || !strings.Contains(stderr, "pagefile 3") {
		t.Fatal("missing pagefile became empty/successful read", stderr, err)
	}
}
