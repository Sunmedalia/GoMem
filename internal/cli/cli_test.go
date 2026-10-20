package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func run(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	var out, stderr bytes.Buffer
	cmd := New(strings.NewReader(input), &out, &stderr)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), stderr.String(), err
}
func TestCommandsEndToEnd(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(f.Image)
	caseDir := t.TempDir()
	args := []string{"analyze", "linux.pslist", "--image", f.Image, "--case", caseDir, "--symbols", f.Symbols, "--dtb", f.DTB, "--os", "linux", "--format", "jsonl"}
	out, stderr, err := run(t, "", args...)
	if err != nil {
		t.Fatal(stderr, err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatal(out)
	}
	var first evidence.Row
	if err = json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	_, stderr, err = run(t, "", args...)
	if err != nil || !strings.Contains(stderr, "cached=true") {
		t.Fatal(stderr, err)
	}
	if _, _, err = run(t, "", "export", "--case", caseDir, "--format", "bundle", "--output", "evidence.zip"); err != nil {
		t.Fatal(err)
	}
	out, _, err = run(t, "use kernel\nhex 0x8000 32\nuse process "+first.ID+"\nhex 0x8000 16\nquit\n", "shell", "--image", f.Image, "--symbols", f.Symbols, "--dtb", f.DTB, "--case", caseDir)
	if err != nil || !strings.Contains(out, "Linux version") {
		t.Fatal(out, err)
	}
	out, _, err = run(t, "", "triage", "--image", f.Image, "--case", caseDir, "--os", "linux", "--symbols", f.Symbols, "--dtb", f.DTB, "--ioc", "gomem-test-ioc")
	if err == nil || !strings.Contains(out, `"unavailable"`) {
		t.Fatal(out, err)
	}
	after, _ := os.ReadFile(f.Image)
	if !bytes.Equal(before, after) {
		t.Fatal("image changed")
	}
}
func TestFailuresAreNotEmptySuccess(t *testing.T) {
	if _, _, err := run(t, "", "analyze", "windows.psscan", "--image", "missing.raw"); err == nil {
		t.Fatal("unimplemented plugin succeeded")
	}
	f, _ := testfixture.Write(t.TempDir(), "linux")
	if out, _, err := run(t, "", "analyze", "linux.pslist", "--image", f.Image, "--offline"); err == nil || out != "" {
		t.Fatal(out, err)
	}
	if _, _, err := run(t, "", "doctor", "--strict"); err == nil {
		t.Fatal("release gate passed")
	}
	if _, _, err := run(t, "", "symbols", "fetch", "https://example.com/table.json", "--offline"); err == nil {
		t.Fatal("offline download succeeded")
	}
}

func TestNativeSymbolConversionCommand(t *testing.T) {
	source := "../../pkg/symbols/testdata/dwarf-x86_64-v5.elf"
	target := t.TempDir() + "/converted.json"
	out, stderr, err := run(t, "", "symbols", "convert", source, "--output", target)
	if err != nil {
		t.Fatal(stderr, err)
	}
	if !strings.Contains(out, "converted.json") || !strings.Contains(stderr, `"entries"`) {
		t.Fatal(out, stderr)
	}
	table, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err = json.Unmarshal(table, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, _, err = run(t, "", "symbols", "convert", source, "--output", target); err == nil {
		t.Fatal("overwrote existing symbol table")
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(table, after) {
		t.Fatal("existing symbols changed")
	}
	out, _, err = run(t, "", "symbols", "inspect", source)
	if err != nil || !strings.Contains(out, `"enums"`) {
		t.Fatal(out, err)
	}
	out, _, err = run(t, "", "symbols", "convert", source, "--output", "-")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal("stdout was not clean ISF JSON", err)
	}
}
