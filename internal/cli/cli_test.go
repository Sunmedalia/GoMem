package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestArtifactVerificationDoesNotCreateAnAbsentCase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	if _, _, err := run(t, "", "case", "verify-artifacts", "--case", dir); err == nil {
		t.Fatal("absent case verified")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("inspection created an empty case", err)
	}
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

func TestLocalSymbolIndexCommand(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	caseDir := t.TempDir()
	if _, _, err = run(t, "", "symbols", "index", f.Symbols, "--case", caseDir); err != nil {
		t.Fatal(err)
	}
	if _, _, err = run(t, "", "symbols", "index", f.Symbols, "--case", caseDir); err == nil {
		t.Fatal("existing index overwritten")
	}
	out, stderr, err := run(t, "", "analyze", "linux.pslist", "--image", f.Image, "--case", caseDir, "--dtb", f.DTB, "--offline", "--format", "jsonl")
	if err != nil || len(strings.Split(strings.TrimSpace(out), "\n")) != 2 {
		t.Fatal(out, stderr, err)
	}
}

func TestLinuxDiscoveryCommand(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	out, stderr, err := run(t, "", "analyze", "linux.pslist", "--image", f.Image, "--symbols", f.Symbols, "--offline", "--format", "jsonl")
	if err != nil || len(strings.Split(strings.TrimSpace(out), "\n")) != 2 {
		t.Fatal(out, stderr, err)
	}
	out, stderr, err = run(t, "", "doctor", "--image", f.Image, "--symbols", f.Symbols, "--offline")
	if err != nil || !strings.Contains(out, `"pgd_symbol": "init_top_pgt"`) {
		t.Fatal(out, stderr, err)
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

func TestNativePDBCommand(t *testing.T) {
	out, stderr, err := run(t, "", "symbols", "convert", "../../pkg/symbols/testdata/native-x64.pdb")
	if err != nil || !strings.Contains(stderr, `"format":"pdb-msf7"`) || !strings.Contains(out, `"name":"_EPROCESS"`) {
		t.Fatal(out, stderr, err)
	}
	if _, _, err = run(t, "", "symbols", "convert", "../../pkg/symbols/testdata/native-x64.pdb", "--os", "linux"); err == nil {
		t.Fatal("PDB selected as Linux symbols")
	}
	if _, _, err = run(t, "", "symbols", "convert", "../../pkg/symbols/testdata/native-x64.pdb", "--system-map", "missing"); err == nil {
		t.Fatal("ignored DWARF-only option")
	}
}

func TestWindowsCrashDiscoveryCommand(t *testing.T) {
	f, err := testfixture.Write(t.TempDir(), "windows")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	copy(data[0x7010:], "KDBG")
	binary.LittleEndian.PutUint32(data[0x7014:], 0x380)
	binary.LittleEndian.PutUint64(data[0x7018:], 0x4000)
	binary.LittleEndian.PutUint64(data[0x7048:], 0x6010)
	binary.LittleEndian.PutUint64(data[0x7050:], 0x6000)
	dump := make([]byte, 8192+len(data))
	copy(dump, "PAGEDU64")
	copy(dump[8192:], data)
	binary.LittleEndian.PutUint64(dump[16:], 0x1000)
	binary.LittleEndian.PutUint64(dump[32:], 0x6010)
	binary.LittleEndian.PutUint64(dump[40:], 0x6000)
	binary.LittleEndian.PutUint32(dump[48:], 0x8664)
	binary.LittleEndian.PutUint64(dump[128:], 0x7000)
	binary.LittleEndian.PutUint32(dump[136:], 1)
	binary.LittleEndian.PutUint64(dump[144:], uint64(len(data)/4096))
	binary.LittleEndian.PutUint64(dump[160:], uint64(len(data)/4096))
	binary.LittleEndian.PutUint32(dump[3992:], 1)
	path := filepath.Join(t.TempDir(), "memory.dmp")
	if err = os.WriteFile(path, dump, 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := run(t, "", "analyze", "windows.pslist", "--image", path, "--symbols", f.Symbols, "--offline", "--format", "jsonl")
	if err != nil || len(strings.Split(strings.TrimSpace(out), "\n")) != 2 {
		t.Fatal(out, stderr, err)
	}
	out, stderr, err = run(t, "", "doctor", "--image", path, "--symbols", f.Symbols, "--offline")
	if err != nil || !strings.Contains(out, `"method": "crash-header-kdbg-pe"`) || !strings.Contains(out, `"verified": true`) {
		t.Fatal(out, stderr, err)
	}
}
