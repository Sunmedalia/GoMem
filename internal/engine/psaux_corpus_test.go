package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialLinuxProcessArguments(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional legacy x64 process argument comparison; not full acceptance")
	}
	f, err := os.Open(filepath.Join(dir, "reference-linux-psaux.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	var reference []map[string]any
	err = decoder.Decode(&reference)
	f.Close()
	if err != nil || len(reference) != 133 {
		t.Fatal("reference drift", len(reference), err)
	}
	groups := map[string]map[string]any{}
	for _, row := range reference {
		pid := row["PID"].(json.Number).String()
		if groups[pid] != nil {
			t.Fatal("duplicate reference PID")
		}
		groups[pid] = row
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "linux-sample-1.bin"), Symbols: filepath.Join(dir, "linux.zip#linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc" {
		t.Fatal("image drift", e.Hash)
	}
	identities := map[string]string{}
	if _, err := e.Run(ctx, "linux.pslist", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		identities[r.Cells["PID"].String()] = r.Cells["Identity"].String()
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	readable, noMM, failures := 0, 0, 0
	result, err := e.Run(ctx, "linux.psaux", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		c := row.Cells
		pid := c["PID"].String()
		ref := groups[pid]
		if ref == nil || row.Verify() != nil || c["PPID"].String() != fmt.Sprint(ref["PPID"]) || c["COMM"].String() != ref["COMM"] || c["ProcessIdentity"].String() != identities[pid] {
			return fmt.Errorf("process identity/core fields differ")
		}
		delete(groups, pid)
		if c["ARGS"].Kind == "missing" {
			if ref["ARGS"] != nil || c["ARGS"].Error == "" || c["ARGS"].Reason != "argument_buffer_unreadable" {
				return fmt.Errorf("unexplained missing argument buffer")
			}
			failures++
			return nil
		}
		if c["ARGS"].String() != ref["ARGS"] {
			return fmt.Errorf("arguments differ")
		}
		if c["ArgsSource"].String() == "comm_without_mm" {
			if c["MM"].String() != evidence.Address(0).String() || c["ArgsRaw"].Reason != "no_user_mm" || c["ARGS"].String() != "["+c["COMM"].String()+"]" {
				return fmt.Errorf("null-mm display passed off as captured arguments")
			}
			noMM++
			return nil
		}
		raw := c["ArgsRaw"].Data.([]byte)
		size, _ := c["Length"].Uint()
		captured, _ := c["CapturedBytes"].Uint()
		if !utf8.Valid(raw) || uint64(len(raw)) != size || size != captured || c["ReadComplete"].Data != true || row.Provenance.Layer != "process:"+identities[pid] {
			return fmt.Errorf("raw capture or source differs")
		}
		display := strings.ReplaceAll(string(raw), "\x00", " ")
		if len(display) > 1 && strings.HasSuffix(display, " ") {
			display = display[:len(display)-1]
		}
		if display != c["ARGS"].String() {
			return fmt.Errorf("display differs from original bytes")
		}
		readable++
		return nil
	}})
	if err == nil || result.Task.State != "failed" || result.Task.Rows != 133 || len(groups) != 0 || readable != 92 || noMM != 39 || failures != 2 {
		t.Fatal(result, readable, noMM, failures, len(groups), err)
	}
}
