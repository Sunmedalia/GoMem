package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsCommandLines(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected Windows 10 command lines; not full capability acceptance")
	}
	ctx := context.Background()
	f, err := os.Open(filepath.Join(dir, "reference-windows-cmdline.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	var reference []map[string]any
	err = decoder.Decode(&reference)
	f.Close()
	if err != nil || len(reference) != 120 {
		t.Fatal("reference drift", len(reference), err)
	}
	groups := map[string]map[string]any{}
	for _, row := range reference {
		id := row["PID"].(json.Number).String()
		if groups[id] != nil {
			t.Fatal("duplicate reference PID")
		}
		groups[id] = row
	}
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
		t.Fatal("image drift", e.Hash)
	}
	identities := map[string]string{}
	if _, err := e.Run(ctx, "windows.pslist", nil, engine.RunOptions{Emit: func(r evidence.Row) error {
		identities[r.Cells["PID"].String()] = r.Cells["Identity"].String()
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	readable, absent, failures, nuls := 0, 0, 0, 0
	seen := map[string]bool{}
	result, err := e.Run(ctx, "windows.cmdline", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		if err := row.Verify(); err != nil {
			return err
		}
		c := row.Cells
		pid := c["PID"].String()
		ref := groups[pid]
		if ref == nil || seen[pid] || c["Process"].String() != ref["Process"] || c["ProcessIdentity"].String() != identities[pid] {
			return fmt.Errorf("unexpected process or identity")
		}
		seen[pid] = true
		args := c["Args"]
		if args.Kind == "missing" {
			if ref["Args"] != nil {
				return fmt.Errorf("missing command line that reference recovered")
			}
			if args.Reason == "no_process_peb" && args.Error == "" {
				absent++
			} else if args.Error != "" {
				failures++
			} else {
				return fmt.Errorf("unexplained missing command line")
			}
			return nil
		}
		if args.String() != ref["Args"] || row.Provenance.Layer != "process:"+identities[pid] || c["ReadComplete"].Data != true {
			return fmt.Errorf("command line or source layer differs")
		}
		raw, ok := c["ArgsRaw"].Data.([]byte)
		length, er := c["Length"].Uint()
		captured, er2 := c["CapturedBytes"].Uint()
		if !ok || er != nil || er2 != nil || uint64(len(raw)) != length || captured != length || length%2 != 0 {
			return fmt.Errorf("capture length or raw evidence differs")
		}
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		full := string(utf16.Decode(units))
		if c["ArgsFull"].String() != full {
			return fmt.Errorf("declared string differs from raw capture")
		}
		if i := strings.IndexByte(full, 0); i >= 0 {
			nuls++
			if args.String() != full[:i] || !bytes.Equal(raw, commandUTF16(full)) {
				return fmt.Errorf("embedded NUL lost raw suffix")
			}
		}
		readable++
		return nil
	}})
	if err == nil || result.Task.State != "failed" || result.Task.Rows != 120 || len(seen) != 120 || readable != 96 || absent != 3 || failures != 21 || nuls != 2 {
		t.Fatal(result, readable, absent, failures, nuls, len(seen), err)
	}
}
