package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestOfficialWindowsProcessFieldsAndModulePaths(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional Windows selected-field and physical-offset comparison; not full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Hash != "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460" {
		t.Fatal("official image drift", e.Hash)
	}
	read := func(name, key string) map[string]map[string]any {
		t.Helper()
		file, err := os.Open(filepath.Join(dir, "reference-windows-"+name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		var rows []map[string]any
		decoder := json.NewDecoder(file)
		decoder.UseNumber()
		if err = decoder.Decode(&rows); err != nil {
			t.Fatal(err)
		}
		result := map[string]map[string]any{}
		for _, row := range rows {
			id := fmt.Sprint(row[key])
			if result[id] != nil {
				t.Fatal("duplicate reference key", id)
			}
			result[id] = row
		}
		return result
	}
	for _, physical := range []bool{false, true} {
		name, offset := "pslist", "Offset(V)"
		if physical {
			name, offset = "pslist-physical", "Offset(P)"
		}
		reference := read(name, "PID")
		handles, sessions, times := 0, 0, 0
		r, err := e.Run(ctx, "windows.pslist", map[string]string{"physical": strconv.FormatBool(physical)}, engine.RunOptions{Emit: func(row evidence.Row) error {
			c := row.Cells
			ref := reference[c["PID"].String()]
			if ref == nil {
				return fmt.Errorf("unexpected process")
			}
			delete(reference, c["PID"].String())
			for _, pair := range [][2]string{{"Name", "ImageFileName"}, {"PPID", "PPID"}, {"Threads", "Threads"}, {"Wow64", "Wow64"}} {
				if c[pair[0]].String() != fmt.Sprint(ref[pair[1]]) {
					return fmt.Errorf("process %s differs", pair[0])
				}
			}
			a, er := c["Offset"].Uint()
			if !physical {
				a &= 0xffffffffffff
			}
			if er != nil || strconv.FormatUint(a, 10) != fmt.Sprint(ref[offset]) {
				return fmt.Errorf("process offset differs")
			}
			for _, key := range []string{"Handles", "SessionId"} {
				if ref[key] == nil {
					cell := c[key]
					valid := key == "Handles" && (cell.Reason == "unsupported_handle_count" || cell.Reason == "handle_table_not_set") || key == "SessionId" && cell.Reason == "not_applicable"
					if !valid || cell.Error != "" {
						return fmt.Errorf("unexplained missing %s", key)
					}
					if key == "Handles" {
						handles++
					} else {
						sessions++
					}
				} else if c[key].String() != fmt.Sprint(ref[key]) {
					return fmt.Errorf("process %s differs", key)
				}
			}
			for _, pair := range [][2]string{{"Created", "CreateTime"}, {"Exited", "ExitTime"}} {
				cell := c[pair[0]]
				if ref[pair[1]] == nil {
					if cell.Reason != "not_set" || cell.Error != "" {
						return fmt.Errorf("unexplained missing timestamp")
					}
					continue
				}
				a, er := time.Parse(time.RFC3339Nano, cell.String())
				b, er2 := time.Parse(time.RFC3339Nano, ref[pair[1]].(string))
				if er != nil || er2 != nil || !a.Truncate(time.Second).Equal(b) {
					return fmt.Errorf("process time differs")
				}
				times++
			}
			return nil
		}})
		if err != nil || r.Task.Rows != 120 || len(reference) != 0 || handles != 120 || sessions != 4 || times != 123 {
			t.Fatal(physical, r, handles, sessions, times, len(reference), err)
		}
	}
	reference := read("modules", "Offset")
	readable, errors := 0, 0
	r, err := e.Run(ctx, "windows.modules", nil, engine.RunOptions{Emit: func(row evidence.Row) error {
		a, er := row.Cells["Offset"].Uint()
		if er != nil {
			return er
		}
		id := strconv.FormatUint(a&0xffffffffffff, 10)
		ref := reference[id]
		if ref == nil {
			return fmt.Errorf("unexpected module")
		}
		delete(reference, id)
		path := row.Cells["Path"]
		if path.Kind == "missing" {
			if path.Error == "" || ref["Path"] != nil {
				return fmt.Errorf("unexplained path error")
			}
			errors++
		} else {
			if path.String() != ref["Path"] {
				return fmt.Errorf("module path differs")
			}
			readable++
		}
		return nil
	}})
	if err != nil || r.Task.Rows != 176 || len(reference) != 0 || readable != 157 || errors != 19 {
		t.Fatal(r, readable, errors, err)
	}
}

func TestOfficialWindowsMainAndSessionPEs(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("optional selected process and session PEs; not full acceptance")
	}
	ctx := context.Background()
	e, err := engine.Open(ctx, engine.Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), CaseDir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, tc := range []struct {
		plugin, filter, value, size, missing, sha string
	}{{"windows.pslist", "pid", "488", "28672", "16384", "abdc0769d35ed4f36912e5d4f5823e22abec4ccd3139db57bde9ee511bb6c269"}, {"windows.modules", "base", "0xfffff8043601f000", "17063936", "8347648", "ef644d9319a50413a914e42be14c3a2b78fc03a37650010ba7115cee00cd80bc"}, {"windows.modules", "base", "0xffffeb4b3acd0000", "634880", "81920", "a1d6e49dbe1749e9e1fe735fb769a1dbc6ba92fd9e12de179d89ed1818dcae6d"}, {"windows.pedump", "base", "0xffffeb4b3acd0000", "634880", "81920", "a1d6e49dbe1749e9e1fe735fb769a1dbc6ba92fd9e12de179d89ed1818dcae6d"}} {
		parameters := map[string]string{"dump": "true", tc.filter: tc.value}
		if tc.plugin == "windows.pedump" {
			parameters = map[string]string{"kernel-module": "true", "base": tc.value}
		}
		r, err := e.Run(ctx, tc.plugin, parameters, engine.RunOptions{})
		if err != nil || r.Task.Rows != 1 {
			t.Fatal(tc, r, err)
		}
		files, err := e.Store.Artifacts(ctx, r.Task.ID)
		if err != nil || len(files) != 1 {
			t.Fatal(files, err)
		}
		a := files[0]
		if a.Size != tc.size || a.MissingBytes != tc.missing || a.SHA256 != tc.sha || a.State != "completed_with_gaps" {
			t.Fatal(a)
		}
		if err = e.Store.VerifyTaskArtifacts(ctx, r.Task.ID); err != nil {
			t.Fatal(err)
		}
	}
	var mixed []evidence.Row
	r, err := e.Run(ctx, "windows.pedump", map[string]string{"pid": "384,488", "base": "0x7ff66e1d0000"}, engine.RunOptions{Emit: func(row evidence.Row) error { mixed = append(mixed, row); return nil }})
	if err == nil || r.Task.State != "failed" || r.Task.Rows != 2 || mixed[0].Cells["PID"].String() != "384" || mixed[0].Cells["FileOutput"].Reason != "invalid_or_unreadable_pe" || mixed[1].Cells["PID"].String() != "488" || mixed[1].Cells["FileOutput"].Kind != "artifact" {
		t.Fatal(r, mixed, err)
	}
	files, err := e.Store.Artifacts(ctx, r.Task.ID)
	if err != nil || len(files) != 1 || files[0].SHA256 != "abdc0769d35ed4f36912e5d4f5823e22abec4ccd3139db57bde9ee511bb6c269" {
		t.Fatal(files, err)
	}
}
