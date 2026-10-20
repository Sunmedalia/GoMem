package engine_test

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func envarsFixture(t *testing.T, env []byte, mutate func(data []byte)) testfixture.Fixture {
	t.Helper()
	f := psauxFixture(t, "native")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	mm := table.Types["mm_struct"]
	mm.Size = 80
	ptr := symbols.TypeRef{Kind: "pointer"}
	mm.Fields["env_start"] = symbols.Field{Offset: 64, Type: ptr}
	mm.Fields["env_end"] = symbols.Field{Offset: 72, Type: ptr}
	table.Types["mm_struct"] = mm
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	const start = 0x1c100
	if start+len(env) > len(data) {
		t.Fatal("environment does not fit the fixture image")
	}
	copy(data[start:], env)
	binary.LittleEndian.PutUint64(data[0xe040:], start)
	binary.LittleEndian.PutUint64(data[0xe048:], start+uint64(len(env)))
	if mutate != nil {
		mutate(data)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func runEnvars(t *testing.T, f testfixture.Fixture, params map[string]string) ([]evidence.Row, error) {
	t.Helper()
	e := openPsaux(t, f)
	var rows []evidence.Row
	result, err := e.Run(context.Background(), "linux.envars", params, engine.RunOptions{Emit: func(row evidence.Row) error {
		rows = append(rows, row)
		return nil
	}})
	if result.Task.State == "completed" && err != nil || result.Task.State == "failed" && err == nil {
		t.Fatal(result.Task.State, err)
	}
	return rows, err
}

func TestLinuxEnvarsRetainsRawBytesAndStopsAtMalformedEntries(t *testing.T) {
	env := []byte("PATH=/bin\x00HOME=/root\x00\x00")
	rows, err := runEnvars(t, envarsFixture(t, env, nil), nil)
	if err != nil || rows[len(rows)-1].Cells["RecordType"].String() != "summary" {
		t.Fatal(err, rows)
	}
	summary := rows[len(rows)-1]
	coverage := summary.Cells["Coverage"].Data.(map[string]any)
	if coverage["variables"] != "4" || coverage["user_tasks"] != "2" || coverage["diagnostics"] != nil || summary.Cells["Error"].Reason != "not_applicable" {
		t.Fatal(coverage, summary.Cells["Error"])
	}
	got := map[string][]string{}
	for _, row := range rows[:len(rows)-1] {
		if row.Cells["RecordType"].String() != "variable" {
			t.Fatal(row.Cells)
		}
		got[row.Cells["PID"].String()] = append(got[row.Cells["PID"].String()], row.Cells["Key"].String()+"="+row.Cells["Value"].String())
		if string(row.Cells["KeyRaw"].Data.([]byte)) == "HOME" && string(row.Cells["ValueRaw"].Data.([]byte)) != "/root" {
			t.Fatal(row.Cells["ValueRaw"])
		}
		if row.Cells["PPID"].String() == "100" && row.Cells["PID"].String() != "101" {
			t.Fatal(row.Cells["PID"], row.Cells["PPID"])
		}
	}
	if len(got["100"]) != 2 || got["100"][0] != "PATH=/bin" || got["100"][1] != "HOME=/root" || len(got["101"]) != 2 {
		t.Fatal(got)
	}

	bad := []byte("PATH=/bin\x00NOTPAIRED\x00HOME=/root")
	rows, err = runEnvars(t, envarsFixture(t, bad, nil), nil)
	if err == nil || rows[len(rows)-1].Cells["Error"].Reason != "environment_incomplete" {
		t.Fatal(err, rows)
	}
	var keys []string
	var stopped bool
	for _, row := range rows {
		if row.Cells["PID"].String() != "100" {
			continue
		}
		switch row.Cells["RecordType"].String() {
		case "variable":
			keys = append(keys, row.Cells["Key"].String())
		case "diagnostic":
			stopped = row.Cells["Error"].Reason == "environment_entry_malformed" && string(row.Cells["EntryRaw"].Data.([]byte)) == "NOTPAIRED"
		}
	}
	if !stopped || len(keys) != 1 || keys[0] != "PATH" {
		t.Fatal(keys, stopped)
	}
}

func TestLinuxEnvarsFiltersPidAndRejectsOversizedBlocks(t *testing.T) {
	env := []byte("A=1\xff\x00B=two=parts\x00")
	rows, err := runEnvars(t, envarsFixture(t, env, nil), map[string]string{"pid": "101"})
	if err != nil {
		t.Fatal(err)
	}
	var variables int
	for _, row := range rows {
		if row.Cells["RecordType"].String() != "variable" {
			continue
		}
		variables++
		if row.Cells["PID"].String() != "101" {
			t.Fatal(row.Cells["PID"])
		}
		if row.Cells["Key"].String() == "A" {
			raw := row.Cells["ValueRaw"].Data.([]byte)
			if string(raw) != "1\xff" || row.Cells["Value"].String() != "1\uFFFD" {
				t.Fatal(row.Cells["Value"], raw)
			}
		}
		if row.Cells["Key"].String() == "B" && row.Cells["Value"].String() != "two=parts" {
			t.Fatal(row.Cells["Value"])
		}
	}
	if variables != 2 {
		t.Fatal(variables, rows)
	}
	rows, err = runEnvars(t, envarsFixture(t, env, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0xb038:], 0)
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	var noMM bool
	for _, row := range rows {
		if row.Cells["PID"].String() == "101" && row.Cells["Error"].Reason == "no_user_mm" {
			noMM = true
		}
	}
	if !noMM || rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)["variables"] != "2" {
		t.Fatal(rows)
	}
	rows, err = runEnvars(t, envarsFixture(t, env, func(data []byte) {
		binary.LittleEndian.PutUint32(data[0xb050:], 0x00200000)
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	coverage := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
	if coverage["kernel_threads"] != "1" || coverage["variables"] != "2" {
		t.Fatal(coverage)
	}
	for _, row := range rows {
		if row.Cells["PID"].String() == "101" {
			t.Fatal("kernel thread emitted", row.Cells["RecordType"])
		}
	}
	rows, err = runEnvars(t, envarsFixture(t, env, nil), map[string]string{"max-env": "4"})
	if err == nil {
		t.Fatal("oversized environment succeeded")
	}
	var limited bool
	for _, row := range rows {
		if row.Cells["PID"].String() == "100" && row.Cells["Error"].Reason == "environment_size_limit" {
			limited = true
		}
	}
	if !limited {
		t.Fatal(rows)
	}
}
