package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func TestWindowsEnvarsParseQuirkCapAndFallback(t *testing.T) {
	f := windowsEnvarFixture(t, true)
	env := windowsEnvUTF16("USERNAME=alice\x00PATH=C:\\Windows\x00NOEQUALS\x00SKIP=\x00=NO\x00LAST=drop")
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1e110:], 0x1f800)
		binary.LittleEndian.PutUint64(data[0x1e118:], uint64(len(env)))
		copy(data[0x1f800:], env)
	})
	rows, state, err := windowsEnvarRows(t, f, nil)
	if err != nil || state != "completed" {
		t.Fatal(state, err, windowsEnvarBrief(rows))
	}
	vars := windowsEnvarValues(rows)
	if strings.Join(vars, "|") != "USERNAME=alice|PATH=C:\\Windows|NOEQUAL=NOEQUALS" {
		t.Fatal(vars)
	}
	if rows[0].Cells["RecordType"].String() != "diagnostic" || rows[0].Cells["PID"].String() != "4" || rows[0].Cells["Error"].Reason != "no_process_peb" {
		t.Fatal(rows[0].Cells)
	}
	variable := rows[1]
	if variable.Cells["Block"].String() != "0x1e110" || variable.Cells["Process"].String() != "worker.exe" || variable.Cells["SizeField"].String() != "EnvironmentSize" || variable.Provenance.Offset != "0x1f800" {
		t.Fatal(variable.Cells, variable.Provenance)
	}
	rows, state, err = windowsEnvarRows(t, f, map[string]string{"silent": "true", "pid": "104"})
	if err != nil || state != "completed" || strings.Join(windowsEnvarValues(rows), "|") != "USERNAME=alice|PATH=C:\\Windows|NOEQUAL=NOEQUALS" {
		t.Fatal(state, err, windowsEnvarBrief(rows))
	}
	summary := rows[len(rows)-1].Cells["Coverage"].Data.(map[string]any)
	if summary["silent_requested"] != "1" || summary["silent_applied"] != "0" || summary["variables"] != "3" {
		t.Fatal(summary)
	}

	f = windowsEnvarFixture(t, true)
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1e110:], 0x1f800)
		binary.LittleEndian.PutUint64(data[0x1e118:], uint64(len(env)+1))
		copy(data[0x1f800:], append(append([]byte{}, env...), 0x41))
	})
	rows, state, err = windowsEnvarRows(t, f, map[string]string{"pid": "104"})
	if err != nil || state != "completed" || strings.Join(windowsEnvarValues(rows), "|") != "USERNAME=alice|PATH=C:\\Windows|NOEQUAL=NOEQUALS" {
		t.Fatal("odd tail changed variables", state, err, windowsEnvarBrief(rows))
	}

	f = windowsEnvarFixture(t, true)
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1e110:], 0x1f800)
		binary.LittleEndian.PutUint64(data[0x1e118:], 32)
		copy(data[0x1f800:], env)
	})
	rows, state, err = windowsEnvarRows(t, f, map[string]string{"pid": "104", "max-env": "8"})
	if err == nil || state != "failed" || len(windowsEnvarValues(rows)) != 0 || rows[0].Cells["Error"].Reason != "environment_size_limit" {
		t.Fatal(state, err, windowsEnvarBrief(rows))
	}

	f = windowsEnvarFixture(t, true)
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1e110:], 0x300000)
		binary.LittleEndian.PutUint64(data[0x1e118:], 8)
	})
	rows, state, err = windowsEnvarRows(t, f, map[string]string{"pid": "104"})
	if err == nil || state != "failed" || len(windowsEnvarValues(rows)) != 0 || rows[0].Cells["Error"].Reason != "environment_buffer_unreadable" || rows[0].Cells["Error"].Error == "" {
		t.Fatal(state, err, windowsEnvarBrief(rows))
	}

	f = windowsEnvarFixture(t, false)
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1e110:], 0x1f800)
		binary.LittleEndian.PutUint32(data[0x1e118:], uint32(len(env)))
		copy(data[0x1f800:], env)
	})
	rows, state, err = windowsEnvarRows(t, f, map[string]string{"pid": "104"})
	if err != nil || state != "completed" || rows[0].Cells["SizeField"].String() != "Length" || strings.Join(windowsEnvarValues(rows), "|") != "USERNAME=alice|PATH=C:\\Windows|NOEQUAL=NOEQUALS" {
		t.Fatal(state, err, windowsEnvarBrief(rows))
	}
}

func windowsEnvarFixture(t *testing.T, sized bool) testfixture.Fixture {
	t.Helper()
	f := dllFixture(t, "native")
	raw, err := os.ReadFile(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	var table symbols.ISF
	if err = json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	params := table.Types["_RTL_USER_PROCESS_PARAMETERS"]
	params.Size = 40
	params.Fields["Environment"] = symbols.Field{Offset: 16, Type: symbols.TypeRef{Kind: "pointer"}}
	if sized {
		params.Fields["EnvironmentSize"] = symbols.Field{Offset: 24, Type: symbols.TypeRef{Kind: "base", Name: "u64"}}
	} else {
		params.Fields["Length"] = symbols.Field{Offset: 24, Type: symbols.TypeRef{Kind: "base", Name: "u32"}}
	}
	table.Types["_RTL_USER_PROCESS_PARAMETERS"] = params
	encoded, err := json.MarshalIndent(&table, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func windowsEnvUTF16(s string) []byte {
	units := utf16.Encode([]rune(s))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return raw
}

func windowsEnvarRows(t *testing.T, f testfixture.Fixture, params map[string]string) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.envars", params, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}

func windowsEnvarValues(rows []evidence.Row) []string {
	out := make([]string, 0)
	for _, row := range rows {
		if row.Cells["RecordType"].String() != "variable" {
			continue
		}
		out = append(out, row.Cells["Variable"].String()+"="+row.Cells["Value"].String())
	}
	return out
}

func windowsEnvarBrief(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Cells["RecordType"].String()+" "+row.Cells["PID"].String()+" "+row.Cells["Variable"].String()+" "+row.Cells["Error"].Reason)
	}
	return out
}
