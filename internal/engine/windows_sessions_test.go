package engine_test

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
)

func TestWindowsSessionsUsersAndUnavailableEnv(t *testing.T) {
	f := windowsEnvarFixture(t, true)
	env := windowsEnvUTF16("USERDOMAIN=CORP\x00USERNAME=first\x00username=alice\x00SESSIONNAME=Console\x00")
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1e110:], 0x1f800)
		binary.LittleEndian.PutUint64(data[0x1e118:], uint64(len(env)))
		copy(data[0x1f800:], env)
	})
	rows, state, err := windowsSessionRows(t, f, nil)
	if err != nil || state != "completed" {
		t.Fatal(state, err, windowsSessionBrief(rows))
	}
	if got := windowsSessionLine(rows, "4"); got != "4 System <not_applicable> <not_available> <not_available>" {
		t.Fatal(got)
	}
	if got := windowsSessionLine(rows, "104"); got != "104 worker.exe 1 Console CORP/alice" {
		t.Fatal(got)
	}
	worker := windowsSessionFind(rows, "104")
	if worker.Cells["CreateTime"].Kind != "string" || !strings.Contains(worker.Cells["CreateTime"].String(), "T") || worker.Cells["Error"].Reason != "not_applicable" {
		t.Fatal(worker.Cells)
	}
	rows, state, err = windowsSessionRows(t, f, map[string]string{"pid": "104"})
	if err != nil || state != "completed" || len(windowsSessionBrief(rows)) != 2 || windowsSessionLine(rows, "104") != "104 worker.exe 1 Console CORP/alice" {
		t.Fatal(state, err, windowsSessionBrief(rows))
	}

	f = windowsEnvarFixture(t, true)
	editWindowsImage(t, f, func(data []byte) {
		binary.LittleEndian.PutUint64(data[0x1e110:], 0x300000)
		binary.LittleEndian.PutUint64(data[0x1e118:], 8)
	})
	rows, state, err = windowsSessionRows(t, f, map[string]string{"pid": "104"})
	if err == nil || state != "failed" || windowsSessionLine(rows, "104") != "104 worker.exe 1 <not_available> <not_available>" || rows[0].Cells["Error"].Error == "" {
		t.Fatal(state, err, windowsSessionBrief(rows))
	}
}

func windowsSessionRows(t *testing.T, f testfixture.Fixture, params map[string]string) ([]evidence.Row, string, error) {
	t.Helper()
	var rows []evidence.Row
	result, err := openWindowsImage(t, f).Run(context.Background(), "windows.sessions", params, engine.RunOptions{Emit: engineRun(t, &rows)})
	return rows, result.Task.State, err
}

func windowsSessionFind(rows []evidence.Row, pid string) evidence.Row {
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "session" && row.Cells["PID"].String() == pid {
			return row
		}
	}
	return evidence.Row{}
}

func windowsSessionLine(rows []evidence.Row, pid string) string {
	row := windowsSessionFind(rows, pid)
	cell := func(name string) string {
		value := row.Cells[name]
		if value.Kind == "missing" {
			return "<" + value.Reason + ">"
		}
		return value.String()
	}
	return strings.Join([]string{cell("PID"), cell("Process"), cell("SessionID"), cell("SessionType"), cell("UserName")}, " ")
}

func windowsSessionBrief(rows []evidence.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Cells["RecordType"].String() == "summary" {
			out = append(out, "summary")
			continue
		}
		out = append(out, windowsSessionLine([]evidence.Row{row}, row.Cells["PID"].String())+" "+row.Cells["Error"].Reason)
	}
	return out
}
