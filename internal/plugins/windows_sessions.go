package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsSessionPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.sessions", Upstream: "windows.sessions.Sessions", Platform: "windows", NeedsKernel: true,
		Description: "List active processes with session IDs and users taken from USERNAME, USERDOMAIN and SESSIONNAME",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process traversal bound"},
			{Name: "max-env", Kind: "uint", Default: "1048576", Description: "Environment byte limit, 1..16777216; native bound, not an upstream parameter"},
		},
		Columns: []evidence.Column{
			{Name: "SessionID", Kind: "uint64"},
			{Name: "SessionType", Kind: "string"},
			{Name: "PID", Kind: "uint64"},
			{Name: "Process", Kind: "string"},
			{Name: "UserName", Kind: "string"},
			{Name: "CreateTime", Kind: "string"},
			{Name: "CreateTimeRaw", Kind: "uint64"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "ProcessIdentity", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsSessions}}
}

func windowsSessions(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	maxEnv, err := strconv.ParseUint(p["max-env"], 0, 32)
	if err != nil || maxEnv == 0 || maxEnv > memory.MaxRead {
		return fmt.Errorf("max-env must be 1..%d", memory.MaxRead)
	}
	var failures pluginFailures
	var processes int
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		row, cause := windowsSessionRow(ctx, e, process, pid, name, maxEnv)
		processes++
		failures.add(cause)
		return out(row)
	})
	if err != nil {
		return err
	}
	summary := windowsSessionBlank(e, e.Kernel.Name(), "0x0")
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"processes": strconv.Itoa(processes),
		"failures":  strconv.Itoa(failures.count),
	}}
	if cause := failures.err("Windows sessions"); cause != nil {
		summary.Cells["Error"] = evidence.Missing("sessions_incomplete", cause)
	}
	if err = out(summary); err != nil {
		return err
	}
	return failures.err("Windows sessions")
}

func windowsSessionRow(ctx context.Context, e plugin.Environment, process, pid uint64, name string, maxEnv uint64) (evidence.Row, error) {
	stamp := ""
	created, _ := windowsTime(ctx, e, process, "_EPROCESS", "CreateTime")
	if created.Kind != "missing" {
		stamp = created.String()
	}
	identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
	row := windowsSessionBlank(e, e.Kernel.Name(), fmt.Sprintf("0x%x", process))
	row.Cells["RecordType"] = evidence.Text("session")
	row.Cells["PID"] = evidence.Number(pid)
	row.Cells["Process"] = evidence.Text(name)
	row.Cells["ProcessOffset"] = evidence.Address(process)
	row.Cells["ProcessIdentity"] = evidence.Text(identity)
	var cause error
	row.Cells["SessionID"], cause = sessionComparable(windowsSessionID(ctx, e, process))
	when, raw := windowsTime(ctx, e, process, "_EPROCESS", "CreateTime")
	row.Cells["CreateTimeRaw"] = raw
	compared, timeErr := sessionComparable(when)
	row.Cells["CreateTime"] = compared
	if cause == nil {
		cause = timeErr
	}
	envRows, envErr := readWindowsEnvironment(ctx, e, process, pid, name, created, maxEnv)
	if cause == nil {
		cause = envErr
	}
	user, domain, sessionName, sawSession := sessionIdentity(envRows)
	full := domain + "/" + user
	if full == "/" {
		row.Cells["UserName"] = evidence.Missing("not_available", nil)
	} else {
		row.Cells["UserName"] = evidence.Text(full)
	}
	if sawSession {
		row.Cells["SessionType"] = evidence.Text(sessionName)
	} else {
		row.Cells["SessionType"] = evidence.Missing("not_available", nil)
	}
	if cause != nil {
		row.Cells["Error"] = evidence.Missing("session_incomplete", cause)
	}
	return row, cause
}

func sessionIdentity(rows []evidence.Row) (user, domain, session string, sawSession bool) {
	for _, row := range rows {
		if row.Cells["RecordType"].String() != "variable" {
			continue
		}
		switch strings.ToLower(row.Cells["Variable"].String()) {
		case "username":
			user = row.Cells["Value"].String()
		case "userdomain":
			domain = row.Cells["Value"].String()
		case "sessionname":
			session = row.Cells["Value"].String()
			sawSession = true
		}
	}
	return user, domain, session, sawSession
}

func sessionComparable(value evidence.Value) (evidence.Value, error) {
	if value.Kind != "missing" || value.Error == "" {
		return value, nil
	}
	err := fmt.Errorf("%s", value.Error)
	value.Error = ""
	return value, err
}

func windowsSessionBlank(e plugin.Environment, layer, offset string) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: offset}}
	for _, column := range windowsSessionPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	return row
}
