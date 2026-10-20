package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func windowsPrivilegePlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.privileges", Upstream: "windows.privileges.Privs", Platform: "windows", NeedsKernel: true,
		Description: "List token privileges for active processes using the pinned privilege names",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process traversal bound"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"},
			{Name: "Process", Kind: "string"},
			{Name: "Value", Kind: "uint64"},
			{Name: "Privilege", Kind: "string"},
			{Name: "Attributes", Kind: "string"},
			{Name: "Description", Kind: "string"},
			{Name: "Token", Kind: "address"},
			{Name: "ProcessOffset", Kind: "address"},
			{Name: "ProcessIdentity", Kind: "string"},
			{Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"},
			{Name: "Coverage", Kind: "structure"},
		},
	}, windowsPrivileges}}
}

func windowsPrivileges(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.privileges requires a kernel layer and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	if _, err = e.Objects.Field("_EPROCESS", "Token.Object"); err != nil {
		return fmt.Errorf("windows.privileges requires _EPROCESS.Token as _EX_FAST_REF: %w", err)
	}
	privField, err := e.Objects.Field("_TOKEN", "Privileges")
	if err != nil {
		return fmt.Errorf("windows.privileges requires _TOKEN.Privileges: %w", err)
	}
	modern := privField.Type.Kind == "struct" || privField.Type.Kind == "union"
	if modern {
		for _, name := range []string{"Privileges.Present", "Privileges.Enabled", "Privileges.EnabledByDefault"} {
			if _, err = e.Objects.Field("_TOKEN", name); err != nil {
				return fmt.Errorf("windows.privileges requires %s: %w", name, err)
			}
		}
	} else if privField.Type.Kind == "pointer" {
		if _, err = e.Objects.Field("_TOKEN", "PrivilegeCount"); err != nil {
			return fmt.Errorf("windows.privileges requires PrivilegeCount for a pointer Privileges member: %w", err)
		}
	} else {
		return fmt.Errorf("windows.privileges: Privileges kind %s is unsupported", privField.Type.Kind)
	}
	var processes, skipped, broken, emitted int
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		rows, skip, broke, cause := processPrivileges(ctx, e, process, pid, name, created, modern)
		if skip {
			skipped++
			row := privilegeBase(e, process, pid, name, created)
			row.Cells["RecordType"] = evidence.Text("diagnostic")
			row.Cells["Error"] = evidence.Missing("token_unreadable", cause)
			return out(row)
		}
		if broke {
			broken++
		}
		if cause != nil {
			return cause
		}
		for _, row := range rows {
			emitted++
			if err := out(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := privilegeBase(e, 0, 0, "", evidence.Missing("not_applicable", nil))
	summary.Provenance.Offset = "0x0"
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{
		"processes": strconv.Itoa(processes),
		"skipped":   strconv.Itoa(skipped),
		"broken":    strconv.Itoa(broken),
		"rows":      strconv.Itoa(emitted),
		"layout":    map[bool]string{true: "bitmask", false: "luid"}[modern],
	}}
	return out(summary)
}

func processPrivileges(ctx context.Context, e plugin.Environment, process, pid uint64, name string, created evidence.Value, modern bool) ([]evidence.Row, bool, bool, error) {
	raw, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Token.Object")
	if err != nil {
		return nil, true, false, err
	}
	token := maskFastRef(raw, e.Symbols.PointerSize())
	if modern {
		rows, err := modernPrivileges(ctx, e, process, pid, name, created, token)
		return rows, false, false, err
	}
	rows, broken, err := xpPrivileges(ctx, e, process, pid, name, created, token)
	return rows, false, broken, err
}

func modernPrivileges(ctx context.Context, e plugin.Environment, process, pid uint64, name string, created evidence.Value, token uint64) ([]evidence.Row, error) {
	present, err := e.Objects.Uint(ctx, token, "_TOKEN", "Privileges.Present")
	if err != nil {
		return nil, err
	}
	enabled, err := e.Objects.Uint(ctx, token, "_TOKEN", "Privileges.Enabled")
	if err != nil {
		return nil, err
	}
	fallback, err := e.Objects.Uint(ctx, token, "_TOKEN", "Privileges.EnabledByDefault")
	if err != nil {
		return nil, err
	}
	var rows []evidence.Row
	for index := 0; index < 64; index++ {
		info, ok := windowsPrivilegeInfo[index]
		if !ok {
			continue
		}
		bit := uint64(1) << index
		rows = append(rows, privilegeRow(e, process, pid, name, created, token, index, info, present&bit != 0, enabled&bit != 0, fallback&bit != 0))
	}
	return rows, nil
}

func xpPrivileges(ctx context.Context, e plugin.Environment, process, pid uint64, name string, created evidence.Value, token uint64) ([]evidence.Row, bool, error) {
	count, err := e.Objects.Uint(ctx, token, "_TOKEN", "PrivilegeCount")
	if err != nil {
		return nil, false, err
	}
	if count >= 1024 {
		return nil, true, nil
	}
	target, err := e.Objects.Uint(ctx, token, "_TOKEN", "Privileges")
	if err != nil {
		return nil, false, err
	}
	size, err := e.Objects.Size(symbols.TypeRef{Kind: "struct", Name: "_LUID_AND_ATTRIBUTES"})
	if err != nil || size == 0 {
		return nil, false, fmt.Errorf("windows.privileges requires _LUID_AND_ATTRIBUTES: %w", err)
	}
	var rows []evidence.Row
	for i := uint64(0); i < count; i++ {
		element, err := memory.Add(target, i*size)
		if err != nil {
			return nil, false, err
		}
		value, err := e.Objects.Uint(ctx, element, "_LUID_AND_ATTRIBUTES", "Luid.LowPart")
		if err != nil {
			return nil, false, err
		}
		attributes, err := e.Objects.Uint(ctx, element, "_LUID_AND_ATTRIBUTES", "Attributes")
		if err != nil {
			return nil, false, err
		}
		if value > 63 {
			continue
		}
		info, ok := windowsPrivilegeInfo[int(value)]
		if !ok {
			continue
		}
		rows = append(rows, privilegeRow(e, process, pid, name, created, token, int(value), info, true, attributes&2 != 0, attributes&1 != 0))
	}
	return rows, false, nil
}

func privilegeRow(e plugin.Environment, process, pid uint64, name string, created evidence.Value, token uint64, value int, info privilegeName, present, enabled, fallback bool) evidence.Row {
	row := privilegeBase(e, process, pid, name, created)
	row.Cells["RecordType"] = evidence.Text("privilege")
	row.Cells["Value"] = evidence.Number(uint64(value))
	row.Cells["Privilege"] = evidence.Text(info.Name)
	row.Cells["Attributes"] = evidence.Text(privilegeAttributes(present, enabled, fallback))
	row.Cells["Description"] = evidence.Text(info.Description)
	row.Cells["Token"] = evidence.Address(token)
	row.Provenance.Offset = fmt.Sprintf("0x%x", token)
	return row
}

func privilegeBase(e plugin.Environment, process, pid uint64, name string, created evidence.Value) evidence.Row {
	stamp := ""
	if created.Kind != "missing" {
		stamp = created.String()
	}
	layer := ""
	if e.Kernel != nil {
		layer = e.Kernel.Name()
	}
	row := evidence.Row{Cells: map[string]evidence.Value{
		"PID": evidence.Number(pid), "Process": evidence.Text(name),
		"Value": evidence.Missing("not_applicable", nil), "Privilege": evidence.Missing("not_applicable", nil),
		"Attributes": evidence.Missing("not_applicable", nil), "Description": evidence.Missing("not_applicable", nil),
		"Token": evidence.Missing("not_applicable", nil), "ProcessOffset": evidence.Address(process),
		"ProcessIdentity": evidence.Text(evidence.ProcessID(e.ImageHash, layer, process, pid, stamp)),
		"RecordType":      evidence.Missing("not_applicable", nil),
		"Error":           evidence.Missing("not_applicable", nil),
		"Coverage":        evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", process)}}
	return row
}

func privilegeAttributes(present, enabled, fallback bool) string {
	var parts []string
	if present {
		parts = append(parts, "Present")
	}
	if enabled {
		parts = append(parts, "Enabled")
	}
	if fallback {
		parts = append(parts, "Default")
	}
	return strings.Join(parts, ",")
}

func maskFastRef(value uint64, pointerBytes int) uint64 {
	if pointerBytes <= 4 {
		return value &^ 7
	}
	return value &^ 15
}

type privilegeName struct{ Name, Description string }

// Names and descriptions are the pinned sids_and_privileges.json privilege table.
var windowsPrivilegeInfo = map[int]privilegeName{
	2:  {"SeCreateTokenPrivilege", "Create a token object"},
	3:  {"SeAssignPrimaryTokenPrivilege", "Replace a process-level token"},
	4:  {"SeLockMemoryPrivilege", "Lock pages in memory"},
	5:  {"SeIncreaseQuotaPrivilege", "Increase quotas"},
	6:  {"SeMachineAccountPrivilege", "Add workstations to the domain"},
	7:  {"SeTcbPrivilege", "Act as part of the operating system"},
	8:  {"SeSecurityPrivilege", "Manage auditing and security log"},
	9:  {"SeTakeOwnershipPrivilege", "Take ownership of files/objects"},
	10: {"SeLoadDriverPrivilege", "Load and unload device drivers"},
	11: {"SeSystemProfilePrivilege", "Profile system performance"},
	12: {"SeSystemtimePrivilege", "Change the system time"},
	13: {"SeProfileSingleProcessPrivilege", "Profile a single process"},
	14: {"SeIncreaseBasePriorityPrivilege", "Increase scheduling priority"},
	15: {"SeCreatePagefilePrivilege", "Create a pagefile"},
	16: {"SeCreatePermanentPrivilege", "Create permanent shared objects"},
	17: {"SeBackupPrivilege", "Backup files and directories"},
	18: {"SeRestorePrivilege", "Restore files and directories"},
	19: {"SeShutdownPrivilege", "Shut down the system"},
	20: {"SeDebugPrivilege", "Debug programs"},
	21: {"SeAuditPrivilege", "Generate security audits"},
	22: {"SeSystemEnvironmentPrivilege", "Edit firmware environment values"},
	23: {"SeChangeNotifyPrivilege", "Receive notifications of changes to files or directories"},
	24: {"SeRemoteShutdownPrivilege", "Force shutdown from a remote system"},
	25: {"SeUndockPrivilege", "Remove computer from docking station"},
	26: {"SeSyncAgentPrivilege", "Synch directory service data"},
	27: {"SeEnableDelegationPrivilege", "Enable user accounts to be trusted for delegation"},
	28: {"SeManageVolumePrivilege", "Manage the files on a volume"},
	29: {"SeImpersonatePrivilege", "Impersonate a client after authentication"},
	30: {"SeCreateGlobalPrivilege", "Create global objects"},
	31: {"SeTrustedCredManAccessPrivilege", "Access Credential Manager as a trusted caller"},
	32: {"SeRelabelPrivilege", "Modify the mandatory integrity level of an object"},
	33: {"SeIncreaseWorkingSetPrivilege", "Allocate more memory for user applications"},
	34: {"SeTimeZonePrivilege", "Adjust the time zone of the computer's internal clock"},
	35: {"SeCreateSymbolicLinkPrivilege", "Required to create a symbolic link"},
	36: {"SeDelegateSessionUserImpersonatePrivilege", "Obtain an impersonation token for another user in the same session."},
}
