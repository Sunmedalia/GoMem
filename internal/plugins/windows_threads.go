package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func threadPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.threads", Upstream: "windows.threads.Threads", Platform: "windows", NeedsKernel: true,
		Description: "Enumerate active process threads with typed IDs, times and modern VAD start paths",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process/VAD traversal limit"}, {Name: "max-threads", Kind: "uint", Default: "1000000", Description: "Total thread traversal/output limit"}},
		Columns:     []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "PID", Kind: "uint64"}, {Name: "TID", Kind: "uint64"}, {Name: "StartAddress", Kind: "address"}, {Name: "StartPath", Kind: "string"}, {Name: "Win32StartAddress", Kind: "address"}, {Name: "Win32StartPath", Kind: "string"}, {Name: "CreateTime", Kind: "string"}, {Name: "ExitTime", Kind: "string"}, {Name: "CreateTimeRaw", Kind: "uint64"}, {Name: "ExitTimeRaw", Kind: "uint64"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "ProcessName", Kind: "string"}, {Name: "ListPID", Kind: "uint64"}, {Name: "OwnerPIDMatches", Kind: "string"}, {Name: "Identity", Kind: "string"}}}, windowsThreads}}
}
func windowsThreads(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	threadMax, err := strconv.ParseUint(p["max-threads"], 0, 32)
	if err != nil || threadMax == 0 || threadMax > 1000000 {
		return fmt.Errorf("max-threads must be 1..1000000")
	}
	list, err := e.Objects.Field("_EPROCESS", "ThreadListHead")
	if err != nil {
		return err
	}
	link, err := e.Objects.Field("_ETHREAD", "ThreadListEntry")
	if err != nil {
		return err
	}
	var count uint64
	return visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		head, err := memory.Add(process, list.Offset)
		if err != nil {
			return err
		}
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		processID := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		var regions []windowsVADPath
		var regionsErr error
		built := false
		return e.Objects.WalkList(ctx, head, link.Offset, int(threadMax), func(thread uint64) error {
			if count >= threadMax {
				return fmt.Errorf("thread count exceeds max-threads")
			}
			count++
			owner, err := e.Objects.Uint(ctx, thread, "_ETHREAD", "Cid.UniqueProcess")
			if err != nil {
				return err
			}
			tid, err := e.Objects.Uint(ctx, thread, "_ETHREAD", "Cid.UniqueThread")
			if err != nil {
				return err
			}
			start := optionalUint(ctx, e, thread, "_ETHREAD", "StartAddress", true)
			win32 := optionalUint(ctx, e, thread, "_ETHREAD", "Win32StartAddress", true)
			creation, rawCreate := windowsTime(ctx, e, thread, "_ETHREAD", "CreateTime")
			exit, rawExit := windowsTime(ctx, e, thread, "_ETHREAD", "ExitTime")
			if _, err := e.Objects.Field("_ETHREAD", "ThreadsProcess"); err == nil && rawCreate.Kind != "missing" {
				raw, _ := rawCreate.Uint()
				creation = windowsFiletime(raw >> 3)
			}
			pathAt := func(cell evidence.Value) evidence.Value {
				if cell.Kind == "missing" {
					return cell
				}
				if owner != pid {
					return evidence.Missing("owner_pid_mismatch", nil)
				}
				if pid == 4 {
					return evidence.Missing("system_thread_mapping_not_applicable", nil)
				}
				if !built {
					regions, regionsErr = windowsVADPaths(ctx, e, process, max)
					built = true
				}
				if regionsErr != nil {
					return evidence.Missing("vad_index_incomplete", regionsErr)
				}
				address, err := cell.Uint()
				if err != nil {
					return evidence.Missing("invalid_start_address", err)
				}
				return windowsPathAt(regions, address)
			}
			threadStamp := ""
			if rawCreate.Kind != "missing" {
				threadStamp = rawCreate.String()
			}
			identity := evidence.ThreadID(e.ImageHash, e.Kernel.Name(), thread, tid, threadStamp)
			return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(thread), "PID": evidence.Number(owner), "TID": evidence.Number(tid), "StartAddress": start, "StartPath": pathAt(start), "Win32StartAddress": win32, "Win32StartPath": pathAt(win32), "CreateTime": creation, "ExitTime": exit, "CreateTimeRaw": rawCreate, "ExitTimeRaw": rawExit, "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(processID), "ProcessName": evidence.Text(name), "ListPID": evidence.Number(pid), "OwnerPIDMatches": evidence.Text(strconv.FormatBool(owner == pid)), "Identity": evidence.Text(identity)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", thread)}})
		})
	})
}
