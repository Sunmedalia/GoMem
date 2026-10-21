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

func windowsSuspiciousThreadPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.suspicious_threads", Upstream: "windows.malware.suspicious_threads.SuspiciousThreads", Platform: "windows", NeedsKernel: true,
		Description: "Find live threads starting in non-file VADs, unexpected protection or another executable mapping",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Active-process and VAD bound; not an upstream parameter"}, {Name: "max-threads", Kind: "uint", Default: "1000000", Description: "Total thread traversal bound; not an upstream parameter"}},
		Columns:     []evidence.Column{{Name: "Process", Kind: "string"}, {Name: "PID", Kind: "uint64"}, {Name: "TID", Kind: "uint64"}, {Name: "Context", Kind: "string"}, {Name: "Address", Kind: "address"}, {Name: "VADPath", Kind: "string"}, {Name: "Note", Kind: "string"}, {Name: "Rule", Kind: "string"}, {Name: "Protection", Kind: "string"}, {Name: "VADOffset", Kind: "address"}, {Name: "VADBase", Kind: "address"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "ThreadOffset", Kind: "address"}, {Name: "ThreadIdentity", Kind: "string"}, {Name: "RawAddress", Kind: "address"}, {Name: "PathError", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"}, {Name: "Error", Kind: "string"}},
	}, windowsSuspiciousThreads}}
}

type suspiciousThreadFinding struct {
	path, note, rule string
	region           analysisVADRange
}

func suspiciousThreadNotes(exePath string, ranges []analysisVADRange, address uint64) []suspiciousThreadFinding {
	region, ok := analysisThreadRange(ranges, address)
	if !ok {
		return nil
	}
	path := ""
	if region.file.Kind == "string" {
		path = region.file.String()
	}
	var notes []suspiciousThreadFinding
	add := func(rule, note string) { notes = append(notes, suspiciousThreadFinding{path, note, rule, region}) }
	if region.file.Kind != "string" {
		path = "<Non-File Backed Region>"
		add("non_file_backed", fmt.Sprintf("This thread started execution in the VAD starting at base address (%#x), which is not backed by a file", region.start))
	}
	if region.protection != "PAGE_EXECUTE_WRITECOPY" {
		add("unexpected_protection", fmt.Sprintf("VAD at base address (%#x) hosting this thread has an unexpected starting protection %s", region.start, region.protection))
	}
	if exePath != "" && strings.HasSuffix(strings.ToLower(path), ".exe") && strings.ToLower(path) != strings.ToLower(exePath) {
		// This is a literal string (not an f-string) in the pinned plugin.
		add("other_executable", "VAD at base address ({vad_base:#x}) hosting this thread maps an application executable that is not the process executable")
	}
	return notes
}

type suspiciousThreadStats struct{ processes, shortVADs, threads, exited, gatherSkipped, addresses, duplicates, outside, findings, pathErrors uint64 }

func suspiciousThreadRow(layer string, thread uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", thread)}}
	for _, column := range windowsSuspiciousThreadPlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	return row
}
func windowsSuspiciousThreads(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.suspicious_threads requires a kernel layer and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	maxThreads, err := strconv.ParseUint(p["max-threads"], 0, 32)
	if err != nil || maxThreads == 0 || maxThreads > 1000000 {
		return fmt.Errorf("max-threads must be 1..1000000")
	}
	for _, check := range []struct{ typ, path string }{{"_EPROCESS", "SectionBaseAddress"}, {"_EPROCESS", "ThreadListHead"}, {"_ETHREAD", "ThreadListEntry"}, {"_ETHREAD", "Tcb.State"}, {"_ETHREAD", "ExitTime.QuadPart"}, {"_ETHREAD", "Cid.UniqueProcess"}, {"_ETHREAD", "Cid.UniqueThread"}, {"_ETHREAD", "StartAddress"}, {"_ETHREAD", "Win32StartAddress"}, {"_ETHREAD", "CreateTime"}} {
		if _, err = e.Objects.Field(check.typ, check.path); err != nil {
			return err
		}
	}
	width := e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return fmt.Errorf("unsupported thread pointer width %d", width)
	}
	list, _ := e.Objects.Field("_EPROCESS", "ThreadListHead")
	link, _ := e.Objects.Field("_ETHREAD", "ThreadListEntry")
	protect := vadProtectionCache{env: e}
	stats := suspiciousThreadStats{}
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		stats.processes++
		ranges, err := analysisVADRanges(ctx, e, process, max, &protect)
		if err != nil {
			return fmt.Errorf("process %#x VAD analysis: %w", process, err)
		}
		if len(ranges) < 5 {
			stats.shortVADs++
			return nil
		}
		section, err := e.Objects.Uint(ctx, process, "_EPROCESS", "SectionBaseAddress")
		if err != nil {
			return err
		}
		exePath := ""
		if region, found := analysisThreadRange(ranges, pointerIdentity(section, width)); found && region.file.Kind == "string" {
			exePath = region.file.String()
		}
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		processID := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		checked := map[uint64]bool{}
		head, err := memory.Add(process, list.Offset)
		if err != nil {
			return err
		}
		return e.Objects.WalkList(ctx, head, link.Offset, int(maxThreads), func(thread uint64) error {
			if stats.threads >= maxThreads {
				return fmt.Errorf("suspicious thread traversal exceeds max-threads")
			}
			stats.threads++
			exit, err := e.Objects.Int(ctx, thread, "_ETHREAD", "ExitTime.QuadPart")
			if err != nil {
				return err
			}
			if exit > 0 {
				stats.exited++
				return nil
			}
			state, err := e.Objects.Uint(ctx, thread, "_ETHREAD", "Tcb.State")
			if err != nil {
				return err
			}
			if state == 4 {
				stats.exited++
				return nil
			}
			info, err := gatherSuspiciousThread(ctx, e, thread)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				stats.gatherSkipped++
				row := suspiciousThreadRow(e.Kernel.Name(), thread)
				row.Cells["ThreadOffset"] = evidence.Address(thread)
				row.Cells["ProcessOffset"] = evidence.Address(process)
				row.Cells["ProcessIdentity"] = evidence.Text(processID)
				row.Cells["RecordType"] = evidence.Text("diagnostic")
				row.Cells["Error"] = evidence.Text(err.Error())
				return out(row)
			}
			if info.pid == 0 || info.pid > 0xfffffffc || info.pid%4 != 0 {
				stats.gatherSkipped++
				return nil
			}
			threadID := evidence.ThreadID(e.ImageHash, e.Kernel.Name(), thread, info.tid, info.created.String())
			for _, item := range []struct {
				raw     uint64
				context string
			}{{info.start, "Start"}, {info.win32, "Win32Start"}} {
				address := pointerIdentity(item.raw, width)
				if checked[address] {
					stats.duplicates++
					continue
				}
				checked[address] = true
				stats.addresses++
				if _, found := analysisThreadRange(ranges, address); !found {
					stats.outside++
					continue
				}
				for _, finding := range suspiciousThreadNotes(exePath, ranges, address) {
					stats.findings++
					row := suspiciousThreadRow(e.Kernel.Name(), thread)
					row.Cells["Process"] = evidence.Text(name)
					row.Cells["PID"] = evidence.Number(pid)
					row.Cells["TID"] = evidence.Number(info.tid)
					row.Cells["Context"] = evidence.Text(item.context)
					row.Cells["Address"] = evidence.Address(address)
					row.Cells["RawAddress"] = evidence.Address(item.raw)
					row.Cells["VADPath"] = evidence.Text(finding.path)
					row.Cells["Note"] = evidence.Text(finding.note)
					row.Cells["Rule"] = evidence.Text(finding.rule)
					row.Cells["Protection"] = evidence.Text(finding.region.protection)
					row.Cells["VADOffset"] = evidence.Address(finding.region.address)
					row.Cells["VADBase"] = evidence.Address(finding.region.start)
					row.Cells["ProcessOffset"] = evidence.Address(process)
					row.Cells["ProcessIdentity"] = evidence.Text(processID)
					row.Cells["ThreadOffset"] = evidence.Address(thread)
					row.Cells["ThreadIdentity"] = evidence.Text(threadID)
					row.Cells["RecordType"] = evidence.Text("finding")
					if finding.region.file.Error != "" {
						stats.pathErrors++
						row.Cells["PathError"] = finding.region.file
					}
					if err = out(row); err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	row := suspiciousThreadRow(e.Kernel.Name(), 0)
	row.Provenance.Offset = ""
	row.Cells["RecordType"] = evidence.Text("summary")
	row.Cells["Coverage"] = poolCoverage(map[string]string{"processes": formatCount(stats.processes), "short_vad_sets": formatCount(stats.shortVADs), "threads": formatCount(stats.threads), "exited": formatCount(stats.exited), "gather_skipped": formatCount(stats.gatherSkipped), "unique_addresses": formatCount(stats.addresses), "duplicates": formatCount(stats.duplicates), "outside_vad": formatCount(stats.outside), "findings": formatCount(stats.findings), "path_read_errors": formatCount(stats.pathErrors)})
	return out(row)
}

type suspiciousThreadInfo struct {
	pid, tid, start, win32 uint64
	created                evidence.Value
}

func gatherSuspiciousThread(ctx context.Context, e plugin.Environment, thread uint64) (suspiciousThreadInfo, error) {
	var info suspiciousThreadInfo
	for _, item := range []struct {
		path   string
		target *uint64
	}{{"Cid.UniqueProcess", &info.pid}, {"Cid.UniqueThread", &info.tid}, {"StartAddress", &info.start}, {"Win32StartAddress", &info.win32}} {
		value, err := e.Objects.Uint(ctx, thread, "_ETHREAD", item.path)
		if err != nil {
			return info, err
		}
		*item.target = value
	}
	info.pid = pointerIdentity(info.pid, e.Symbols.PointerSize())
	info.tid = pointerIdentity(info.tid, e.Symbols.PointerSize())
	_, raw, err := threadDisplayedTime(ctx, e.Objects, thread, "_ETHREAD", "CreateTime", true)
	if err != nil {
		return info, err
	}
	info.created = raw
	_, _, err = threadDisplayedTime(ctx, e.Objects, thread, "_ETHREAD", "ExitTime", false)
	return info, err
}
