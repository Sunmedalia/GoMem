package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsProcessGhostingPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.processghosting", Upstream: "windows.malware.processghosting.ProcessGhosting", Platform: "windows", NeedsKernel: true,
		Description: "Check active user processes and mapped files for deletion-related state",
		Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process and per-process VAD traversal bound; native parameter"}, {Name: "max-vads", Kind: "uint", Default: "1000000", Description: "Aggregate VAD bound; native parameter"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Base", Kind: "address"}, {Name: "FILE_OBJECT", Kind: "address"}, {Name: "DeletePending", Kind: "uint64"}, {Name: "DeleteOnClose", Kind: "uint64"}, {Name: "Path", Kind: "string"}, {Name: "Rule", Kind: "string"}, {Name: "DeletePendingRaw", Kind: "uint64"}, {Name: "DeleteOnCloseRaw", Kind: "uint64"}, {Name: "ImageFileRaw", Kind: "address"}, {Name: "ImageFilePointerOffset", Kind: "address"}, {Name: "VADOffset", Kind: "address"}, {Name: "ControlArea", Kind: "address"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"}, {Name: "Error", Kind: "string"}},
	}, windowsProcessGhosting}}
}

type ghostFinding struct {
	file, base     uint64
	pending, close *uint64
	rule           string
}

func ghostProcessFindings(file, base uint64, pending *uint64) []ghostFinding {
	// The process check rejects smeared DeletePending values; the VAD check
	// compares exactly to one, and does not apply this normalization.
	if pending != nil && *pending != 0 && *pending != 1 {
		pending = nil
	}
	if file == 0 || pending != nil && *pending == 1 {
		return []ghostFinding{{file: file, base: base, pending: pending, rule: "image_file_state"}}
	}
	return nil
}
func ghostVADFindings(file, base uint64, path string, pending, close *uint64) []ghostFinding {
	var result []ghostFinding
	path = strings.ToLower(path)
	if close != nil && *close != 0 && (strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dll")) {
		result = append(result, ghostFinding{file: file, base: base, close: close, rule: "vad_delete_on_close"})
	}
	if pending != nil && *pending == 1 {
		result = append(result, ghostFinding{file: file, base: base, pending: pending, rule: "vad_delete_pending"})
	}
	return result
}
func ghostRow(layer string, process uint64) evidence.Row {
	r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", process)}}
	for _, c := range windowsProcessGhostingPlugins()[0].spec.Columns {
		r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
	}
	return r
}

// The pinned filter compares two fresh UnreadableValue objects by identity.
// Even an unreadable handle count passes that comparison. Preserve the observed
// predicate instead of strengthening it into a new applicability requirement.
func ghostActiveProcess(ctx context.Context, e plugin.Environment, process, pid uint64, issue func(string, error) error) (bool, error) {
	valid, err := processObjectValid(ctx, e.Objects, process)
	if err != nil || !valid {
		return false, err
	}
	threads, err := e.Objects.Uint(ctx, process, "_EPROCESS", "ActiveThreads")
	if err != nil {
		return false, err
	}
	if threads == 0 || pid == 4 {
		return false, nil
	}
	parent, err := e.Objects.Uint(ctx, process, "_EPROCESS", "InheritedFromUniqueProcessId")
	if err != nil {
		return false, err
	}
	if parent == 4 {
		return false, nil
	}
	exit, err := windowsRawTime(ctx, e, process, "_EPROCESS", "ExitTime")
	if err != nil {
		return false, err
	}
	if exit != 0 {
		return false, nil
	}
	if _, err = e.Objects.Field("_HANDLE_TABLE", "HandleCount"); err != nil {
		if errors.Is(err, object.ErrFieldAbsent) {
			return true, nil
		}
		return false, err
	}
	if _, err = e.Objects.Field("_EPROCESS", "ObjectTable"); err != nil {
		if errors.Is(err, object.ErrFieldAbsent) {
			return true, nil
		}
		return false, err
	}
	table, err := e.Objects.Uint(ctx, process, "_EPROCESS", "ObjectTable")
	if err == nil {
		_, err = e.Objects.Uint(ctx, table, "_HANDLE_TABLE", "HandleCount")
	}
	if err != nil {
		return true, issue("active_handle_count_unreadable", err)
	}
	return true, nil
}

func ghostControlArea(ctx context.Context, e plugin.Environment, vad uint64) (uint64, error) {
	if _, err := e.Objects.Field("_MMVAD", "ControlArea"); err == nil {
		return e.Objects.Uint(ctx, vad, "_MMVAD", "ControlArea")
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return 0, err
	}
	subsection, err := e.Objects.Uint(ctx, vad, "_MMVAD", "Subsection")
	if err != nil {
		return 0, err
	}
	return e.Objects.Uint(ctx, subsection, "_SUBSECTION", "ControlArea")
}
func ghostFilePointer(ctx context.Context, e plugin.Environment, control uint64) (uint64, error) {
	f, err := e.Objects.Field("_CONTROL_AREA", "FilePointer")
	if err != nil {
		return 0, err
	}
	if f.Type.Kind == "pointer" {
		return e.Objects.Uint(ctx, control, "_CONTROL_AREA", "FilePointer")
	}
	path := "FilePointer.Value"
	if _, err = e.Objects.Field("_CONTROL_AREA", path); errors.Is(err, object.ErrFieldAbsent) {
		path = "FilePointer.Object"
	} else if err != nil {
		return 0, err
	}
	file, err := e.Objects.Uint(ctx, control, "_CONTROL_AREA", path)
	mask := uint64(15)
	if e.Symbols.PointerSize() == 4 {
		mask = 7
	}
	return file &^ mask, err
}

type ghostMappedFile struct {
	region        windowsVADPath
	path          string
	control, file uint64
}

func ghostFileName(ctx context.Context, e plugin.Environment, file uint64) (string, bool, error) {
	length, err := e.Objects.Uint(ctx, file, "_FILE_OBJECT", "FileName.Length")
	if err != nil || length == 0 {
		return "", false, err
	}
	value, err := volatilityObjectString(ctx, e.Kernel, e.Objects, file, "_FILE_OBJECT", "FileName")
	if err != nil {
		return "", false, err
	}
	return value.String(), true, nil
}

func ghostMappedFiles(ctx context.Context, e plugin.Environment, regions []windowsVADPath, issue func(string, error) error) ([]ghostMappedFile, error) {
	var mapped []ghostMappedFile
	indexes := map[uint64]int{}
	for _, region := range regions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if region.tag == "VadS" || region.tag == "VadF" {
			continue
		}
		control, err := ghostControlArea(ctx, e, region.address)
		if err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				return nil, err
			}
			if err = issue("vad_control_unreadable", err); err != nil {
				return nil, err
			}
			continue
		}
		file, err := ghostFilePointer(ctx, e, control)
		if err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				return nil, err
			}
			if err = issue("vad_file_pointer_unreadable", err); err != nil {
				return nil, err
			}
			continue
		}
		// Do not pre-reject null pointers. The pinned object reader can observe a
		// mapped zero address; unlike an absent file name, a read failure is explicit.
		path, hasName, err := ghostFileName(ctx, e, file)
		if err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				return nil, err
			}
			if err = issue("vad_path_unreadable", err); err != nil {
				return nil, err
			}
			continue
		}
		if !hasName {
			continue
		}
		entry := ghostMappedFile{region, path, control, file}
		if i, ok := indexes[region.start]; ok {
			mapped[i] = entry
		} else {
			indexes[region.start] = len(mapped)
			mapped = append(mapped, entry)
		}
	}
	return mapped, nil
}

func windowsProcessGhosting(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.processghosting requires kernel symbols and memory")
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	maxVADs, err := strconv.ParseUint(p["max-vads"], 0, 32)
	if err != nil || maxVADs == 0 || maxVADs > 1000000 {
		return fmt.Errorf("max-vads must be 1..1000000")
	}
	for _, path := range []string{"ActiveThreads", "InheritedFromUniqueProcessId", "ExitTime", "CreateTime", "ImageFileName", "UniqueProcessId", "ThreadListHead.Flink", "ThreadListHead.Blink", "Pcb.DirectoryTableBase"} {
		if _, err = e.Objects.Field("_EPROCESS", path); err != nil {
			return err
		}
	}
	imageField, err := e.Objects.Field("_EPROCESS", "ImageFilePointer")
	hasImage := err == nil
	if err != nil && !errors.Is(err, object.ErrFieldAbsent) {
		return err
	}
	if hasImage && imageField.Type.Kind != "pointer" {
		return fmt.Errorf("ImageFilePointer is not a pointer")
	}
	_, handleErr := e.Objects.Field("_HANDLE_TABLE", "HandleCount")
	if handleErr != nil && !errors.Is(handleErr, object.ErrFieldAbsent) {
		return handleErr
	}
	var processes, active, vads, mappedCount, private, findings, diagnostics uint64
	err = visitWindowsProcesses(ctx, e, max, nil, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		newRow := func(kind string) evidence.Row {
			r := ghostRow(e.Kernel.Name(), process)
			r.Cells["PID"] = evidence.Number(pid)
			r.Cells["Process"] = evidence.Text(name)
			r.Cells["ProcessOffset"] = evidence.Address(process)
			r.Cells["ProcessIdentity"] = evidence.Text(identity)
			r.Cells["RecordType"] = evidence.Text(kind)
			return r
		}
		issue := func(stage string, cause error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			diagnostics++
			r := newRow("diagnostic")
			r.Cells["Error"] = evidence.Missing(stage, cause)
			return out(r)
		}
		keep, err := ghostActiveProcess(ctx, e, process, pid, issue)
		if err != nil || !keep {
			return err
		}
		active++
		regions, err := windowsVADRegions(ctx, e, process, int(min(uint64(max), maxVADs-vads)))
		if err != nil {
			return err
		}
		vads += uint64(len(regions))
		if vads > maxVADs {
			return fmt.Errorf("processghosting exceeds max-vads")
		}
		mapped, err := ghostMappedFiles(ctx, e, regions, issue)
		if err != nil {
			return err
		}
		mappedCount += uint64(len(mapped))
		paths := map[uint64]string{}
		for _, entry := range mapped {
			paths[entry.region.start] = entry.path
		}
		var imageCause error
		emit := func(f ghostFinding, region *ghostMappedFile, pendingRaw, closeRaw *uint64, imageRaw *uint64) error {
			findings++
			r := newRow("finding")
			r.Cells["Base"] = evidence.Address(f.base)
			r.Cells["FILE_OBJECT"] = evidence.Address(f.file)
			r.Cells["Rule"] = evidence.Text(f.rule)
			if f.pending != nil && *f.pending != 0 {
				r.Cells["DeletePending"] = evidence.Number(*f.pending)
			}
			if f.close != nil && *f.close != 0 {
				r.Cells["DeleteOnClose"] = evidence.Number(*f.close)
			}
			r.Cells["Path"] = evidence.Missing("not_available", nil)
			if path, ok := paths[f.base]; ok {
				r.Cells["Path"] = evidence.Text(path)
			}
			if pendingRaw != nil {
				r.Cells["DeletePendingRaw"] = evidence.Number(*pendingRaw)
			}
			if closeRaw != nil {
				r.Cells["DeleteOnCloseRaw"] = evidence.Number(*closeRaw)
			}
			if imageRaw != nil {
				r.Cells["ImageFileRaw"] = evidence.Address(*imageRaw)
			}
			if region != nil {
				r.Cells["VADOffset"] = evidence.Address(region.region.address)
				r.Cells["ControlArea"] = evidence.Address(region.control)
			} else {
				if imageCause != nil {
					r.Cells["Error"] = evidence.Missing("image_file_unreadable", imageCause)
				}
				slot, err := memory.Add(process, imageField.Offset)
				if err != nil {
					return err
				}
				r.Cells["ImageFilePointerOffset"] = evidence.Address(slot)
			}
			return out(r)
		}
		if hasImage {
			slot, err := memory.Add(process, imageField.Offset)
			if err != nil {
				return err
			}
			file := uint64(0)
			var pending, imageRaw *uint64
			if slot != 0 {
				value, err := e.Objects.Uint(ctx, process, "_EPROCESS", "ImageFilePointer")
				if err == nil {
					imageRaw = &value
					file = value
					dp, readErr := e.Objects.Uint(ctx, file, "_FILE_OBJECT", "DeletePending")
					err = readErr
					if err == nil {
						pending = &dp
					}
				}
				if err != nil {
					if errors.Is(err, object.ErrFieldAbsent) {
						return err
					}
					file = 0
					imageCause = err
					if err = issue("image_file_unreadable", err); err != nil {
						return err
					}
				}
			}
			// SectionBaseAddress is accessed only if the process check emits a row.
			list := ghostProcessFindings(file, 0, pending)
			if len(list) > 0 {
				base, err := e.Objects.Uint(ctx, process, "_EPROCESS", "SectionBaseAddress")
				if err != nil {
					return err
				}
				list[0].base = base
				if err = emit(list[0], nil, pending, nil, imageRaw); err != nil {
					return err
				}
			}
		}
		for i := range mapped {
			entry := &mapped[i]
			path, _, err := windowsVADField(e, "_MMVAD", []string{"u1.VadFlags1.PrivateMemory", "u.VadFlags.PrivateMemory", "Core.u1.VadFlags1.PrivateMemory", "Core.u.VadFlags.PrivateMemory"})
			if err != nil {
				return err
			}
			value, err := e.Objects.Uint(ctx, entry.region.address, "_MMVAD", path)
			if err != nil {
				return err
			}
			if value == 1 {
				private++
				continue
			}
			var close *uint64
			dc, err := e.Objects.Uint(ctx, entry.control, "_CONTROL_AREA", "u.Flags.DeleteOnClose")
			if err != nil {
				if errors.Is(err, object.ErrFieldAbsent) {
					return err
				}
				if err = issue("vad_delete_on_close_unreadable", err); err != nil {
					return err
				}
			} else {
				close = &dc
			}
			// The close finding is emitted before reading DeletePending, like
			// the pinned generator. An output failure stops further reads.
			for _, f := range ghostVADFindings(entry.file, entry.region.start, entry.path, nil, close) {
				if err = emit(f, entry, nil, close, nil); err != nil {
					return err
				}
			}
			var pending *uint64
			dp, err := e.Objects.Uint(ctx, entry.file, "_FILE_OBJECT", "DeletePending")
			if err != nil {
				if errors.Is(err, object.ErrFieldAbsent) {
					return err
				}
				if err = issue("vad_delete_pending_unreadable", err); err != nil {
					return err
				}
			} else {
				pending = &dp
			}
			for _, f := range ghostVADFindings(entry.file, entry.region.start, entry.path, pending, nil) {
				if err = emit(f, entry, pending, close, nil); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	r := ghostRow(e.Kernel.Name(), 0)
	r.Provenance.Offset = ""
	r.Cells["RecordType"] = evidence.Text("summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"processes": formatCount(processes), "active": formatCount(active), "filtered": formatCount(processes - active), "vads": formatCount(vads), "mapped_files": formatCount(mappedCount), "private_skipped": formatCount(private), "findings": formatCount(findings), "diagnostics": formatCount(diagnostics), "image_file_member": formatCount(boolCount(hasImage)), "handle_count_member": formatCount(boolCount(handleErr == nil))})
	return out(r)
}
func boolCount(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
