package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxProcessSpoofingPlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"uint64", "PID PPID"}, {"string", "Exe_Path Cmdline_Basename Comm Exe_Basename ProcessIdentity RecordType"},
		{"bool", "Cmdline_Spoofed Comm_Spoofed Exe_Deleted CmdlineCompared CommCompared"},
		{"address", "ProcessOffset MM ExeFile"}, {"structure", "CommandLineEvidence ExecutableEvidence CommEvidence Error Coverage"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.process_spoofing", Upstream: "linux.malware.process_spoofing.ProcessSpoofing", Platform: "linux", NeedsKernel: true,
		Description: "Compare executable, argv[0] and comm with raw byte captures and explicit read coverage",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated task PID filter"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task traversal bound; native parameter"}}, Columns: columns}, linuxProcessSpoofing}}
}

// PurePosixPath.name drops empty and dot components, but preserves '..'. It is
// not shell tokenization or filepath.Base (which depends on the host OS).
func spoofPosixName(value string) string {
	parts := strings.Split(value, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" && parts[i] != "." {
			return parts[i]
		}
	}
	return ""
}
func linuxSpoofNames(executable, command, comm string) (bool, bool) {
	available := 0
	for _, value := range []string{executable, command, comm} {
		if value != "" {
			available++
		}
	}
	if available < 2 {
		return false, false
	}
	commandMismatch := executable != "" && command != "" && executable != command
	prefix := []rune(executable)
	if len(prefix) > 15 {
		prefix = prefix[:15]
	}
	return commandMismatch, executable != "" && comm != "" && string(prefix) != comm
}
func spoofDecoded(raw []byte) string {
	text, _ := replaceInvalidUTF8(raw)
	if i := strings.IndexAny(text, "\x00\ufffd"); i >= 0 {
		text = text[:i]
	}
	return text
}
func spoofReadable(ctx context.Context, e plugin.Environment, address uint64, typ string) error {
	t, err := e.Symbols.Type(typ)
	if err != nil {
		return err
	}
	if t.Size == 0 || t.Size > memory.MaxRead {
		return fmt.Errorf("invalid %s extent %d", typ, t.Size)
	}
	_, err = memory.Read(ctx, e.Kernel, address, int(t.Size))
	return err
}

func linuxSpoofCommand(ctx context.Context, e plugin.Environment, mm uint64, identity string, details map[string]evidence.Value, issue func(string, error)) string {
	start, err := e.Objects.Uint(ctx, mm, "mm_struct", "arg_start")
	if err != nil {
		issue("argument_start_unreadable", err)
		return ""
	}
	details["Start"] = evidence.Address(start)
	end, err := e.Objects.Uint(ctx, mm, "mm_struct", "arg_end")
	if err != nil {
		issue("argument_end_unreadable", err)
		return ""
	}
	details["End"] = evidence.Address(end)
	if end <= start {
		details["Status"] = evidence.Text("empty_or_reversed_range")
		return ""
	}
	size := end - start
	length := min(size, uint64(32*4096)) // MAX_ARG_STRLEN in the pinned source.
	details["DeclaredBytes"], details["RequestedBytes"] = evidence.Number(size), evidence.Number(length)
	details["Capped"] = evidence.Bool(size > length)
	if _, err = memory.Add(start, length); err != nil {
		issue("invalid_argument_range", err)
		return ""
	}
	layer, err := processMemory(ctx, e, 0, mm, identity)
	if err != nil {
		issue("process_layer_unavailable", err)
		return ""
	}
	details["Layer"] = evidence.Text(layer.Name())
	raw := make([]byte, int(length))
	got, err := layer.ReadAt(ctx, raw, start)
	if got < 0 || got > len(raw) {
		issue("invalid_argument_read", fmt.Errorf("invalid captured byte count %d", got))
		return ""
	}
	details["Raw"], details["CapturedBytes"] = evidence.Bytes(raw[:got]), evidence.Number(uint64(got))
	complete := err == nil && got == len(raw)
	details["ReadComplete"] = evidence.Bool(complete)
	if !complete {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		details["ReadError"] = evidence.Missing("argument_prefix_only", err)
		issue("argument_prefix_only", err)
	}
	// The pinned utility decodes a contiguous prefix after a later mapping hole.
	// Keep that behavior, but retain the missing suffix as evidence, not a clean read.
	text := spoofDecoded(raw[:got])
	details["Decoded"] = evidence.Text(text)
	if got == 0 {
		details["Status"] = evidence.Text("no_readable_prefix")
	}
	return spoofPosixName(text)
}

func linuxSpoofDynamicName(ctx context.Context, e plugin.Environment, dentry, callback uint64, details map[string]evidence.Value, issue func(string, error), callbackNames func(uint64) []string) string {
	if _, err := memory.Read(ctx, e.Kernel, callback, 1); err != nil {
		issue("dynamic_callback_unreadable", err)
		return fmt.Sprintf("<invalid d_dname pointer> %x", callback)
	}
	inode, err := e.Objects.Uint(ctx, dentry, "dentry", "d_inode")
	if err != nil {
		issue("dynamic_inode_pointer_unreadable", err)
		return ""
	}
	details["Inode"] = evidence.Address(inode)
	invalid := fmt.Sprintf("<invalid dentry inode> %x", inode)
	if inode == 0 {
		return invalid
	}
	if err = spoofReadable(ctx, e, inode, "inode"); err != nil {
		issue("dynamic_inode_extent_unreadable", err)
		return invalid
	}
	number, err := e.Objects.Uint(ctx, inode, "inode", "i_ino")
	if err != nil {
		issue("dynamic_inode_number_unreadable", err)
		return ""
	}
	details["InodeNumber"] = evidence.Number(number)
	if number == 0 {
		return invalid
	}
	count, err := e.Objects.Int(ctx, inode, "inode", "i_count.counter")
	if err != nil {
		issue("dynamic_inode_count_unreadable", err)
		return ""
	}
	details["InodeCount"] = evidence.Integer(count)
	if count < 0 {
		return invalid
	}
	names := callbackNames(callback)
	details["CallbackNames"] = evidence.Value{Kind: "structure", Data: names}
	prefix := fmt.Sprintf("<unknown d_dname pointer> %x", callback)
	if len(names) == 1 {
		switch name := names[0]; name {
		case "sockfs_dname":
			prefix = "socket"
		case "pipefs_dname":
			prefix = "pipe"
		case "anon_inodefs_dname":
			prefix = "anon_inode"
		case "simple_dname":
			buffer, err := e.Objects.Uint(ctx, dentry, "dentry", "d_name.name")
			if err != nil {
				issue("dynamic_label_pointer_unreadable", err)
				return ""
			}
			details["NameBuffer"] = evidence.Address(buffer)
			if buffer == 0 {
				prefix = ""
				break
			}
			raw, err := memory.Read(ctx, e.Kernel, buffer, 255)
			if err != nil {
				issue("dynamic_label_unreadable", err)
				return ""
			}
			details["NameRaw"] = evidence.Bytes(raw)
			text, _ := replaceInvalidUTF8(raw)
			text, _, _ = strings.Cut(text, "\x00")
			return "/" + text + " (deleted)"
		case "ns_dname":
			raw, err := linuxNamespaceLabel(ctx, e, dentry, inode)
			if err != nil {
				issue("namespace_label_unavailable", err)
				return ""
			}
			details["NameRaw"] = evidence.Bytes(raw)
			prefix, _ = replaceInvalidUTF8(raw)
		default:
			prefix = "<unsupported d_op symbol> " + name
		}
	}
	return prefix + ":[" + strconv.FormatUint(number, 10) + "]"
}

// Follow the pinned prepend_path display, preserving each raw qstr capture.
// A failed qstr becomes an explicitly marked smeared component; cycles and
// native bounds fail that pathname rather than looping indefinitely.
func linuxSpoofFilesystemPath(ctx context.Context, e plugin.Environment, task, file, dentry uint64, details map[string]evidence.Value, issue func(string, error), callbackNames func(uint64) []string) (string, bool) {
	op, err := e.Objects.Uint(ctx, dentry, "dentry", "d_op")
	if err != nil {
		issue("dentry_operation_unreadable", err)
	} else if op != 0 {
		callback, err := e.Objects.Uint(ctx, op, "dentry_operations", "d_dname")
		if err != nil {
			issue("dentry_callback_unreadable", err)
		} else if callback != 0 {
			details["Scope"], details["Callback"] = evidence.Text("dynamic_name"), evidence.Address(callback)
			return linuxSpoofDynamicName(ctx, e, dentry, callback, details, issue, callbackNames), true
		}
	}
	root, rootMount, err := linuxProcessRoot(ctx, e, task)
	if err != nil {
		issue("process_root_unreadable", err)
		return "", false
	}
	details["RootDentry"], details["RootMount"] = evidence.Address(root), evidence.Address(rootMount)
	for _, entry := range []struct {
		address uint64
		typ     string
	}{{root, "dentry"}, {rootMount, "vfsmount"}} {
		if err = spoofReadable(ctx, e, entry.address, entry.typ); err != nil {
			issue("root_extent_unreadable", err)
			return "", false
		}
	}
	mount, err := linuxMember(ctx, e, file, "file", "f_path.mnt", "f_vfsmnt")
	if err != nil {
		issue("file_mount_unreadable", err)
		return "", false
	}
	details["Mount"], details["Scope"] = evidence.Address(mount), evidence.Text("process_root")
	if mount == 0 {
		return "", false
	}
	if err = spoofReadable(ctx, e, mount, "vfsmount"); err != nil {
		issue("mount_extent_unreadable", err)
		return "", false
	}
	seen := map[[2]uint64]bool{}
	var components []string
	var captures []map[string]evidence.Value
	defer func() { details["Components"] = evidence.Value{Kind: "structure", Data: captures} }()
	smeared := false
	for depth := 0; ; depth++ {
		if err := ctx.Err(); err != nil {
			issue("path_cancelled", err)
			return "", false
		}
		if dentry == 0 || dentry == root && mount == rootMount {
			break
		}
		key := [2]uint64{dentry, mount}
		if depth >= 256 || seen[key] {
			issue("path_cycle_or_bound", fmt.Errorf("filesystem path repeats or exceeds 256 entries"))
			return "", false
		}
		seen[key] = true
		if err = spoofReadable(ctx, e, dentry, "dentry"); err != nil {
			issue("dentry_extent_unreadable", err)
			break
		}
		parent, err := e.Objects.Uint(ctx, dentry, "dentry", "d_parent")
		if err != nil {
			issue("dentry_parent_unreadable", err)
			return "", false
		}
		mountRoot, err := e.Objects.Uint(ctx, mount, "vfsmount", "mnt_root")
		if err != nil {
			issue("mount_root_unreadable", err)
			return "", false
		}
		if dentry == mountRoot || dentry == parent {
			if dentry != mountRoot {
				details["Scope"] = evidence.Text("escaped_or_disconnected")
				break
			}
			next, point, err := linuxMountParent(ctx, e, mount)
			if err != nil {
				issue("mount_parent_unreadable", err)
				return "", false
			}
			if next == mount {
				details["Scope"] = evidence.Text("global_root")
				break
			}
			mount, dentry = next, point
			continue
		}
		count := uint64(255)
		if _, err = e.Objects.Field("dentry", "d_name.len"); err == nil {
			count, err = e.Objects.Uint(ctx, dentry, "dentry", "d_name.len")
			if err != nil {
				issue("qstr_length_unreadable", err)
				return "", false
			}
			if count > 4096 {
				issue("qstr_length_bound", fmt.Errorf("qstr length %d exceeds 4096", count))
				return "", false
			}
			count++
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			issue("qstr_layout_unavailable", err)
			return "", false
		}
		buffer, err := e.Objects.Uint(ctx, dentry, "dentry", "d_name.name")
		if err != nil {
			issue("qstr_pointer_unreadable", err)
			return "", false
		}
		raw := make([]byte, int(count))
		got, readErr := e.Kernel.ReadAt(ctx, raw, buffer)
		if got < 0 || got > len(raw) {
			issue("qstr_invalid_read", fmt.Errorf("invalid captured byte count %d", got))
			return "", false
		}
		capture := map[string]evidence.Value{"Dentry": evidence.Address(dentry), "Buffer": evidence.Address(buffer), "RequestedBytes": evidence.Number(count), "Raw": evidence.Bytes(raw[:got]), "CapturedBytes": evidence.Number(uint64(got)), "ReadComplete": evidence.Bool(readErr == nil && got == len(raw))}
		if readErr != nil || got != len(raw) {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			issue("qstr_prefix_only", readErr)
			capture["Error"] = evidence.Missing("qstr_prefix_only", readErr)
		}
		name := spoofDecoded(raw[:got])
		capture["Decoded"] = evidence.Text(name)
		captures = append(captures, capture)
		if name == "" {
			smeared = true
		}
		components = append(components, strings.Trim(name, "/"))
		size := len(components)
		for _, c := range components {
			size += len(c)
		}
		if size > 16384 {
			issue("path_length_bound", fmt.Errorf("filesystem path exceeds 16KiB"))
			return "", false
		}
		dentry = parent
	}
	for i, j := 0, len(components)-1; i < j; i, j = i+1, j-1 {
		components[i], components[j] = components[j], components[i]
	}
	path := "/" + strings.Join(components, "/")
	if smeared {
		path = "<potentially smeared> " + path
		details["Scope"] = evidence.Text("smeared")
	}
	return path, false
}

func linuxSpoofExecutable(ctx context.Context, e plugin.Environment, task, file uint64, details map[string]evidence.Value, issue func(string, error), callbackNames func(uint64) []string) string {
	if err := spoofReadable(ctx, e, file, "file"); err != nil {
		issue("executable_object_unreadable", err)
		return ""
	}
	dentry, err := linuxMember(ctx, e, file, "file", "f_path.dentry", "f_dentry")
	if err != nil {
		issue("dentry_pointer_unreadable", err)
		return ""
	}
	details["Dentry"] = evidence.Address(dentry)
	if dentry == 0 {
		return ""
	}
	path, dynamic := linuxSpoofFilesystemPath(ctx, e, task, file, dentry, details, issue, callbackNames)
	if path == "" {
		return ""
	}
	// LinuxUtilities.do_get_path checks a readable, valid inode before adding
	// its literal leading space and ' (deleted)' suffix.
	inode, err := e.Objects.Uint(ctx, dentry, "dentry", "d_inode")
	if err != nil {
		issue("executable_inode_unreadable", err)
		return ""
	}
	details["Inode"] = evidence.Address(inode)
	if inode != 0 && !dynamic {
		if err = spoofReadable(ctx, e, inode, "inode"); err != nil {
			issue("inode_extent_unreadable", err)
			return path
		}
		number, err := e.Objects.Uint(ctx, inode, "inode", "i_ino")
		if err != nil {
			issue("inode_number_unreadable", err)
			return ""
		}
		details["InodeNumber"] = evidence.Number(number)
		if number > 0 {
			count, err := e.Objects.Int(ctx, inode, "inode", "i_count.counter")
			if err != nil {
				issue("inode_count_unreadable", err)
				return ""
			}
			details["InodeCount"] = evidence.Integer(count)
			if count >= 0 {
				links, err := linuxMember(ctx, e, inode, "inode", "i_nlink", "__i_nlink")
				if err != nil {
					issue("inode_links_unreadable", err)
					return ""
				}
				details["Links"] = evidence.Number(links)
				if links == 0 {
					path = " " + path + " (deleted)"
				}
			}
		}
	}
	return path
}

func linuxSpoofRow(layer string, task uint64) evidence.Row {
	r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", task)}}
	for _, c := range linuxProcessSpoofingPlugins()[0].spec.Columns {
		r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
	}
	return r
}
func linuxProcessSpoofing(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("linux.process_spoofing requires kernel memory and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	init, err := e.Symbol("init_task")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("task_struct", "tasks")
	if err != nil {
		return err
	}
	head, err := memory.Add(init, links.Offset)
	if err != nil {
		return err
	}
	var callbackIndex map[uint64][]string
	callbackNames := func(address uint64) []string {
		if callbackIndex == nil {
			callbackIndex = map[uint64][]string{}
			for _, name := range e.Symbols.Names() {
				if location, err := e.Symbol(name); err == nil {
					callbackIndex[location] = append(callbackIndex[location], name)
				}
			}
		}
		return callbackIndex[address]
	}
	var processes, cmdCompared, commCompared, cmdMismatches, commMismatches, diagnostics uint64
	err = e.Objects.WalkList(ctx, head, links.Offset, max, func(task uint64) error {
		pid, err := e.Objects.Uint(ctx, task, "task_struct", "pid")
		if err != nil {
			return err
		}
		if pids != nil && !pids[pid] {
			return nil
		}
		processes++
		r := linuxSpoofRow(e.Kernel.Name(), task)
		r.Cells["PID"], r.Cells["ProcessOffset"], r.Cells["RecordType"] = evidence.Number(pid), evidence.Address(task), evidence.Text("process")
		var issues []evidence.Value
		issue := func(stage string, cause error) {
			diagnostics++
			issues = append(issues, evidence.Missing(stage, cause))
		}
		stamp := ""
		created := linuxStartTime(ctx, e, task)
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, pid, stamp)
		r.Cells["ProcessIdentity"] = evidence.Text(identity)
		parent, err := e.Objects.Uint(ctx, task, "task_struct", "real_parent")
		r.Cells["PPID"] = evidence.Number(0)
		if err != nil {
			issue("parent_pointer_unreadable", err)
		} else if parent != 0 {
			if err = spoofReadable(ctx, e, parent, "task_struct"); err != nil {
				issue("parent_object_unreadable", err)
			} else {
				ppid, err := e.Objects.Uint(ctx, parent, "task_struct", "tgid")
				if err != nil {
					issue("parent_pid_unreadable", err)
					r.Cells["PPID"] = evidence.Missing("parent_pid_unreadable", err)
				} else {
					r.Cells["PPID"] = evidence.Number(ppid)
				}
			}
		}
		comm := ""
		commDetails := map[string]evidence.Value{}
		f, err := e.Objects.Field("task_struct", "comm")
		if err != nil {
			issue("comm_layout_unavailable", err)
		} else {
			size, err := e.Objects.Size(f.Type)
			if err != nil || size == 0 || size > 4096 {
				if err == nil {
					err = fmt.Errorf("invalid comm extent %d", size)
				}
				issue("comm_layout_unavailable", err)
			} else {
				address, err := memory.Add(task, f.Offset)
				if err != nil {
					issue("comm_address_invalid", err)
				} else {
					raw := make([]byte, int(size))
					got, readErr := e.Kernel.ReadAt(ctx, raw, address)
					if got < 0 || got > len(raw) {
						issue("comm_invalid_read", fmt.Errorf("invalid captured byte count %d", got))
					} else {
						commDetails["Address"], commDetails["Raw"] = evidence.Address(address), evidence.Bytes(raw[:got])
						commDetails["CapturedBytes"], commDetails["ReadComplete"] = evidence.Number(uint64(got)), evidence.Bool(readErr == nil && got == len(raw))
						if readErr != nil || got != len(raw) {
							if readErr == nil {
								readErr = io.ErrUnexpectedEOF
							}
							issue("comm_prefix_only", readErr)
						}
						comm = spoofDecoded(raw[:got])
					}
				}
			}
		}
		commDetails["Decoded"] = evidence.Text(comm)
		r.Cells["CommEvidence"] = evidence.Value{Kind: "structure", Data: commDetails}
		executable, command := "", ""
		mm, err := e.Objects.Uint(ctx, task, "task_struct", "mm")
		if err != nil {
			issue("mm_pointer_unreadable", err)
		} else {
			r.Cells["MM"] = evidence.Address(mm)
			if mm != 0 {
				if err = spoofReadable(ctx, e, mm, "mm_struct"); err != nil {
					issue("mm_object_unreadable", err)
				} else {
					file, err := e.Objects.Uint(ctx, mm, "mm_struct", "exe_file")
					details := map[string]evidence.Value{}
					if err != nil {
						issue("executable_pointer_unreadable", err)
					} else {
						r.Cells["ExeFile"] = evidence.Address(file)
						if file != 0 {
							executable = linuxSpoofExecutable(ctx, e, task, file, details, issue, callbackNames)
						}
					}
					r.Cells["ExecutableEvidence"] = evidence.Value{Kind: "structure", Data: details}
					commandDetails := map[string]evidence.Value{}
					command = linuxSpoofCommand(ctx, e, mm, identity, commandDetails, issue)
					r.Cells["CommandLineEvidence"] = evidence.Value{Kind: "structure", Data: commandDetails}
				}
			}
		}
		exeName := spoofPosixName(executable)
		exeName = strings.TrimSuffix(exeName, " (deleted)")
		r.Cells["Exe_Basename"] = evidence.Missing("not_available", nil)
		if exeName != "" {
			r.Cells["Exe_Basename"] = evidence.Text(exeName)
		}
		for key, value := range map[string]string{"Exe_Path": executable, "Cmdline_Basename": command, "Comm": comm} {
			if value == "" {
				value = "N/A"
			}
			r.Cells[key] = evidence.Text(value)
		}
		cmd, com := linuxSpoofNames(exeName, command, comm)
		r.Cells["Cmdline_Spoofed"], r.Cells["Comm_Spoofed"], r.Cells["Exe_Deleted"] = evidence.Bool(cmd), evidence.Bool(com), evidence.Bool(strings.HasSuffix(executable, " (deleted)"))
		cc, oc := exeName != "" && command != "", exeName != "" && comm != ""
		r.Cells["CmdlineCompared"], r.Cells["CommCompared"] = evidence.Bool(cc), evidence.Bool(oc)
		cmdCompared += boolCount(cc)
		commCompared += boolCount(oc)
		cmdMismatches += boolCount(cmd)
		commMismatches += boolCount(com)
		if len(issues) > 0 {
			r.Cells["Error"] = evidence.Value{Kind: "structure", Data: issues}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return out(r)
	})
	if err != nil {
		return err
	}
	r := linuxSpoofRow(e.Kernel.Name(), 0)
	r.Provenance.Offset = ""
	r.Cells["RecordType"] = evidence.Text("summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"processes": formatCount(processes), "cmdline_compared": formatCount(cmdCompared), "comm_compared": formatCount(commCompared), "cmdline_mismatches": formatCount(cmdMismatches), "comm_mismatches": formatCount(commMismatches), "diagnostics": formatCount(diagnostics)})
	return out(r)
}
