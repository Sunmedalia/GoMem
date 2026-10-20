package plugins

import (
	"context"
	"encoding/binary"
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

func linuxLsofPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.lsof", Upstream: "linux.lsof.Lsof", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate task/thread file descriptors with scoped raw paths and exact inode metadata",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Task-list PID set; selected groups include threads, matching the reference"}, {Name: "files-only", Kind: "bool", Default: "false", Description: "Use filesystem path traversal instead of dynamic dentry names; does not filter to regular inode types"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task and per-group traversal bound"}, {Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total task/thread bound"}, {Name: "max-fds", Kind: "uint", Default: "500000", Description: "Per-task descriptor slot bound (1..500000)"}, {Name: "max-slots", Kind: "uint", Default: "10000000", Description: "Total descriptor slots visited across tasks (1..100000000)"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "TID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "FD", Kind: "uint64"}, {Name: "Path", Kind: "string"}, {Name: "Device", Kind: "string"}, {Name: "Inode", Kind: "uint64"}, {Name: "Type", Kind: "string"}, {Name: "Mode", Kind: "string"}, {Name: "Changed", Kind: "string"}, {Name: "Modified", Kind: "string"}, {Name: "Accessed", Kind: "string"}, {Name: "Size", Kind: "int64"}, {Name: "PathRaw", Kind: "bytes"}, {Name: "PathScope", Kind: "string"}, {Name: "PathInProcessRoot", Kind: "bool"}, {Name: "Offset", Kind: "address"}, {Name: "FileExtent", Kind: "structure"}, {Name: "Dentry", Kind: "address"}, {Name: "InodeOffset", Kind: "address"}, {Name: "InodeSource", Kind: "string"}, {Name: "ModeRaw", Kind: "uint64"}, {Name: "Nlink", Kind: "uint64"}, {Name: "Deleted", Kind: "bool"}, {Name: "Major", Kind: "uint64"}, {Name: "Minor", Kind: "uint64"}, {Name: "Superblock", Kind: "address"}, {Name: "ChangedRaw", Kind: "structure"}, {Name: "ModifiedRaw", Kind: "structure"}, {Name: "AccessedRaw", Kind: "structure"}, {Name: "Files", Kind: "address"}, {Name: "FDTable", Kind: "address"}, {Name: "Slot", Kind: "address"}, {Name: "SkippedSlots", Kind: "uint64"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "TaskOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "TaskIdentity", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "string"}}}, linuxLsof}}
}

// Enumerate pointer slots page by page, so an unreadable page cannot suppress
// captured descriptors on other pages. Count includes NULL and unreadable slots.
func linuxFDTable(ctx context.Context, e plugin.Environment, task uint64) (files, table, count uint64, err error) {
	files, err = e.Objects.Uint(ctx, task, "task_struct", "files")
	if err != nil || files == 0 {
		return
	}
	base, typ := files, "files_struct"
	if field, er := e.Objects.Field("files_struct", "fdt"); er == nil {
		typ = "fdtable"
		if field.Type.Kind == "pointer" {
			base, err = e.Objects.Uint(ctx, files, "files_struct", "fdt")
			if err == nil && base == 0 {
				err = fmt.Errorf("files_struct.fdt is null")
			}
		} else {
			err = fmt.Errorf("files_struct.fdt is not a pointer")
		}
		if err != nil {
			return
		}
	} else if !errors.Is(er, object.ErrFieldAbsent) {
		err = er
		return
	}
	table, err = e.Objects.Uint(ctx, base, typ, "fd")
	if err != nil {
		return
	}
	count, err = e.Objects.Uint(ctx, base, typ, "max_fds")
	if err != nil {
		return
	}
	width := uint64(e.Symbols.PointerSize())
	if width != 4 && width != 8 || count > 0 && (table == 0 || table%width != 0 || count > (^uint64(0)-table)/width) {
		err = fmt.Errorf("invalid descriptor table pointer/interval")
	}
	return
}

func linuxLsof(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	filesOnly, err := strconv.ParseBool(p["files-only"])
	if err != nil {
		return err
	}
	var failures pluginFailures
	err = visitLinuxDescriptors(ctx, e, p, func(row evidence.Row) error {
		if row.Cells["RecordType"].String() == "file" {
			task, _ := row.Cells["TaskOffset"].Uint()
			file, _ := row.Cells["Offset"].Uint()
			failures.add(linuxOpenFile(ctx, e, task, file, filesOnly, &row))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return out(row)
	})
	return errors.Join(err, failures.err("Linux open file metadata"))
}

// Shared task/thread descriptor producer; consumers interpret only the file
// fields they need. Socket enumeration does not depend on inode timestamps or
// successful pathname recovery for unrelated open files.
func visitLinuxDescriptors(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	pointerType, err := e.Symbols.Type("pointer")
	if err != nil || pointerType.Endian != "" && pointerType.Endian != "little" {
		return fmt.Errorf("descriptor enumeration requires little-endian Intel pointers")
	}
	maxFDs, err := strconv.ParseUint(p["max-fds"], 0, 64)
	if err != nil || maxFDs == 0 || maxFDs > 500000 {
		return fmt.Errorf("max-fds must be 1..500000")
	}
	maxSlots, err := strconv.ParseUint(p["max-slots"], 0, 64)
	if err != nil || maxSlots == 0 || maxSlots > 100000000 {
		return fmt.Errorf("max-slots must be 1..100000000")
	}
	// Reuse the verified task/thread traversal and its group/identity semantics.
	taskParameters := map[string]string{"pid": p["pid"], "max-nodes": p["max-nodes"], "max-tasks": p["max-tasks"], "threads": "true", "decorate-comm": "false", "dump": "false", "elf-layout": "mapped", "max-elf-size": "1073741824"}
	var slots uint64
	var failures pluginFailures
	var outputErr error
	emit := func(row evidence.Row) error { outputErr = out(row); return outputErr }
	err = linuxTaskListing(ctx, e, taskParameters, func(taskRow evidence.Row) error {
		c := taskRow.Cells
		task, er := c["Offset"].Uint()
		if er != nil {
			return er
		}
		baseRow := func() evidence.Row {
			row := evidence.Row{Cells: map[string]evidence.Value{"PID": c["PID"], "TID": c["TID"], "Process": c["NameRaw"], "TaskOffset": c["Offset"], "ProcessOffset": c["ProcessOffset"], "ProcessIdentity": c["Identity"], "TaskIdentity": c["TaskIdentity"], "RecordType": evidence.Text("file"), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", task)}}
			for _, key := range []string{"FD", "Path", "Device", "Inode", "Type", "Mode", "Changed", "Modified", "Accessed", "Size", "PathRaw", "PathScope", "PathInProcessRoot", "Offset", "FileExtent", "Dentry", "InodeOffset", "InodeSource", "ModeRaw", "Nlink", "Deleted", "Major", "Minor", "Superblock", "ChangedRaw", "ModifiedRaw", "AccessedRaw", "Files", "FDTable", "Slot", "SkippedSlots"} {
				row.Cells[key] = evidence.Missing("not_reached", nil)
			}
			return row
		}
		diagnostic := func(row evidence.Row, reason string, cause error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures.add(cause)
			row.Cells["RecordType"], row.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing(reason, cause)
			return emit(row)
		}
		if c["RecordType"].String() == "diagnostic" {
			return diagnostic(baseRow(), "task_enumeration_incomplete", fmt.Errorf("%s", c["Error"].String()))
		}
		files, table, count, err := linuxFDTable(ctx, e, task)
		base := baseRow()
		base.Cells["Files"], base.Cells["FDTable"] = evidence.Address(files), evidence.Address(table)
		if err != nil {
			return diagnostic(base, "descriptor_table_unavailable", err)
		}
		if files == 0 || count == 0 {
			return nil
		}
		if count > maxFDs {
			return diagnostic(base, "descriptor_limit_exceeded", fmt.Errorf("task %#x max_fds %d exceeds bound %d", task, count, maxFDs))
		}
		if count > maxSlots-slots {
			return fmt.Errorf("total descriptor traversal exceeds max-slots")
		}
		slots += count
		width := uint64(e.Symbols.PointerSize())
		for index := uint64(0); index < count; {
			if err := ctx.Err(); err != nil {
				return err
			}
			address := table + index*width
			n := min((4096-(address&4095))/width, count-index)
			data := make([]byte, int(n*width))
			got, readErr := e.Kernel.ReadAt(ctx, data, address)
			if got < 0 || got > len(data) {
				return fmt.Errorf("invalid descriptor read length")
			}
			captured := uint64(got) / width
			if got < len(data) && readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}

			for k := uint64(0); k < captured; k++ {
				if err := ctx.Err(); err != nil {
					return err
				}
				var pointer uint64
				if width == 4 {
					pointer = uint64(binary.LittleEndian.Uint32(data[k*width:]))
				} else {
					pointer = binary.LittleEndian.Uint64(data[k*width:])
				}
				if pointer == 0 {
					continue
				}
				row := baseRow()
				row.Cells["FD"], row.Cells["Offset"], row.Cells["Files"], row.Cells["FDTable"], row.Cells["Slot"] = evidence.Number(index+k), evidence.Address(pointer), evidence.Address(files), evidence.Address(table), evidence.Address(address+k*width)
				row.Provenance.Offset = fmt.Sprintf("0x%x", pointer)
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err := emit(row); err != nil {
					return err
				}
			}
			if readErr != nil {
				row := baseRow()
				offset := address + captured*width
				row.Cells["FD"], row.Cells["Files"], row.Cells["FDTable"], row.Cells["Slot"], row.Cells["SkippedSlots"] = evidence.Number(index+captured), evidence.Address(files), evidence.Address(table), evidence.Address(offset), evidence.Number(n-captured)
				row.Provenance.Offset = fmt.Sprintf("0x%x", offset)
				if err := diagnostic(row, "descriptor_slots_unreadable", readErr); err != nil {
					return err
				}
			}
			index += n
		}
		return nil
	})
	if outputErr != nil {
		return outputErr
	}
	if err != nil {
		return err
	}
	return failures.err("Linux open file enumeration")
}

func linuxOpenFile(ctx context.Context, e plugin.Environment, task, file uint64, filesOnly bool, row *evidence.Row) error {
	var failures pluginFailures
	fileType, extentErr := e.Symbols.Type("file")
	if extentErr == nil && (fileType.Size == 0 || fileType.Size > memory.MaxRead) {
		extentErr = fmt.Errorf("invalid file object extent")
	}
	if extentErr == nil {
		_, extentErr = memory.Read(ctx, e.Kernel, file, int(fileType.Size))
	}
	extent := map[string]any{"size": strconv.FormatUint(fileType.Size, 10), "readable": extentErr == nil}
	if extentErr != nil {
		extent["error"] = extentErr.Error()
		row.Cells["RecordType"] = evidence.Text("file_partial")
		failures.add(extentErr)
	}
	row.Cells["FileExtent"] = evidence.Value{Kind: "structure", Data: extent}
	dentry, err := linuxMember(ctx, e, file, "file", "f_path.dentry", "f_dentry")
	if err != nil {
		row.Cells["Dentry"] = evidence.Missing("dentry_pointer_unreadable", err)
		failures.add(err)
	} else {
		row.Cells["Dentry"] = evidence.Address(dentry)
	}
	metadata, er := linuxInodeMetadata(ctx, e, file, dentry)
	failures.add(er)
	for key, value := range metadata {
		row.Cells[key] = value
	}
	scope := "process_root"
	var name []byte
	if err == nil && dentry == 0 {
		err = fmt.Errorf("file has null dentry")
	}
	if err == nil {
		name, err = linuxFilePathWithDynamic(ctx, e, task, file, dentry, &scope, !filesOnly)
	}
	row.Cells["PathScope"] = evidence.Text(scope)
	row.Cells["PathInProcessRoot"] = evidence.Value{Kind: "bool", Data: scope == "process_root" && err == nil}
	if err != nil {
		row.Cells["Path"], row.Cells["PathRaw"] = evidence.Missing("file_path_unreadable", err), evidence.Missing("file_path_unreadable", err)
		failures.add(err)
	} else {
		row.Cells["PathRaw"] = evidence.Bytes(name)
		text := strings.ToValidUTF8(string(name), "\ufffd")
		// Kernel dynamic labels are not normal filesystem paths. Keep their
		// display unchanged; inode link state is retained in a separate field.
		if scope != "dynamic_name" && row.Cells["Deleted"].Data == true {
			text += " (deleted)"
		}
		row.Cells["Path"] = evidence.Text(text)
	}
	if err := failures.err("open file metadata/path"); err != nil {
		row.Cells["Error"] = evidence.Missing("file_metadata_incomplete", err)
		return err
	}
	return nil
}
