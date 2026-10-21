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

func linuxMountInfoPlugins() []builtin {
	columns := []evidence.Column{
		{Name: "MNT_NS_ID", Kind: "uint64"}, {Name: "PID", Kind: "uint64"},
		{Name: "MOUNT ID", Kind: "int64"}, {Name: "PARENT_ID", Kind: "int64"},
		{Name: "MAJOR:MINOR", Kind: "string"}, {Name: "ROOT", Kind: "string"},
		{Name: "MOUNT_POINT", Kind: "string"}, {Name: "MOUNT_OPTIONS", Kind: "string"},
		{Name: "FIELDS", Kind: "string"}, {Name: "FSTYPE", Kind: "string"},
		{Name: "MOUNT_SRC", Kind: "string"}, {Name: "SB_OPTIONS", Kind: "string"},
		{Name: "DEVNAME", Kind: "string"}, {Name: "PATH", Kind: "string"}, {Name: "MNT_OPTS", Kind: "string"},
		{Name: "Mount", Kind: "address"}, {Name: "Task", Kind: "address"}, {Name: "Superblock", Kind: "address"},
		{Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"},
		{Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
	}
	return []builtin{{plugin.Spec{
		Name: "linux.mountinfo", Upstream: "linux.mountinfo.MountInfo", Platform: "linux", NeedsKernel: true,
		Description: "List per-namespace mount points in /proc/pid/mountinfo form, including the brief mount -l view",
		Parameters: []plugin.Parameter{
			{Name: "pids", Kind: "string", Description: "Optional comma-separated task.pid filter; repeats mounts for each selected task"},
			{Name: "mntns", Kind: "string", Description: "Optional comma-separated mount-namespace inode filter"},
			{Name: "mount-format", Kind: "bool", Default: "false", Description: "Record that the brief devname/path/fstype/options view is selected"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task and mount visit bound, 1..1000000"},
			{Name: "max-mounts", Kind: "uint", Default: "131072", Description: "Mount object bound, 1..1000000"},
		},
		Columns: columns,
	}, linuxMountInfo}}
}

func linuxMountOptionList(flags uint64) (string, []string) {
	access := "rw"
	if flags&0x40 != 0 {
		access = "ro"
	}
	options := []string{access}
	for _, item := range []struct {
		bit  uint64
		name string
	}{{0x01, "nosuid"}, {0x02, "nodev"}, {0x04, "noexec"}, {0x08, "noatime"}, {0x10, "nodiratime"}, {0x20, "relatime"}} {
		if flags&item.bit != 0 {
			options = append(options, item.name)
		}
	}
	return strings.Join(options, ","), options
}

func linuxSuperOptionList(flags uint64) (string, []string) {
	access := "rw"
	if flags&1 != 0 {
		access = "ro"
	}
	options := []string{access}
	for _, item := range []struct {
		bit  uint64
		name string
	}{{16, "sync"}, {128, "dirsync"}, {64, "mand"}, {1 << 25, "lazytime"}} {
		if flags&item.bit != 0 {
			options = append(options, item.name)
		}
	}
	return strings.Join(options, ","), options
}

func linuxDeviceNumber(dev uint64) string {
	const minorBits = 20
	return strconv.FormatUint(dev>>minorBits, 10) + ":" + strconv.FormatUint(dev&((1<<minorBits)-1), 10)
}

func linuxMountPointDisplay(path string, deleted bool) string {
	if deleted {
		return " " + path + " (deleted)"
	}
	return path
}

func linuxJoinUniqueOptions(groups ...[]string) string {
	seen := map[string]bool{}
	var out []string
	for _, group := range groups {
		for _, item := range group {
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			out = append(out, item)
		}
	}
	return strings.Join(out, ",")
}

func linuxMountInfo(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("linux.mountinfo requires kernel memory and symbols")
	}
	maxNodes, pids, err := limits(map[string]string{"max-nodes": p["max-nodes"], "pid": p["pids"]})
	if err != nil {
		return err
	}
	maxMounts, err := strconv.ParseUint(p["max-mounts"], 0, 32)
	if err != nil || maxMounts < 1 || maxMounts > 1000000 {
		return fmt.Errorf("max-mounts must be 1..1000000")
	}
	mountFormat, err := strconv.ParseBool(p["mount-format"])
	if err != nil {
		return fmt.Errorf("mount-format: %w", err)
	}
	var namespaceFilter map[uint64]bool
	if p["mntns"] != "" {
		namespaceFilter = map[uint64]bool{}
		for _, token := range strings.Split(p["mntns"], ",") {
			value, err := strconv.ParseUint(strings.TrimSpace(token), 0, 64)
			if err != nil {
				return fmt.Errorf("mntns: %w", err)
			}
			namespaceFilter[value] = true
		}
	}
	mountType := "vfsmount"
	var embedded uint64
	if _, err := e.Symbols.Type("mount"); err == nil {
		mountType = "mount"
		field, err := e.Objects.Field("mount", "mnt")
		if err != nil {
			return err
		}
		if field.Type.Kind != "struct" || field.Type.Name != "vfsmount" {
			return fmt.Errorf("unsupported mount.mnt layout")
		}
		embedded = field.Offset
	}
	for _, spec := range []struct{ typ, field string }{
		{"vfsmount", "mnt_root"}, {"vfsmount", "mnt_sb"}, {"vfsmount", "mnt_flags"},
		{mountType, "mnt_id"}, {mountType, "mnt_parent"}, {mountType, "mnt_mountpoint"},
		{mountType, "mnt_group_id"}, {mountType, "mnt_master"},
		{"super_block", "s_dev"}, {"super_block", "s_flags"}, {"super_block", "s_type"},
		{"dentry", "d_parent"},
	} {
		if _, err := e.Objects.Field(spec.typ, spec.field); err != nil {
			return fmt.Errorf("mountinfo layout unavailable: %s.%s: %w", spec.typ, spec.field, err)
		}
	}
	columns := linuxMountInfoPlugins()[0].spec.Columns
	var failures pluginFailures
	var emitErr error
	emit := func(r evidence.Row) error {
		if emitErr != nil {
			return emitErr
		}
		if err := ctx.Err(); err != nil {
			emitErr = err
			return err
		}
		for _, column := range columns {
			if _, ok := r.Cells[column.Name]; !ok {
				r.Cells[column.Name] = evidence.Missing("not_applicable", nil)
			}
		}
		emitErr = out(r)
		return emitErr
	}
	base := func(task, pid, mount uint64, ns evidence.Value) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", mount)}}
		r.Cells["Task"], r.Cells["Mount"], r.Cells["MNT_NS_ID"] = evidence.Address(task), evidence.Address(mount), ns
		if pids != nil {
			r.Cells["PID"] = evidence.Number(pid)
		}
		return r
	}
	diagnostic := func(r evidence.Row, reason string, cause error) error {
		failures.add(cause)
		r.Cells["RecordType"] = evidence.Text("diagnostic")
		r.Cells["Error"] = evidence.Missing(reason, cause)
		return emit(r)
	}
	seenNS, seenID := map[uint64]bool{}, map[int64]bool{}
	var mounts, entities, skipped uint64
	filterIgnored := false
	err = visitLinuxProcesses(ctx, e, maxNodes, pids, func(task, pid uint64, _ string, _ evidence.Value) error {
		nsValue := evidence.Missing("namespace_inode_not_in_layout", nil)
		fs, err := e.Objects.Uint(ctx, task, "task_struct", "fs")
		if err != nil {
			return diagnostic(base(task, pid, 0, nsValue), "task_fs_unreadable", err)
		}
		nsproxy, err := e.Objects.Uint(ctx, task, "task_struct", "nsproxy")
		if err != nil {
			return diagnostic(base(task, pid, 0, nsValue), "task_nsproxy_unreadable", err)
		}
		if fs == 0 || nsproxy == 0 {
			skipped++
			return nil
		}
		ns, err := e.Objects.Uint(ctx, nsproxy, "nsproxy", "mnt_ns")
		if err != nil {
			return diagnostic(base(task, pid, 0, nsValue), "mount_namespace_unreadable", err)
		}
		if ns == 0 {
			skipped++
			return nil
		}
		if id, err := linuxMember(ctx, e, ns, "mnt_namespace", "proc_inum", "ns.inum"); err == nil {
			nsValue = evidence.Number(id)
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return diagnostic(base(task, pid, 0, evidence.Missing("namespace_inode_unreadable", err)), "namespace_inode_unreadable", err)
		}
		if namespaceFilter != nil {
			if nsValue.Kind == "missing" {
				filterIgnored = true
			} else if id, err := nsValue.Uint(); err != nil || !namespaceFilter[id] {
				return nil
			}
		}
		if pids == nil {
			if seenNS[ns] {
				return nil
			}
			seenNS[ns] = true
		}
		rootDentry, rootMount, err := linuxProcessRoot(ctx, e, task)
		if err != nil {
			return diagnostic(base(task, pid, 0, nsValue), "process_root_unreadable", err)
		}
		each := func(address uint64) error {
			if mounts >= maxMounts {
				return fmt.Errorf("mount count exceeds max-mounts")
			}
			mounts++
			r := base(task, pid, address, nsValue)
			fields := map[string]evidence.Value{}
			r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
			vfs, err := memory.Add(address, embedded)
			if err != nil {
				return diagnostic(r, "mount_container_invalid", err)
			}
			id, _, err := linuxSignedField(ctx, e, address, mountType, "mnt_id", fields, "MountID")
			if err != nil {
				return diagnostic(r, "mount_id_unreadable", err)
			}
			if pids == nil {
				if seenID[id] {
					return nil
				}
				seenID[id] = true
			}
			root, err := e.Objects.Uint(ctx, vfs, "vfsmount", "mnt_root")
			if err != nil {
				return diagnostic(r, "mount_root_unreadable", err)
			}
			if root == 0 {
				return diagnostic(r, "mount_root_absent", fmt.Errorf("mount %#x has a null root", address))
			}
			parentVFS, point, err := linuxMountParent(ctx, e, vfs)
			if err != nil {
				return diagnostic(r, "mount_parent_unreadable", err)
			}
			scope := "process_root"
			path, err := linuxPathAtRoot(ctx, e, rootDentry, rootMount, root, vfs, &scope, false)
			if err != nil {
				return diagnostic(r, "mount_point_unreadable", err)
			}
			if len(path) == 0 {
				return diagnostic(r, "mount_point_absent", fmt.Errorf("mount %#x has an empty path", address))
			}
			deleted, err := linuxMountPointDeleted(ctx, e, point)
			if err != nil {
				return diagnostic(r, "mount_point_inode_unreadable", err)
			}
			display := linuxMountPointDisplay(string(path), deleted)
			sb, err := e.Objects.Uint(ctx, vfs, "vfsmount", "mnt_sb")
			if err != nil {
				return diagnostic(r, "superblock_pointer_unreadable", err)
			}
			r.Cells["Superblock"] = evidence.Address(sb)
			if sb == 0 {
				return diagnostic(r, "superblock_absent", fmt.Errorf("mount %#x has a null superblock", address))
			}
			if err := spoofReadable(ctx, e, sb, "super_block"); err != nil {
				return diagnostic(r, "superblock_unreadable", err)
			}
			dev, _, err := linuxUnsignedField(ctx, e, sb, "super_block", "s_dev", fields, "Device")
			if err != nil {
				return diagnostic(r, "superblock_device_unreadable", err)
			}
			mntFlags, _, err := linuxUnsignedField(ctx, e, vfs, "vfsmount", "mnt_flags", fields, "MountFlags")
			if err != nil {
				return diagnostic(r, "mount_flags_unreadable", err)
			}
			sbFlags, _, err := linuxUnsignedField(ctx, e, sb, "super_block", "s_flags", fields, "SuperFlags")
			if err != nil {
				return diagnostic(r, "superblock_flags_unreadable", err)
			}
			parentOuter, err := linuxOuterMount(parentVFS, mountType, embedded)
			if err != nil {
				return diagnostic(r, "parent_mount_invalid", err)
			}
			parentID, _, err := linuxSignedField(ctx, e, parentOuter, mountType, "mnt_id", fields, "ParentID")
			if err != nil {
				return diagnostic(r, "parent_id_unreadable", err)
			}
			rootPath, err := linuxDentryTreePath(ctx, e, root)
			if err != nil {
				return diagnostic(r, "mount_root_path_unreadable", err)
			}
			fstype, err := linuxMountFilesystemType(ctx, e, sb, fields)
			if err != nil {
				return diagnostic(r, "filesystem_type_unreadable", err)
			}
			source, err := linuxMountDevname(ctx, e, address, vfs, mountType, fields)
			if err != nil {
				return diagnostic(r, "mount_source_unreadable", err)
			}
			tagged, err := linuxMountTaggedFields(ctx, e, address, mountType, mntFlags, ns, rootDentry, rootMount, embedded, fields)
			if err != nil {
				return diagnostic(r, "mount_fields_unreadable", err)
			}
			mntText, mntOpts := linuxMountOptionList(mntFlags)
			sbText, sbOpts := linuxSuperOptionList(sbFlags)
			r.Cells["MOUNT ID"], r.Cells["PARENT_ID"] = evidence.Integer(id), evidence.Integer(parentID)
			r.Cells["MAJOR:MINOR"] = evidence.Text(linuxDeviceNumber(dev))
			r.Cells["ROOT"], r.Cells["MOUNT_POINT"] = evidence.Text(rootPath), evidence.Text(display)
			r.Cells["MOUNT_OPTIONS"], r.Cells["FIELDS"] = evidence.Text(mntText), evidence.Text(strings.Join(tagged, " "))
			r.Cells["FSTYPE"] = fstype
			r.Cells["MOUNT_SRC"], r.Cells["SB_OPTIONS"] = evidence.Text(source), evidence.Text(sbText)
			r.Cells["DEVNAME"], r.Cells["PATH"] = evidence.Text(source), evidence.Text(display)
			r.Cells["MNT_OPTS"] = evidence.Text(linuxJoinUniqueOptions(mntOpts, sbOpts))
			r.Cells["RecordType"] = evidence.Text("mount")
			entities++
			return emit(r)
		}
		if err := linuxWalkNamespaceMounts(ctx, e, ns, mountType, int(maxMounts), each); err != nil {
			if emitErr != nil {
				return emitErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return diagnostic(base(task, pid, ns, nsValue), "mount_list_incomplete", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: "mountinfo"}}
	summary.Cells["RecordType"] = evidence.Text("summary")
	scope := "one row per mount id; absent roots are diagnostics and read failures fail the task"
	if pids != nil {
		scope = "pid filter repeats mounts; absent roots are diagnostics and read failures fail the task"
	}
	if mountFormat {
		scope += "; brief columns repeat the detailed source, path, type and combined options"
	}
	summary.Cells["Coverage"] = poolCoverage(map[string]string{"mounts_visited": formatCount(mounts), "entities": formatCount(entities), "tasks_without_namespace": formatCount(skipped), "mntns_filter_ignored": strconv.FormatBool(filterIgnored), "read_layout_errors": strconv.Itoa(failures.count), "scope": scope})
	if err := emit(summary); err != nil {
		return err
	}
	return failures.err("Linux mountinfo")
}

func linuxOuterMount(vfs uint64, mountType string, embedded uint64) (uint64, error) {
	if mountType != "mount" {
		return vfs, nil
	}
	if vfs < embedded {
		return 0, fmt.Errorf("parent mount container underflow")
	}
	return vfs - embedded, nil
}

func linuxWalkNamespaceMounts(ctx context.Context, e plugin.Environment, ns uint64, mountType string, maxMounts int, each func(uint64) error) error {
	field, err := e.Objects.Field("mnt_namespace", "list")
	if err == nil {
		if field.Type.Kind != "struct" || field.Type.Name != "list_head" {
			return fmt.Errorf("unsupported mount namespace list")
		}
		head, err := memory.Add(ns, field.Offset)
		if err != nil {
			return err
		}
		link, err := e.Objects.Field(mountType, "mnt_list")
		if err != nil {
			return err
		}
		return e.Objects.WalkList(ctx, head, link.Offset, maxMounts, each)
	}
	if !errors.Is(err, object.ErrFieldAbsent) {
		return err
	}
	field, err = e.Objects.Field("mnt_namespace", "mounts")
	if err != nil {
		return err
	}
	if mountType != "mount" || field.Type.Kind != "struct" || field.Type.Name != "rb_root" {
		return fmt.Errorf("unsupported mount namespace tree")
	}
	head, err := memory.Add(ns, field.Offset)
	if err != nil {
		return err
	}
	link, err := e.Objects.Field("mount", "mnt_node")
	if err != nil {
		return err
	}
	return e.Objects.WalkRBTree(ctx, head, link.Offset, maxMounts, each)
}

func linuxSignedField(ctx context.Context, e plugin.Environment, base uint64, typ, path string, fields map[string]evidence.Value, name string) (int64, evidence.Value, error) {
	proof, err := linuxFieldProof(ctx, e, base, typ, path)
	fields[name] = proof
	if err != nil {
		return 0, proof, err
	}
	value, err := e.Objects.Int(ctx, base, typ, path)
	if err != nil {
		return 0, proof, err
	}
	return value, proof, nil
}

func linuxUnsignedField(ctx context.Context, e plugin.Environment, base uint64, typ, path string, fields map[string]evidence.Value, name string) (uint64, evidence.Value, error) {
	proof, err := linuxFieldProof(ctx, e, base, typ, path)
	fields[name] = proof
	if err != nil {
		return 0, proof, err
	}
	value, err := e.Objects.Uint(ctx, base, typ, path)
	if err != nil {
		return 0, proof, err
	}
	return value, proof, nil
}

func linuxFieldProof(ctx context.Context, e plugin.Environment, base uint64, typ, path string) (evidence.Value, error) {
	field, err := e.Objects.Field(typ, path)
	if err != nil {
		return evidence.Missing("field_unavailable", err), err
	}
	size, err := e.Objects.Size(field.Type)
	if err != nil {
		return evidence.Missing("field_size_unavailable", err), err
	}
	if size == 0 || size > 64 {
		err = fmt.Errorf("%s.%s has unsupported capture size %d", typ, path, size)
		return evidence.Missing("field_size_unsupported", err), err
	}
	address, err := memory.Add(base, field.Offset)
	if err != nil {
		return evidence.Missing("field_address_invalid", err), err
	}
	_, proof, err := linuxCaptureRange(ctx, e.Kernel, address, int(size))
	return proof, err
}

func linuxMountPointDeleted(ctx context.Context, e plugin.Environment, dentry uint64) (bool, error) {
	inode, err := e.Objects.Uint(ctx, dentry, "dentry", "d_inode")
	if err != nil {
		return false, err
	}
	if inode == 0 {
		return false, nil
	}
	if err := spoofReadable(ctx, e, inode, "inode"); err != nil {
		return false, err
	}
	number, err := e.Objects.Uint(ctx, inode, "inode", "i_ino")
	if err != nil {
		return false, err
	}
	count, err := e.Objects.Int(ctx, inode, "inode", "i_count.counter")
	if err != nil {
		return false, err
	}
	if number == 0 || count < 0 {
		return false, nil
	}
	links, err := linuxMember(ctx, e, inode, "inode", "i_nlink", "__i_nlink")
	if err != nil {
		return false, err
	}
	return links == 0, nil
}

func linuxDentryTreePath(ctx context.Context, e plugin.Environment, dentry uint64) (string, error) {
	seen := map[uint64]bool{}
	var names []string
	for depth := 0; depth < 256; depth++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		parent, err := e.Objects.Uint(ctx, dentry, "dentry", "d_parent")
		if err != nil {
			return "", err
		}
		if dentry == parent {
			break
		}
		if dentry == 0 || seen[dentry] {
			return "", fmt.Errorf("cyclic dentry path at %#x", dentry)
		}
		seen[dentry] = true
		name, err := linuxDentryName(ctx, e, dentry)
		if err != nil {
			return "", err
		}
		names = append(names, string(name))
		dentry = parent
	}
	if len(names) == 256 {
		return "", fmt.Errorf("dentry path depth exceeds 256")
	}
	var path strings.Builder
	path.WriteByte('/')
	for i := len(names) - 1; i >= 0; i-- {
		if i != len(names)-1 {
			path.WriteByte('/')
		}
		path.WriteString(names[i])
		if path.Len() > 16384 {
			return "", fmt.Errorf("dentry path exceeds 16KiB")
		}
	}
	return path.String(), nil
}

func linuxMountFilesystemType(ctx context.Context, e plugin.Environment, sb uint64, fields map[string]evidence.Value) (evidence.Value, error) {
	pointer, err := e.Objects.Uint(ctx, sb, "super_block", "s_type")
	if err != nil {
		return evidence.Missing("fstype_unreadable", err), err
	}
	if pointer == 0 {
		return evidence.Missing("not_available", nil), nil
	}
	field, err := e.Objects.Field("super_block", "s_type")
	if err != nil {
		return evidence.Missing("fstype_unreadable", err), err
	}
	target := field.Type.Name
	if field.Type.Kind == "pointer" {
		if field.Type.Subtype != nil && field.Type.Subtype.Name != "" {
			target = field.Type.Subtype.Name
		} else if field.Type.Base != "" {
			target = field.Type.Base
		}
	}
	if target == "" || target == "pointer" {
		target = "file_system_type"
	}
	if err := spoofReadable(ctx, e, pointer, target); err != nil {
		return evidence.Missing("fstype_unreadable", err), err
	}
	namePtr, err := e.Objects.Uint(ctx, pointer, target, "name")
	if err != nil {
		return evidence.Missing("fstype_unreadable", err), err
	}
	if namePtr == 0 {
		return evidence.Missing("not_available", nil), nil
	}
	name, proof, err := linuxBoundedText(ctx, e, namePtr, 255)
	fields["FSType"] = proof
	if err != nil {
		return evidence.Missing("fstype_unreadable", err), err
	}
	if _, err := e.Objects.Field("super_block", "s_subtype"); err == nil {
		sub, err := e.Objects.Uint(ctx, sb, "super_block", "s_subtype")
		if err != nil {
			return evidence.Missing("fstype_unreadable", err), err
		}
		if sub != 0 {
			text, subProof, err := linuxBoundedText(ctx, e, sub, 255)
			fields["FSSubtype"] = subProof
			if err != nil {
				return evidence.Missing("fstype_unreadable", err), err
			}
			name += "." + text
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return evidence.Missing("fstype_unreadable", err), err
	}
	return evidence.Text(name), nil
}

func linuxMountDevname(ctx context.Context, e plugin.Environment, mount, vfs uint64, mountType string, fields map[string]evidence.Value) (string, error) {
	base, typ := mount, mountType
	if _, err := e.Objects.Field(mountType, "mnt_devname"); err != nil {
		if !errors.Is(err, object.ErrFieldAbsent) {
			return "", err
		}
		base, typ = vfs, "vfsmount"
	}
	pointer, err := e.Objects.Uint(ctx, base, typ, "mnt_devname")
	if err != nil {
		return "", err
	}
	if pointer == 0 {
		return "", fmt.Errorf("mount source pointer is null")
	}
	text, proof, err := linuxBoundedText(ctx, e, pointer, 255)
	fields["Devname"] = proof
	if err != nil {
		return "", err
	}
	if text == "" {
		return "none", nil
	}
	return text, nil
}

func linuxBoundedText(ctx context.Context, e plugin.Environment, address uint64, count int) (string, evidence.Value, error) {
	raw, proof, err := linuxCaptureRange(ctx, e.Kernel, address, count)
	if len(raw) == 0 {
		if err == nil {
			err = fmt.Errorf("empty string capture")
		}
		return "", proof, err
	}
	// A NUL inside the contiguous prefix completes the string. A fault before
	// that NUL stays a read failure instead of a shortened name.
	for _, b := range raw {
		if b == 0 {
			return spoofDecoded(raw), proof, nil
		}
	}
	if err != nil {
		return "", proof, err
	}
	return spoofDecoded(raw), proof, nil
}

func linuxMountTaggedFields(ctx context.Context, e plugin.Environment, mount uint64, mountType string, flags, ns, rootDentry, rootMount, embedded uint64, fields map[string]evidence.Value) ([]string, error) {
	var tagged []string
	if flags&0x1000 != 0 {
		group, _, err := linuxSignedField(ctx, e, mount, mountType, "mnt_group_id", fields, "GroupID")
		if err != nil {
			return nil, err
		}
		tagged = append(tagged, "shared:"+strconv.FormatInt(group, 10))
	}
	master, err := e.Objects.Uint(ctx, mount, mountType, "mnt_master")
	if err != nil {
		return nil, err
	}
	if master != 0 {
		group, _, err := linuxSignedField(ctx, e, master, mountType, "mnt_group_id", fields, "MasterGroup")
		if err != nil {
			return nil, err
		}
		tagged = append(tagged, "master:"+strconv.FormatInt(group, 10))
		dominating, err := linuxDominatingGroup(ctx, e, master, mountType, ns, rootDentry, rootMount, embedded, map[uint64]bool{})
		if err != nil {
			return nil, err
		}
		if dominating != 0 && dominating != group {
			tagged = append(tagged, "propagate_from:"+strconv.FormatInt(dominating, 10))
		}
	}
	if flags&0x2000 != 0 {
		tagged = append(tagged, "unbindable")
	}
	return tagged, nil
}

func linuxDominatingGroup(ctx context.Context, e plugin.Environment, master uint64, mountType string, ns, rootDentry, rootMount, embedded uint64, seen map[uint64]bool) (int64, error) {
	current := master
	for current != 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if seen[current] {
			break
		}
		seen[current] = true
		peer, err := linuxPeerUnderRoot(ctx, e, current, mountType, ns, rootDentry, rootMount, embedded)
		if err != nil {
			return 0, err
		}
		if peer != 0 {
			return e.Objects.Int(ctx, peer, mountType, "mnt_group_id")
		}
		next, err := e.Objects.Uint(ctx, current, mountType, "mnt_master")
		if err != nil {
			return 0, err
		}
		current = next
	}
	return 0, nil
}

func linuxPeerUnderRoot(ctx context.Context, e plugin.Environment, start uint64, mountType string, ns, rootDentry, rootMount, embedded uint64) (uint64, error) {
	current := start
	seen := map[uint64]bool{}
	share, err := e.Objects.Field(mountType, "mnt_share")
	if err != nil {
		return 0, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if seen[current] {
			return 0, fmt.Errorf("mount peer cycle at %#x", current)
		}
		seen[current] = true
		owner, err := e.Objects.Uint(ctx, current, mountType, "mnt_ns")
		if err != nil {
			return 0, err
		}
		vfs := current
		if mountType == "mount" {
			vfs, err = memory.Add(current, embedded)
			if err != nil {
				return 0, err
			}
		}
		root, err := e.Objects.Uint(ctx, vfs, "vfsmount", "mnt_root")
		if err != nil {
			return 0, err
		}
		if owner == ns {
			reachable, err := linuxMountPathReachable(ctx, e, current, mountType, root, rootDentry, rootMount, embedded, map[uint64]bool{})
			if err != nil {
				return 0, err
			}
			if reachable {
				return current, nil
			}
		}
		next, err := e.Objects.Uint(ctx, current, mountType, "mnt_share.next")
		if err != nil {
			return 0, err
		}
		if next < share.Offset {
			return 0, fmt.Errorf("mount peer pointer underflow")
		}
		peer := next - share.Offset
		if peer == start {
			return 0, nil
		}
		current = peer
		if len(seen) > 1000000 {
			return 0, fmt.Errorf("mount peer walk exceeds bound")
		}
	}
}

func linuxMountPathReachable(ctx context.Context, e plugin.Environment, mount uint64, mountType string, dentry, rootDentry, rootMount, embedded uint64, seen map[uint64]bool) (bool, error) {
	current := mount
	for {
		vfs := current
		var err error
		if mountType == "mount" {
			vfs, err = memory.Add(current, embedded)
			if err != nil {
				return false, err
			}
		}
		if vfs == rootMount || seen[current] {
			break
		}
		parent, err := e.Objects.Uint(ctx, current, mountType, "mnt_parent")
		if err != nil {
			return false, err
		}
		if parent == current {
			break
		}
		seen[current] = true
		point, err := e.Objects.Uint(ctx, current, mountType, "mnt_mountpoint")
		if err != nil {
			return false, err
		}
		dentry = point
		current = parent
	}
	vfs := current
	if mountType == "mount" {
		next, err := memory.Add(current, embedded)
		if err != nil {
			return false, err
		}
		vfs = next
	}
	if vfs != rootMount {
		return false, nil
	}
	return linuxDentryIsSubdir(ctx, e, dentry, rootDentry)
}

func linuxDentryIsSubdir(ctx context.Context, e plugin.Environment, dentry, ancestor uint64) (bool, error) {
	if dentry == ancestor {
		return true, nil
	}
	seen := map[uint64]bool{}
	for depth := 0; depth < 256; depth++ {
		parent, err := e.Objects.Uint(ctx, dentry, "dentry", "d_parent")
		if err != nil {
			return false, err
		}
		if dentry == parent || seen[dentry] {
			return false, nil
		}
		if parent == ancestor {
			return true, nil
		}
		seen[dentry] = true
		dentry = parent
	}
	return false, fmt.Errorf("dentry ancestry exceeds 256")
}
