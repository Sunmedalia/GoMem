package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxFilesPlugins() []builtin {
	columns := []evidence.Column{}
	for _, g := range []struct{ kind, names string }{
		{"string", "FilePath FileType FileMode Device MountPoint PathScope MountScope RecordType Error AccessTime ModificationTime ChangeTime"},
		{"address", "InodeAddr SuperblockAddr Dentry ParentDentry Mapping Mount MountRoot SuperblockRoot TaskOffset Namespace FirstDentry MountRootInode MountAttachment MountAttachmentInode"},
		{"uint64", "InodeNum InodePages CachedPages PID MountID NamespaceID ModeRaw Nlink Depth MountRootNlink MountAttachmentNlink"},
		{"int64", "InodeSize"}, {"bool", "Deleted MountRootDeleted MountAttachmentDeleted"}, {"bytes", "PathRaw MountPointRaw SymlinkTargetRaw"}, {"structure", "AccessTimeRaw ModificationTimeRaw ChangeTimeRaw Coverage"},
	} {
		for _, n := range strings.Fields(g.names) {
			columns = append(columns, evidence.Column{Name: n, Kind: g.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.files", Upstream: "linux.pagecache.Files", Platform: "linux", NeedsKernel: true, Description: "Enumerate cached dentries from task-mounted superblock roots, retaining hardlink aliases and path scope", Parameters: []plugin.Parameter{
		{Name: "type", Kind: "string", Description: "Comma/space-separated Linux inode types: REG DIR LNK CHR BLK FIFO SOCK"},
		{Name: "find", Kind: "string", Description: "First exact undecorated UTF-8 full path, after the type filter; does not resolve symlinks"},
		{Name: "follow-symlinks", Kind: "bool", Default: "true", Description: "Annotate available fast i_link targets; never traverse the target"},
		{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task and individual child-list traversal bound, 1..1000000"},
		{Name: "max-mounts", Kind: "uint", Default: "1000000", Description: "Total mount address bound, 1..1000000"},
		{Name: "max-dentries", Kind: "uint", Default: "1000000", Description: "Total dentry visits including negative entries, 1..1000000"},
		{Name: "max-depth", Kind: "uint", Default: "256", Description: "Maximum child depth, 1..1024; paths also bounded to 16KiB"},
	}, Columns: columns}, linuxFiles}}
}

var errLinuxFileFound = errors.New("requested filesystem path found")

func linuxVisitChildren(ctx context.Context, e plugin.Environment, parent uint64, max int, out func(uint64) error) error {
	var headName, linkName string
	if _, err := e.Objects.Field("dentry", "d_children"); err == nil {
		headName, linkName = "d_children", "d_sib"
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return err
	} else {
		headName = "d_subdirs"
		if _, err = e.Objects.Field("dentry", "d_child"); err == nil {
			linkName = "d_child"
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return err
		} else {
			linkName = "d_u.d_child"
		}
	}
	head, err := e.Objects.Field("dentry", headName)
	if err != nil {
		return err
	}
	link, err := e.Objects.Field("dentry", linkName)
	if err != nil {
		return err
	}
	address, err := memory.Add(parent, head.Offset)
	if err != nil {
		return err
	}
	if head.Type.Kind != "struct" {
		return fmt.Errorf("unsupported child-list layout")
	}
	switch head.Type.Name {
	case "list_head":
		return e.Objects.WalkList(ctx, address, link.Offset, max, out)
	case "hlist_head":
		return e.Objects.WalkHList(ctx, address, link.Offset, max, out)
	default:
		return fmt.Errorf("unsupported child-list type %s", head.Type.Name)
	}
}
func linuxFastSymlink(ctx context.Context, e plugin.Environment, inode uint64) (evidence.Value, error) {
	if _, err := e.Objects.Field("inode", "i_link"); errors.Is(err, object.ErrFieldAbsent) {
		return evidence.Missing("fast_symlink_not_in_layout", nil), nil
	} else if err != nil {
		return evidence.Missing("fast_symlink_unavailable", err), err
	}
	pointer, err := e.Objects.Uint(ctx, inode, "inode", "i_link")
	if err != nil {
		return evidence.Missing("fast_symlink_unreadable", err), err
	}
	if pointer == 0 {
		return evidence.Missing("fast_symlink_not_set", nil), nil
	}
	target := []byte{}
	for i := 0; i < 255; i++ {
		address, er := memory.Add(pointer, uint64(i))
		if er != nil {
			return evidence.Bytes(target), er
		}
		b, er := memory.Read(ctx, e.Kernel, address, 1)
		if er != nil {
			return evidence.Bytes(target), er
		}
		if b[0] == 0 {
			return evidence.Bytes(target), nil
		}
		target = append(target, b[0])
	}
	return evidence.Bytes(target), fmt.Errorf("fast symlink exceeds 254-byte terminated bound")
}

func linuxFiles(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	bound := func(name string, max uint64) (int, error) {
		v, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || v == 0 || v > max {
			return 0, fmt.Errorf("%s must be 1..%d", name, max)
		}
		return int(v), nil
	}
	maxNodes, err := bound("max-nodes", 1000000)
	if err != nil {
		return err
	}
	maxMounts, err := bound("max-mounts", 1000000)
	if err != nil {
		return err
	}
	maxDentries, err := bound("max-dentries", 1000000)
	if err != nil {
		return err
	}
	maxDepth, err := bound("max-depth", 1024)
	if err != nil {
		return err
	}
	if p["find"] != "" && (!strings.HasPrefix(p["find"], "/") || strings.IndexByte(p["find"], 0) >= 0 || !utf8.ValidString(p["find"])) {
		return fmt.Errorf("find must be an absolute UTF-8 path without NUL")
	}
	follow, err := strconv.ParseBool(p["follow-symlinks"])
	if err != nil {
		return err
	}
	types := map[string]bool{}
	for _, kind := range strings.Fields(strings.ReplaceAll(p["type"], ",", " ")) {
		switch kind {
		case "REG", "DIR", "LNK", "CHR", "BLK", "FIFO", "SOCK":
			types[kind] = true
		default:
			return fmt.Errorf("unknown Linux file type %q", kind)
		}
	}
	columns := linuxFilesPlugins()[0].spec.Columns
	makeRow := func(m linuxMount, dentry, parent uint64, path []byte, depth int, kind string) evidence.Row {
		c := map[string]evidence.Value{}
		for _, col := range columns {
			c[col.Name] = evidence.Missing("not_applicable", nil)
		}
		c["RecordType"], c["MountPoint"], c["MountPointRaw"], c["MountScope"], c["PathScope"] = evidence.Text(kind), evidence.Text(strings.ToValidUTF8(string(m.path), "�")), evidence.Bytes(m.path), evidence.Text(m.scope), evidence.Text("superblock_tree_at_first_mount")
		c["Dentry"], c["ParentDentry"], c["Mount"], c["MountRoot"], c["SuperblockAddr"], c["TaskOffset"], c["PID"], c["Namespace"], c["MountID"], c["NamespaceID"], c["Depth"] = evidence.Address(dentry), evidence.Address(parent), evidence.Address(m.mount), evidence.Address(m.root), evidence.Address(m.superblock), evidence.Address(m.task), evidence.Number(m.pid), evidence.Address(m.namespace), m.id, m.namespaceID, evidence.Number(uint64(depth))
		c["MountRootInode"], c["MountRootNlink"], c["MountRootDeleted"] = evidence.Address(m.rootInode), evidence.Number(m.rootLinks), evidence.Value{Kind: "bool", Data: m.rootLinks == 0}
		c["MountAttachment"], c["MountAttachmentInode"], c["MountAttachmentNlink"], c["MountAttachmentDeleted"] = evidence.Address(m.attachment), evidence.Address(m.attachmentInode), evidence.Number(m.attachmentLinks), evidence.Value{Kind: "bool", Data: m.attachmentLinks == 0}
		if path != nil {
			c["PathRaw"], c["FilePath"] = evidence.Bytes(path), evidence.Text(strings.ToValidUTF8(string(path), "�"))
		}
		return evidence.Row{Cells: c, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", dentry)}}
	}
	var failures pluginFailures
	var outputErr error
	var found bool
	emit := func(row evidence.Row) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		outputErr = out(row)
		return outputErr
	}
	diagnostic := func(row evidence.Row, reason string, err error) error {
		failures.add(err)
		row.Cells["RecordType"], row.Cells["Error"] = evidence.Text("diagnostic"), evidence.Missing(reason, err)
		return emit(row)
	}
	seenSB, seenDentry, firstInode := map[uint64]bool{}, map[uint64]bool{}, map[uint64]uint64{}
	var visited, negative, files, aliases, mounts uint64
	stopped := false
	err = visitLinuxMounts(ctx, e, maxNodes, maxMounts, func(m linuxMount, mountErr error) error {
		mounts++
		if mountErr != nil {
			return diagnostic(makeRow(m, 0, 0, nil, 0, "diagnostic"), "mount_enumeration_incomplete", mountErr)
		}
		if seenSB[m.superblock] {
			return nil
		}
		seenSB[m.superblock] = true
		root, er := e.Objects.Uint(ctx, m.superblock, "super_block", "s_root")
		if er != nil {
			return diagnostic(makeRow(m, 0, 0, nil, 0, "diagnostic"), "superblock_root_unreadable", er)
		}
		if root == 0 {
			return diagnostic(makeRow(m, 0, 0, nil, 0, "diagnostic"), "superblock_root_invalid", fmt.Errorf("superblock root is null"))
		}
		var visit func(uint64, uint64, []byte, int) error
		visit = func(dentry, parent uint64, path []byte, depth int) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			row := makeRow(m, dentry, parent, path, depth, "file")
			row.Cells["SuperblockRoot"] = evidence.Address(root)
			if depth > maxDepth {
				return diagnostic(row, "depth_bound_exceeded", fmt.Errorf("directory child depth exceeds max-depth"))
			}
			if visited >= uint64(maxDentries) {
				return fmt.Errorf("dentry visits exceed max-dentries")
			}
			visited++
			if seenDentry[dentry] {
				return diagnostic(row, "dentry_repeated", fmt.Errorf("repeated dentry %#x", dentry))
			}
			seenDentry[dentry] = true
			actualParent, er := e.Objects.Uint(ctx, dentry, "dentry", "d_parent")
			if er != nil {
				return diagnostic(row, "dentry_parent_unreadable", er)
			}
			if actualParent != parent {
				return diagnostic(row, "dentry_parent_mismatch", fmt.Errorf("dentry parent %#x differs from expected %#x", actualParent, parent))
			}
			inode, er := e.Objects.Uint(ctx, dentry, "dentry", "d_inode")
			if er != nil {
				return diagnostic(row, "inode_pointer_unreadable", er)
			}
			if inode == 0 {
				negative++
				return nil
			}
			row.Cells["InodeAddr"] = evidence.Address(inode)
			number, er := e.Objects.Uint(ctx, inode, "inode", "i_ino")
			if er != nil {
				return diagnostic(row, "inode_number_unreadable", er)
			}
			count, er := e.Objects.Int(ctx, inode, "inode", "i_count.counter")
			if er != nil {
				return diagnostic(row, "inode_count_unreadable", er)
			}
			if number == 0 || count < 0 {
				return diagnostic(row, "inode_invalid", fmt.Errorf("invalid inode number/reference count"))
			}
			if depth > 0 {
				name, er := linuxDentryName(ctx, e, dentry)
				if er != nil {
					return diagnostic(row, "dentry_name_unreadable", er)
				}
				if bytes.IndexByte(name, '/') >= 0 || bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
					return diagnostic(row, "dentry_name_invalid", fmt.Errorf("invalid path component"))
				}
				joined := make([]byte, 0, len(path)+len(name)+1)
				joined = append(joined, bytes.TrimSuffix(path, []byte("/"))...)
				joined = append(joined, '/')
				path = append(joined, name...)
				if len(path) > 16384 {
					return diagnostic(row, "path_bound_exceeded", fmt.Errorf("path exceeds 16KiB"))
				}
				row.Cells["PathRaw"], row.Cells["FilePath"] = evidence.Bytes(path), evidence.Text(strings.ToValidUTF8(string(path), "�"))
			}
			metadata, metaErr := linuxReadInodeMetadata(ctx, e, inode, "dentry.d_inode")
			for dest, source := range map[string]string{"InodeNum": "Inode", "FileType": "Type", "FileMode": "Mode", "ModeRaw": "ModeRaw", "InodeSize": "Size", "Device": "Device", "Nlink": "Nlink", "Deleted": "Deleted", "AccessTime": "Accessed", "AccessTimeRaw": "AccessedRaw", "ModificationTime": "Modified", "ModificationTimeRaw": "ModifiedRaw", "ChangeTime": "Changed", "ChangeTimeRaw": "ChangedRaw"} {
				row.Cells[dest] = metadata[source]
			}
			var entityErr error
			entityErr = metaErr
			sb, sbErr := metadata["Superblock"].Uint()
			if sbErr != nil {
				entityErr = errors.Join(entityErr, sbErr)
			} else if sb != m.superblock {
				entityErr = errors.Join(entityErr, fmt.Errorf("inode superblock differs from mount tree"))
			}
			size, sizeErr := metadata["Size"].Int()
			if sizeErr != nil || size < 0 {
				if sizeErr == nil {
					sizeErr = fmt.Errorf("negative inode size")
				}
				row.Cells["InodePages"] = evidence.Missing("inode_size_invalid", sizeErr)
				entityErr = errors.Join(entityErr, sizeErr)
			} else {
				row.Cells["InodePages"] = evidence.Number(uint64(size)/4096 + boolUint(size%4096 != 0))
			}
			mapping, mapErr := e.Objects.Uint(ctx, inode, "inode", "i_mapping")
			if mapErr == nil && mapping == 0 {
				mapErr = fmt.Errorf("inode mapping is null")
			}
			if mapErr == nil {
				row.Cells["Mapping"] = evidence.Address(mapping)
				n, er := e.Objects.Uint(ctx, mapping, "address_space", "nrpages")
				if er == nil {
					row.Cells["CachedPages"] = evidence.Number(n)
				} else {
					row.Cells["CachedPages"] = evidence.Missing("cache_count_unreadable", er)
					mapErr = er
				}
			} else {
				row.Cells["Mapping"], row.Cells["CachedPages"] = evidence.Missing("mapping_unavailable", mapErr), evidence.Missing("mapping_unavailable", mapErr)
			}
			entityErr = errors.Join(entityErr, mapErr)
			kind := row.Cells["FileType"].String()
			if depth == 0 && kind != "DIR" {
				entityErr = errors.Join(entityErr, fmt.Errorf("superblock root inode is not a directory"))
			}
			if follow && kind == "LNK" {
				target, er := linuxFastSymlink(ctx, e, inode)
				row.Cells["SymlinkTargetRaw"] = target
				if er == nil && target.Kind == "bytes" {
					row.Cells["FilePath"] = evidence.Text(row.Cells["FilePath"].String() + " -> " + strings.ToValidUTF8(string(target.Data.([]byte)), "�"))
				}
				entityErr = errors.Join(entityErr, er)
			}
			if first, ok := firstInode[inode]; ok {
				row.Cells["RecordType"], row.Cells["FirstDentry"] = evidence.Text("alias"), evidence.Address(first)
				aliases++
			} else {
				firstInode[inode] = dentry
				files++
			}
			if entityErr != nil {
				failures.add(entityErr)
				row.Cells["Error"] = evidence.Missing("inode_metadata_incomplete", entityErr)
			}
			matchesType := len(types) == 0 || types[kind]
			matchesPath := p["find"] == "" || string(path) == p["find"]
			if matchesType && matchesPath {
				if er = emit(row); er != nil {
					return er
				}
				if p["find"] != "" {
					found = true
					return errLinuxFileFound
				}
			}
			// Filtering affects output, never directory descent.
			if kind == "DIR" && sbErr == nil && sb == m.superblock {
				er = linuxVisitChildren(ctx, e, dentry, maxNodes, func(child uint64) error { return visit(child, dentry, path, depth+1) })
				if outputErr != nil || errors.Is(er, errLinuxFileFound) || ctx.Err() != nil {
					return er
				}
				if er != nil {
					return diagnostic(row, "child_enumeration_incomplete", er)
				}
			}
			return nil
		}
		er = visit(root, root, m.path, 0)
		if errors.Is(er, errLinuxFileFound) {
			stopped = true
			return er
		}
		return er
	})
	if outputErr != nil {
		return outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !errors.Is(err, errLinuxFileFound) {
		failures.add(err)
	}
	summary := makeRow(linuxMount{}, 0, 0, nil, 0, "summary")
	for key := range summary.Cells {
		summary.Cells[key] = evidence.Missing("not_applicable", nil)
	}
	summary.Cells["RecordType"] = evidence.Text("summary")
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]any{"superblocks": strconv.Itoa(len(seenSB)), "mount_records": strconv.FormatUint(mounts, 10), "dentry_visits": strconv.FormatUint(visited, 10), "negative_dentries": strconv.FormatUint(negative, 10), "unique_inodes": strconv.FormatUint(files, 10), "aliases": strconv.FormatUint(aliases, 10), "search_found": found, "search_stopped_after_first_match": stopped, "traversal_complete": !stopped && failures.count == 0}}
	if er := failures.err("Linux filesystem enumeration"); er != nil {
		summary.Cells["Error"] = evidence.Missing("filesystem_incomplete", er)
	}
	if err := emit(summary); err != nil {
		return err
	}
	return failures.err("Linux filesystem enumeration")
}
func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// Resolve through the same filesystem producer, keeping lookup evidence in the
// consuming plugin's rows. No open-file-only shortcut or symlink execution.
func linuxResolveCachedFile(ctx context.Context, e plugin.Environment, p map[string]string) (uint64, evidence.Value, error) {
	parameters, err := plugin.Parameters(linuxFilesPlugins()[0].spec, map[string]string{"find": p["find"], "type": "REG", "follow-symlinks": "false", "max-nodes": p["max-nodes"], "max-mounts": p["max-mounts"], "max-dentries": p["max-dentries"], "max-depth": p["max-depth"]})
	if err != nil {
		return 0, evidence.Missing("lookup_parameters_invalid", err), err
	}
	var matched, summary, firstDiagnostic map[string]evidence.Value
	var diagnostics uint64
	err = linuxFiles(ctx, e, parameters, func(row evidence.Row) error {
		switch row.Cells["RecordType"].String() {
		case "file", "alias":
			matched = row.Cells
		case "summary":
			summary = row.Cells
		case "diagnostic":
			diagnostics++
			if firstDiagnostic == nil {
				firstDiagnostic = row.Cells
			}
		}
		return nil
	})
	proof := evidence.Value{Kind: "structure", Data: map[string]any{"requested_path": p["find"], "matched": matched, "summary": summary, "first_diagnostic": firstDiagnostic, "diagnostic_count": strconv.FormatUint(diagnostics, 10), "source": "linux.files native mounted superblock traversal"}}
	if err != nil {
		return 0, proof, err
	}
	if matched == nil {
		return 0, proof, fmt.Errorf("regular path %q not found in captured filesystem dentries", p["find"])
	}
	inode, err := matched["InodeAddr"].Uint()
	return inode, proof, err
}
