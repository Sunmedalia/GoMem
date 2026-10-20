package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type linuxMount struct {
	task, pid, namespace, mount, vfs, root, superblock uint64
	rootInode, rootLinks                               uint64
	attachment, attachmentInode, attachmentLinks       uint64
	id, namespaceID                                    evidence.Value
	path                                               []byte
	scope                                              string
}

// One representative task root per captured namespace. Coordinates identify
// mounts even when old kernels do not expose namespace inode numbers.
func visitLinuxMounts(ctx context.Context, e plugin.Environment, maxTasks, maxMounts int, out func(linuxMount, error) error) error {
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
	namespaces, mounts := map[uint64]bool{}, map[uint64]bool{}
	var outputErr error
	emit := func(m linuxMount, err error) error { outputErr = out(m, err); return outputErr }
	err := visitLinuxProcesses(ctx, e, maxTasks, nil, func(task, pid uint64, _ string, _ evidence.Value) error {
		m := linuxMount{task: task, pid: pid, id: evidence.Missing("mount_id_not_in_layout", nil), namespaceID: evidence.Missing("namespace_inode_not_in_layout", nil)}
		fs, err := e.Objects.Uint(ctx, task, "task_struct", "fs")
		if err != nil {
			return emit(m, err)
		}
		nsproxy, err := e.Objects.Uint(ctx, task, "task_struct", "nsproxy")
		if err != nil {
			return emit(m, err)
		}
		if fs == 0 || nsproxy == 0 {
			return nil
		}
		ns, err := e.Objects.Uint(ctx, nsproxy, "nsproxy", "mnt_ns")
		if err != nil {
			return emit(m, err)
		}
		m.namespace = ns
		if ns == 0 || namespaces[ns] {
			return nil
		}
		rootDentry, rootMount, err := linuxProcessRoot(ctx, e, task)
		if err != nil {
			return emit(m, err)
		}
		namespaces[ns] = true
		nsid, err := linuxMember(ctx, e, ns, "mnt_namespace", "proc_inum", "ns.inum")
		if err == nil {
			m.namespaceID = evidence.Number(nsid)
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			m.namespaceID = evidence.Missing("namespace_inode_unreadable", err)
			if err = emit(m, err); err != nil {
				return err
			}
		}
		each := func(address uint64) error {
			current := m
			current.mount = address
			if mounts[address] {
				return nil
			}
			if len(mounts) >= maxMounts {
				return fmt.Errorf("mount count exceeds max-mounts")
			}
			mounts[address] = true
			var er error
			current.vfs, er = memory.Add(address, embedded)
			if er != nil {
				return emit(current, er)
			}
			if _, er = e.Objects.Field(mountType, "mnt_ns"); er == nil {
				owner, er := e.Objects.Uint(ctx, address, mountType, "mnt_ns")
				if er != nil {
					return emit(current, er)
				}
				if owner != ns {
					return emit(current, fmt.Errorf("mount namespace ownership differs"))
				}
			} else if !errors.Is(er, object.ErrFieldAbsent) {
				return emit(current, er)
			}
			if _, er = e.Objects.Field(mountType, "mnt_id"); er == nil {
				value, er := e.Objects.Uint(ctx, address, mountType, "mnt_id")
				if er != nil {
					return emit(current, er)
				}
				current.id = evidence.Number(value)
			} else if !errors.Is(er, object.ErrFieldAbsent) {
				return emit(current, er)
			}
			current.root, er = e.Objects.Uint(ctx, current.vfs, "vfsmount", "mnt_root")
			if er != nil {
				return emit(current, er)
			}
			current.superblock, er = e.Objects.Uint(ctx, current.vfs, "vfsmount", "mnt_sb")
			if er != nil {
				return emit(current, er)
			}
			if current.root == 0 || current.superblock == 0 {
				return emit(current, fmt.Errorf("mount has null root or superblock"))
			}
			current.rootInode, er = e.Objects.Uint(ctx, current.root, "dentry", "d_inode")
			if er != nil {
				return emit(current, er)
			}
			if current.rootInode == 0 {
				return emit(current, fmt.Errorf("mount root inode is null"))
			}
			current.rootLinks, er = linuxMember(ctx, e, current.rootInode, "inode", "i_nlink", "__i_nlink")
			if er != nil {
				return emit(current, er)
			}
			current.attachment, er = e.Objects.Uint(ctx, current.mount, mountType, "mnt_mountpoint")
			if er != nil {
				return emit(current, er)
			}
			if current.attachment == 0 {
				return emit(current, fmt.Errorf("mount attachment is null"))
			}
			current.attachmentInode, er = e.Objects.Uint(ctx, current.attachment, "dentry", "d_inode")
			if er != nil {
				return emit(current, er)
			}
			if current.attachmentInode == 0 {
				return emit(current, fmt.Errorf("mount attachment inode is null"))
			}
			current.attachmentLinks, er = linuxMember(ctx, e, current.attachmentInode, "inode", "i_nlink", "__i_nlink")
			if er != nil {
				return emit(current, er)
			}
			current.scope = "process_root"
			current.path, er = linuxPathAtRoot(ctx, e, rootDentry, rootMount, current.root, current.vfs, &current.scope, true)
			return emit(current, er)
		}
		if field, er := e.Objects.Field("mnt_namespace", "list"); er == nil {
			if field.Type.Kind != "struct" || field.Type.Name != "list_head" {
				return emit(m, fmt.Errorf("unsupported mount namespace list"))
			}
			head, er := memory.Add(ns, field.Offset)
			if er != nil {
				return emit(m, er)
			}
			link, er := e.Objects.Field(mountType, "mnt_list")
			if er != nil {
				return emit(m, er)
			}
			err = e.Objects.WalkList(ctx, head, link.Offset, maxMounts, each)
		} else if errors.Is(er, object.ErrFieldAbsent) {
			field, er := e.Objects.Field("mnt_namespace", "mounts")
			if er != nil {
				return emit(m, er)
			}
			if mountType != "mount" || field.Type.Kind != "struct" || field.Type.Name != "rb_root" {
				return emit(m, fmt.Errorf("unsupported mount namespace tree"))
			}
			head, er := memory.Add(ns, field.Offset)
			if er != nil {
				return emit(m, er)
			}
			link, er := e.Objects.Field("mount", "mnt_node")
			if er != nil {
				return emit(m, er)
			}
			err = e.Objects.WalkRBTree(ctx, head, link.Offset, maxMounts, each)
		} else {
			return emit(m, er)
		}
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return emit(m, err)
		}
		return nil
	})
	if outputErr != nil {
		return outputErr
	}
	return err
}
