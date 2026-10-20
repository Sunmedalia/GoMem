package plugins

import (
	"bytes"
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

func linuxMember(ctx context.Context, e plugin.Environment, address uint64, typ string, paths ...string) (uint64, error) {
	for _, path := range paths {
		if _, err := e.Objects.Field(typ, path); err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				continue
			}
			return 0, err
		}
		return e.Objects.Uint(ctx, address, typ, path)
	}
	return 0, fmt.Errorf("%w: %s members %v", object.ErrFieldAbsent, typ, paths)
}

func linuxDentryName(ctx context.Context, e plugin.Environment, dentry uint64) ([]byte, error) {
	n, err := e.Objects.Uint(ctx, dentry, "dentry", "d_name.len")
	if errors.Is(err, object.ErrFieldAbsent) {
		combined, er := e.Objects.Uint(ctx, dentry, "dentry", "d_name.hash_len")
		err = er
		n = combined >> 32
	}
	if err != nil {
		return nil, err
	}
	if n == 0 || n > 4096 {
		return nil, fmt.Errorf("invalid dentry name length %d", n)
	}
	pointer, err := e.Objects.Uint(ctx, dentry, "dentry", "d_name.name")
	if err != nil {
		return nil, err
	}
	name, err := memory.Read(ctx, e.Kernel, pointer, int(n))
	if err != nil {
		return nil, err
	}
	if bytes.IndexByte(name, 0) >= 0 {
		return nil, fmt.Errorf("NUL in length-delimited dentry name")
	}
	return name, nil
}

func linuxProcessRoot(ctx context.Context, e plugin.Environment, task uint64) (uint64, uint64, error) {
	fs, err := e.Objects.Uint(ctx, task, "task_struct", "fs")
	if err != nil {
		return 0, 0, err
	}
	if fs == 0 {
		return 0, 0, fmt.Errorf("task has no filesystem root")
	}
	root, err := e.Objects.Field("fs_struct", "root")
	if err != nil {
		return 0, 0, err
	}
	dentryField, mountField := "root.dentry", "root.mnt"
	if root.Type.Kind == "pointer" {
		dentryField, mountField = "root", "rootmnt"
	}
	dentry, err := e.Objects.Uint(ctx, fs, "fs_struct", dentryField)
	if err != nil {
		return 0, 0, err
	}
	mount, err := e.Objects.Uint(ctx, fs, "fs_struct", mountField)
	if err != nil {
		return 0, 0, err
	}
	if dentry == 0 || mount == 0 {
		return 0, 0, fmt.Errorf("null process root dentry/mount")
	}
	if _, err = e.Objects.Uint(ctx, dentry, "dentry", "d_parent"); err != nil {
		return 0, 0, err
	}
	if _, err = e.Objects.Uint(ctx, mount, "vfsmount", "mnt_root"); err != nil {
		return 0, 0, err
	}
	return dentry, mount, nil
}

func linuxMountParent(ctx context.Context, e plugin.Environment, mount uint64) (parent, point uint64, err error) {
	if _, err = e.Objects.Field("vfsmount", "mnt_parent"); err == nil {
		parent, err = e.Objects.Uint(ctx, mount, "vfsmount", "mnt_parent")
		if err == nil {
			point, err = e.Objects.Uint(ctx, mount, "vfsmount", "mnt_mountpoint")
		}
		return
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return
	}
	f, er := e.Objects.Field("mount", "mnt")
	if er != nil {
		err = er
		return
	}
	if mount < f.Offset {
		err = fmt.Errorf("mount container underflow")
		return
	}
	container := mount - f.Offset
	p, er := e.Objects.Uint(ctx, container, "mount", "mnt_parent")
	if er != nil {
		err = er
		return
	}
	point, err = e.Objects.Uint(ctx, container, "mount", "mnt_mountpoint")
	if err == nil {
		parent, err = memory.Add(p, f.Offset)
	}
	return
}

// Reconstruct within the process filesystem root, crossing both pre-3.3 and
// embedded modern mount layouts. A disconnected/cyclic path remains an error.
func linuxFilePath(ctx context.Context, e plugin.Environment, task, file, dentry uint64, scope *string) ([]byte, error) {
	// Dynamic dentry names are kernel functions, not strings. Resolve only
	// known functions; never call target code or guess an unknown callback.
	op, err := e.Objects.Uint(ctx, dentry, "dentry", "d_op")
	if err != nil {
		return nil, err
	}
	if op != 0 {
		callback, err := e.Objects.Uint(ctx, op, "dentry_operations", "d_dname")
		if err != nil {
			return nil, err
		}
		if callback != 0 {
			for _, handler := range []string{"simple_dname", "sockfs_dname", "pipefs_dname", "anon_inodefs_dname"} {
				address, err := e.Symbol(handler)
				if err != nil || address != callback {
					continue
				}
				*scope = "dynamic_name"
				if handler == "simple_dname" {
					name, err := linuxDentryName(ctx, e, dentry)
					if err != nil {
						return nil, err
					}
					return append([]byte{'/'}, name...), nil
				}
				inode, err := e.Objects.Uint(ctx, dentry, "dentry", "d_inode")
				if err != nil {
					return nil, err
				}
				number, err := e.Objects.Uint(ctx, inode, "inode", "i_ino")
				if err != nil {
					return nil, err
				}
				prefix := map[string]string{"sockfs_dname": "socket", "pipefs_dname": "pipe", "anon_inodefs_dname": "anon_inode"}[handler]
				return []byte(prefix + ":[" + strconv.FormatUint(number, 10) + "]"), nil
			}
			return nil, fmt.Errorf("unsupported dynamic dentry callback %#x", callback)
		}
	}
	rootDentry, rootMount, err := linuxProcessRoot(ctx, e, task)
	if err != nil {
		return nil, err
	}
	mount, err := linuxMember(ctx, e, file, "file", "f_path.mnt", "f_vfsmnt")
	if err != nil {
		return nil, err
	}
	seen := map[[2]uint64]bool{}
	var components [][]byte
	for depth := 0; depth < 256; depth++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if dentry == rootDentry && mount == rootMount {
			var path []byte
			for i := len(components) - 1; i >= 0; i-- {
				path = append(path, '/')
				path = append(path, components[i]...)
			}
			if len(path) == 0 {
				path = []byte{'/'}
			}
			return path, nil
		}
		key := [2]uint64{dentry, mount}
		if dentry == 0 || mount == 0 || seen[key] {
			return nil, fmt.Errorf("null/cyclic filesystem path at %#x/%#x", dentry, mount)
		}
		seen[key] = true
		parent, err := e.Objects.Uint(ctx, dentry, "dentry", "d_parent")
		if err != nil {
			return nil, err
		}
		mountRoot, err := e.Objects.Uint(ctx, mount, "vfsmount", "mnt_root")
		if err != nil {
			return nil, err
		}
		if dentry == mountRoot {
			p, point, err := linuxMountParent(ctx, e, mount)
			if err != nil {
				return nil, err
			}
			if p == mount {
				*scope = "global_root"
				var path []byte
				for i := len(components) - 1; i >= 0; i-- {
					path = append(path, '/')
					path = append(path, components[i]...)
				}
				if len(path) == 0 {
					path = []byte{'/'}
				}
				return path, nil
			}
			dentry, mount = point, p
			continue
		}
		if dentry == parent {
			return nil, fmt.Errorf("disconnected dentry outside mount root")
		}
		name, err := linuxDentryName(ctx, e, dentry)
		if err != nil {
			return nil, err
		}
		if bytes.IndexByte(name, '/') >= 0 {
			if len(components) != 0 {
				return nil, fmt.Errorf("slash inside ancestor dentry component")
			}
			*scope = "dentry_label"
			return append([]byte{'/'}, bytes.Trim(name, "/")...), nil
		}
		components = append(components, name)
		total := len(components)
		for _, c := range components {
			total += len(c)
		}
		if total > 16384 {
			return nil, fmt.Errorf("filesystem path exceeds 16KiB bound")
		}
		dentry = parent
	}
	return nil, fmt.Errorf("filesystem path depth exceeds 256")
}

func linuxAnonymousName(ctx context.Context, e plugin.Environment, mm, start, end uint64) ([]byte, error) {
	brkStart, err := e.Objects.Uint(ctx, mm, "mm_struct", "start_brk")
	if err != nil {
		return nil, err
	}
	brkEnd, err := e.Objects.Uint(ctx, mm, "mm_struct", "brk")
	if err != nil {
		return nil, err
	}
	if start <= brkStart && end >= brkEnd {
		return []byte("[heap]"), nil
	}
	stack, err := e.Objects.Uint(ctx, mm, "mm_struct", "start_stack")
	if err != nil {
		return nil, err
	}
	if start <= stack && stack <= end {
		return []byte("[stack]"), nil
	}
	if _, err := e.Objects.Field("mm_struct", "context.vdso"); err == nil {
		vdso, err := e.Objects.Uint(ctx, mm, "mm_struct", "context.vdso")
		if err != nil {
			return nil, err
		}
		if start == vdso {
			return []byte("[vdso]"), nil
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return nil, err
	}
	return []byte("Anonymous Mapping"), nil
}

func linuxVMAFile(ctx context.Context, e plugin.Environment, task, mm, start, end, file uint64) (path, raw, deleted, inode, major, minor, inodeSize, scope evidence.Value) {
	inode, major, minor = evidence.Number(0), evidence.Number(0), evidence.Number(0)
	deleted = evidence.Text("false")
	inodeSize = evidence.Integer(0)
	pathScope := "process_root"
	var name []byte
	var err error
	if file == 0 {
		pathScope = "anonymous_name"
		name, err = linuxAnonymousName(ctx, e, mm, start, end)
	} else {
		dentry, er := linuxMember(ctx, e, file, "file", "f_path.dentry", "f_dentry")
		err = er
		if err == nil && dentry == 0 {
			err = fmt.Errorf("file has a null dentry")
		}
		if err == nil {
			ip, er := e.Objects.Uint(ctx, dentry, "dentry", "d_inode")
			if er == nil && ip == 0 {
				er = fmt.Errorf("dentry has no inode")
			}
			if er != nil {
				inode = evidence.Missing("unreadable_or_unavailable", er)
				deleted = inode
				inodeSize = inode
				major = inode
				minor = inode
			} else {
				inode = optionalUint(ctx, e, ip, "inode", "i_ino", false)
				size, er := e.Objects.Int(ctx, ip, "inode", "i_size")
				if er != nil {
					inodeSize = evidence.Missing("unreadable_or_unavailable", er)
				} else {
					inodeSize = evidence.Integer(size)
				}
				links, er := linuxMember(ctx, e, ip, "inode", "i_nlink", "__i_nlink")
				if er != nil {
					deleted = evidence.Missing("unreadable_or_unavailable", er)
				} else {
					deleted = evidence.Text(strconv.FormatBool(links == 0))
				}
				sb, er := e.Objects.Uint(ctx, ip, "inode", "i_sb")
				if er != nil {
					major = evidence.Missing("unreadable_or_unavailable", er)
					minor = major
				} else {
					dev, er := e.Objects.Uint(ctx, sb, "super_block", "s_dev")
					if er != nil {
						major = evidence.Missing("unreadable_or_unavailable", er)
						minor = major
					} else {
						major = evidence.Number(dev >> 20)
						minor = evidence.Number(dev & 0xfffff)
					}
				}
			}
			name, err = linuxFilePath(ctx, e, task, file, dentry, &pathScope)
		} else {
			inode = evidence.Missing("unreadable_or_unavailable", err)
			major = inode
			minor = inode
			deleted = inode
			inodeSize = inode
		}
	}
	scope = evidence.Text(pathScope)
	if err != nil {
		path = evidence.Missing("unreadable_or_unavailable", err)
		raw = path
		return
	}
	raw = evidence.Bytes(name)
	text := strings.ToValidUTF8(string(name), "\ufffd")
	if deleted.String() == "true" {
		text += " (deleted)"
	}
	path = evidence.Text(text)
	return
}
