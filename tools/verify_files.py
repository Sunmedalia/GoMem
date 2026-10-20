#!/usr/bin/env python3
"""Independent selected RAW/x64 filesystem oracle (legacy list layouts only).

Re-enumerates tasks, mount namespaces, superblocks and all positive/negative
cached dentries from ISF offsets and raw page tables. Verifies path coordinates,
inode identity, metadata, exact timestamps and coverage. Does not import GoMem
or Volatility, or infer disk/namespace visibility from a cached superblock tree.
"""
import argparse
import base64
import collections
import json
from pathlib import Path
import stat

from compare_extractions import digest
from verify_elf_extractions import RawX64, load_isf
from verify_lsof import resolve_field, decode_time


def verify(native, image, isf, dtb):
    table, symbol_hash = load_isf(isf)
    rows = [json.loads(s) for s in native.read_text().splitlines()]
    if not rows or 'mount' in table['user_types'] or table['base_types']['pointer']['size'] != 8:
        raise ValueError('oracle requires nonempty legacy RAW/x64 output')
    image_hash = digest(image)
    if len({r['provenance']['engine_build'] for r in rows}) != 1 or any(r['provenance']['plugin'] != 'linux.files' or r['provenance']['image_sha256'] != image_hash or r['provenance']['symbols_sha256'] != symbol_hash for r in rows):
        raise ValueError('mixed image/symbol/build/plugin identity')
    if any(r['provenance']['parameters']['find'] or r['provenance']['parameters']['type'] for r in rows):
        raise ValueError('oracle requires the complete unfiltered inode census')
    space = RawX64(image, dtb)
    try:
        def field(typ, path):
            offset = 0
            for part in path.split('.'):
                f = resolve_field(table, typ, part)
                offset += f['offset']
                typ = f['type'].get('name')
            return dict(f, offset=offset)

        def scalar(address, typ, path, signed=False):
            f = field(typ, path)
            ref = f['type']
            width = 8 if ref['kind'] == 'pointer' else table['base_types'][ref['name']]['size']
            return int.from_bytes(space.read(address + f['offset'], width)[0], 'little', signed=signed)

        def walk_list(head, offset):
            node, previous, seen = space.uint(head), head, set()
            while node != head:
                if not node or node < offset or node in seen or len(seen) >= 1000000:
                    raise ValueError('invalid intrusive list')
                seen.add(node)
                if space.uint(node + 8) != previous:
                    raise ValueError('broken intrusive back link')
                yield node - offset
                previous, node = node, space.uint(node)
            if space.uint(head + 8) != previous:
                raise ValueError('broken intrusive list tail')

        def name(dentry):
            length = scalar(dentry, 'dentry', 'd_name.len')
            pointer = scalar(dentry, 'dentry', 'd_name.name')
            if not 0 < length <= 4096:
                raise ValueError('invalid qstr length')
            raw = space.read(pointer, length)[0]
            if b'\0' in raw or b'/' in raw or raw in (b'.', b'..'):
                raise ValueError('invalid path component')
            return raw

        def mount_path(root_dentry, root_mount, dentry, mount):
            seen, parts = set(), []
            for _ in range(256):
                if (dentry, mount) == (root_dentry, root_mount):
                    return b'/' + b'/'.join(reversed(parts)), 'process_root'
                if not dentry or not mount or (dentry, mount) in seen:
                    raise ValueError('invalid mount path')
                seen.add((dentry, mount))
                if dentry == scalar(mount, 'vfsmount', 'mnt_root'):
                    parent = scalar(mount, 'vfsmount', 'mnt_parent')
                    if parent == mount:
                        return b'/' + b'/'.join(reversed(parts)), 'global_root'
                    dentry = scalar(mount, 'vfsmount', 'mnt_mountpoint')
                    mount = parent
                else:
                    parent = scalar(dentry, 'dentry', 'd_parent')
                    if parent == dentry:
                        raise ValueError('disconnected mount path')
                    parts.append(name(dentry))
                    dentry = parent
            raise ValueError('mount path depth exceeds bound')

        init = table['symbols']['init_task']['address']
        task_link = field('task_struct', 'tasks')['offset']
        seen_namespaces, seen_mounts, seen_sb, seen_dentries = set(), set(), set(), set()
        first_inodes, expected = {}, {}
        negative = 0
        for task in walk_list(init + task_link, task_link):
            fs, proxy = (scalar(task, 'task_struct', n) for n in ('fs', 'nsproxy'))
            if not fs or not proxy:
                continue
            ns = scalar(proxy, 'nsproxy', 'mnt_ns')
            if not ns or ns in seen_namespaces:
                continue
            seen_namespaces.add(ns)
            root_dentry, root_mount = scalar(fs, 'fs_struct', 'root.dentry'), scalar(fs, 'fs_struct', 'root.mnt')
            mount_link = field('vfsmount', 'mnt_list')['offset']
            for mount in walk_list(ns + field('mnt_namespace', 'list')['offset'], mount_link):
                if mount in seen_mounts:
                    continue
                seen_mounts.add(mount)
                if scalar(mount, 'vfsmount', 'mnt_ns') != ns:
                    raise ValueError('mount namespace owner differs')
                mounted_root, sb = scalar(mount, 'vfsmount', 'mnt_root'), scalar(mount, 'vfsmount', 'mnt_sb')
                mountpoint, scope = mount_path(root_dentry, root_mount, mounted_root, mount)
                mounted_inode = scalar(mounted_root, 'dentry', 'd_inode')
                mounted_links = scalar(mounted_inode, 'inode', 'i_nlink')
                attachment=scalar(mount,'vfsmount','mnt_mountpoint')
                attachment_inode=scalar(attachment,'dentry','d_inode')
                attachment_links=scalar(attachment_inode,'inode','i_nlink')
                if sb in seen_sb:
                    continue
                seen_sb.add(sb)
                root = scalar(sb, 'super_block', 's_root')
                if scalar(root, 'dentry', 'd_parent') != root:
                    raise ValueError('superblock root is not self-parented')
                # Explicit DFS stack, with children pushed in reverse captured
                # order. This oracle does not call the native recursive walker.
                pending = [(root, root, mountpoint, 0)]
                while pending:
                    dentry, parent, path, depth = pending.pop()
                    if dentry in seen_dentries or len(seen_dentries) >= 1000000 or depth > 256:
                        raise ValueError('repeated/excessive filesystem traversal')
                    seen_dentries.add(dentry)
                    if scalar(dentry, 'dentry', 'd_parent') != parent:
                        raise ValueError('directory parent differs')
                    inode = scalar(dentry, 'dentry', 'd_inode')
                    if not inode:
                        negative += 1
                        continue
                    if depth:
                        path = path.rstrip(b'/') + b'/' + name(dentry)
                    ino = scalar(inode, 'inode', 'i_ino')
                    count = scalar(inode, 'inode', 'i_count.counter', signed=True)
                    if not ino or count < 0 or scalar(inode, 'inode', 'i_sb') != sb:
                        raise ValueError('invalid inode ownership/reference')
                    mode, size = scalar(inode, 'inode', 'i_mode'), scalar(inode, 'inode', 'i_size', signed=True)
                    types = {0o010000: 'FIFO', 0o020000: 'CHR', 0o040000: 'DIR', 0o060000: 'BLK', 0o100000: 'REG', 0o120000: 'LNK', 0o140000: 'SOCK'}
                    kind = types.get(mode & 0o170000)
                    if kind is None or size < 0:
                        raise ValueError('unsupported inode metadata')
                    mapping = scalar(inode, 'inode', 'i_mapping')
                    dev, links = scalar(sb, 'super_block', 's_dev'), scalar(inode, 'inode', 'i_nlink')
                    record = 'alias' if inode in first_inodes else 'file'
                    first = first_inodes.setdefault(inode, dentry)
                    values = dict(FilePath=path.decode('utf8'), MountPoint=mountpoint.decode('utf8'), PathRaw=path, MountPointRaw=mountpoint,
                        RecordType=record, SuperblockAddr=sb, SuperblockRoot=root, InodeAddr=inode, InodeNum=ino, FileType=kind,
                        FileMode=stat.filemode(mode), ModeRaw=mode, InodeSize=size, InodePages=(size + 4095) // 4096,
                        CachedPages=scalar(mapping, 'address_space', 'nrpages'), Mapping=mapping, Device=f'{dev >> 20}:{dev & 0xfffff}',
                        Nlink=links, Deleted=links == 0, Depth=depth, Dentry=dentry, ParentDentry=parent, TaskOffset=task,
                        Namespace=ns, Mount=mount, MountRoot=mounted_root, MountID=scalar(mount, 'vfsmount', 'mnt_id'),
                        PID=scalar(task, 'task_struct', 'pid'), MountScope=scope, PathScope='superblock_tree_at_first_mount',
                        MountRootInode=mounted_inode, MountRootNlink=mounted_links, MountRootDeleted=mounted_links == 0,
                        MountAttachment=attachment,MountAttachmentInode=attachment_inode,MountAttachmentNlink=attachment_links,MountAttachmentDeleted=attachment_links==0)
                    if record == 'alias':
                        values['FirstDentry'] = first
                    clocks = {}
                    for column, member in [('AccessTime', 'i_atime'), ('ModificationTime', 'i_mtime'), ('ChangeTime', 'i_ctime')]:
                        sec = scalar(inode, 'inode', member + '.tv_sec', signed=True)
                        ns_part = scalar(inode, 'inode', member + '.tv_nsec')
                        values[column] = decode_time(sec, ns_part)
                        clocks[column] = (sec, ns_part)
                    expected[dentry] = (values, clocks)
                    if kind == 'DIR':
                        head = dentry + field('dentry', 'd_subdirs')['offset']
                        link = field('dentry', 'd_u.d_child')['offset']
                        children = list(walk_list(head, link))
                        pending.extend((child, dentry, path, depth + 1) for child in reversed(children))
        matched, stamps, deleted_mount_paths = set(), 0, 0
        for row in rows:
            c = row['cells']
            if c['RecordType']['value'] == 'summary':
                continue
            address = int(c['Dentry']['value'], 16)
            if address in matched or address not in expected or c['Error'].get('error'):
                raise ValueError('filesystem entity/diagnostic set differs')
            matched.add(address)
            values, clocks = expected[address]
            for key, want in values.items():
                cell = c[key]
                if isinstance(want, bool):
                    actual = cell.get('value')
                elif isinstance(want, bytes):
                    actual = base64.b64decode(cell['value'], validate=True)
                elif isinstance(want, int):
                    actual = int(cell['value'], 16 if cell['kind'] == 'address' else 10)
                else:
                    actual = cell.get('value')
                if actual != want:
                    raise ValueError('independent filesystem field differs: ' + key)
            for key, (sec, ns_part) in clocks.items():
                raw = c[key + 'Raw']['value']
                if raw['seconds'] != str(sec) or raw['nanoseconds'] != str(ns_part):
                    raise ValueError('raw inode timestamp differs')
                stamps += 1
            deleted_mount_paths += values['MountAttachmentDeleted']
        summaries = [r for r in rows if r['cells']['RecordType']['value'] == 'summary']
        if matched != expected.keys() or len(summaries) != 1:
            raise ValueError('incomplete filesystem census')
        proof = summaries[0]['cells']['Coverage']['value']
        counts = dict(superblocks=len(seen_sb), mount_records=len(seen_mounts), dentry_visits=len(seen_dentries), negative_dentries=negative, unique_inodes=len(first_inodes), aliases=len(expected) - len(first_inodes))
        if any(proof[k] != str(v) for k, v in counts.items()) or proof['traversal_complete'] is not True or summaries[0]['cells']['Error'].get('error'):
            raise ValueError('filesystem coverage differs')
        return dict(verified=True, scope='Selected legacy RAW/x64 list namespaces and dentry trees only', counts=counts, namespaces=len(seen_namespaces), exact_timestamps=stamps, deleted_attachment_path_entities=deleted_mount_paths, type_counts=dict(collections.Counter(v[0]['FileType'] for v in expected.values())), image_sha256=image_hash, symbols_sha256=symbol_hash, engine_build_sha256=rows[0]['provenance']['engine_build'])
    finally:
        space.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native', type=Path, required=True)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--symbols', required=True)
    p.add_argument('--dtb', type=lambda v: int(v, 0), required=True)
    a = p.parse_args()
    print(json.dumps(verify(a.native, a.image, a.symbols, a.dtb), indent=2))


if __name__ == '__main__':
    main()
