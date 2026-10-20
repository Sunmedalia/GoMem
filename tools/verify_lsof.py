#!/usr/bin/env python3
"""Selected RAW/Linux x64 oracle for FD slots and inode metadata, not paths.

Reads the independently checked active task set, then re-enumerates raw FD slots
and decodes fields from ISF offsets using a separate Python x64 page walker.
Checks exact candidate sets, file extent, raw inode fields and UTC arithmetic.
It does not import Volatility or execute GoMem. Namespace path recovery remains
outside this oracle and is compared separately with the locked reference.
"""
import argparse
import base64
import datetime
import hashlib
import json
from pathlib import Path
import stat

from compare_extractions import digest
from verify_elf_extractions import RawX64, load_isf


def decode_time(seconds, nanos):
    if not -62135596800 <= seconds <= 253402300799 or not 0 <= nanos < 1000000000:
        raise ValueError('invalid inode timestamp')
    whole = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=seconds)
    fraction = '.' + f'{nanos:09}'.rstrip('0') if nanos else ''
    return f'{whole.year:04d}-{whole.month:02d}-{whole.day:02d}T{whole.hour:02d}:{whole.minute:02d}:{whole.second:02d}' + fraction + 'Z'


def resolve_field(table, typ, name, seen=()):
    if typ in seen or len(seen) >= 64:
        raise ValueError('cyclic or excessive anonymous type nesting')
    fields = table['user_types'][typ]['fields']
    if name in fields:
        return fields[name]
    found = []
    for candidate in fields.values():
        if candidate.get('anonymous') and candidate['type']['kind'] in ('struct', 'union'):
            try:
                child = resolve_field(table, candidate['type']['name'], name, seen + (typ,))
            except KeyError:
                continue
            found.append(dict(child, offset=candidate['offset'] + child['offset']))
    if len(found) > 1:
        raise ValueError('ambiguous anonymous inode field')
    if not found:
        raise KeyError(name)
    return found[0]


def verify(native, active, image, isf, kernel_dtb):
    table, symbols_hash = load_isf(isf)
    image_hash = digest(image)
    if table['base_types']['pointer']['size'] != 8:
        raise ValueError('oracle requires RAW little-endian x64')
    rows = [json.loads(line) for line in native.read_text().splitlines()]
    tasks = [json.loads(line) for line in active.read_text().splitlines()]
    all_rows = rows + tasks
    builds = {r['provenance']['engine_build'] for r in all_rows}
    if len(builds) != 1 or not rows or not tasks:
        raise ValueError('empty oracle or mixed engine builds')
    if any(r['provenance']['image_sha256'] != image_hash or r['provenance']['symbols_sha256'] != symbols_hash for r in all_rows):
        raise ValueError('image or symbol identity differs')
    space = RawX64(image, kernel_dtb)

    def field(typ, name):
        return resolve_field(table, typ, name)

    def scalar(address, typ, name, signed=False):
        f = field(typ, name)
        ref = f['type']
        width = 8 if ref['kind'] == 'pointer' else table['base_types'][ref['name']]['size']
        return int.from_bytes(space.read(address + f['offset'], width)[0], 'little', signed=signed)

    def value(c, key, expected):
        if isinstance(expected, bool):
            actual = c[key].get('value')
        elif isinstance(expected, int):
            actual = int(c[key]['value'], 16 if c[key]['kind'] == 'address' else 10)
        else:
            actual = c[key].get('value')
        if actual != expected:
            raise ValueError('independent inode/descriptor field differs: ' + key)

    expected, null_zero_with_open = {}, []
    try:
        for task in tasks:
            c = task['cells']
            if c['RecordType']['value'] not in ('task', 'thread') or task['provenance']['parameters']['threads'] != 'true':
                raise ValueError('oracle requires a complete active task/thread list')
            address = int(c['Offset']['value'], 16)
            files = scalar(address, 'task_struct', 'files')
            if not files:
                continue
            fdt = scalar(files, 'files_struct', 'fdt')
            if not fdt:
                raise ValueError('uncaptured descriptor table')
            count, slots = scalar(fdt, 'fdtable', 'max_fds'), scalar(fdt, 'fdtable', 'fd')
            if count > 500000 or count and not slots:
                raise ValueError('invalid descriptor table')
            first = space.uint(slots) if count else None
            present = []
            for index in range(count):
                pointer = space.uint(slots + index * 8)
                if not pointer:
                    continue
                key = (address, index)
                if key in expected:
                    raise ValueError('duplicate active task/FD')
                expected[key] = (pointer, files, slots, c)
                present.append(index)
            if count and first == 0 and present:
                null_zero_with_open.append(dict(task=hex(address), tid=c['TID']['value'], fd_table=hex(slots), max_fds=str(count), closed_fd_zero=True, open_fds=[str(i) for i in present]))
        found = {}
        raw_timestamps = zero_timestamps = 0
        for row in rows:
            c = row['cells']
            if c['RecordType']['value'] != 'file' or row['provenance']['plugin'] != 'linux.lsof':
                raise ValueError('oracle requires readable complete file entities')
            key = (int(c['TaskOffset']['value'], 16), int(c['FD']['value']))
            if key not in expected or key in found:
                raise ValueError('unexpected or duplicate FD evidence')
            pointer, files, slots, task_cells = expected[key]
            found[key] = True
            for name, number in dict(Offset=pointer, Files=files, FDTable=slots, Slot=slots + key[1] * 8).items():
                value(c, name, number)
            for name in ('PID', 'TID'):
                value(c, name, int(task_cells[name]['value']))
            value(c, 'ProcessIdentity', task_cells['Identity']['value'])
            value(c, 'TaskIdentity', task_cells['TaskIdentity']['value'])
            extent = table['user_types']['file']['size']
            space.read(pointer, extent)
            value(c, 'FileExtent', dict(size=str(extent), readable=True))
            dentry = scalar(pointer + field('file', 'f_path')['offset'], 'path', 'dentry')
            inode = scalar(dentry, 'dentry', 'd_inode')
            value(c, 'Dentry', dentry)
            value(c, 'InodeOffset', inode)
            value(c, 'InodeSource', 'dentry.d_inode')
            mode = scalar(inode, 'inode', 'i_mode')
            value(c, 'ModeRaw', mode)
            value(c, 'Mode', stat.filemode(mode))
            link_field = 'i_nlink'
            try:
                field('inode', link_field)
            except KeyError:
                link_field = '__i_nlink'
            for col, member in (('Inode', 'i_ino'), ('Nlink', link_field)):
                value(c, col, scalar(inode, 'inode', member))
            value(c, 'Size', scalar(inode, 'inode', 'i_size', signed=True))
            sb = scalar(inode, 'inode', 'i_sb')
            dev = scalar(sb, 'super_block', 's_dev')
            value(c, 'Superblock', sb)
            value(c, 'Device', f'{dev >> 20}:{dev & 0xfffff}')
            value(c, 'Deleted', scalar(inode, 'inode', link_field) == 0)
            for col, member in (('Changed', 'i_ctime'), ('Modified', 'i_mtime'), ('Accessed', 'i_atime')):
                f = field('inode', member)
                at = inode + f['offset']
                seconds = scalar(at, f['type']['name'], 'tv_sec', signed=True)
                nanos = scalar(at, f['type']['name'], 'tv_nsec')
                value(c, col, decode_time(seconds, nanos))
                value(c, col + 'Raw', dict(seconds=str(seconds), nanoseconds=str(nanos), seconds_field=member + '.tv_sec', nanoseconds_field=member + '.tv_nsec'))
                raw_timestamps += 1
                zero_timestamps += seconds == 0 and nanos == 0
        if set(found) != set(expected):
            raise ValueError('native FD set omits raw captured slots')
        if digest(image) != image_hash:
            raise ValueError('source image changed')
        return dict(verified=True, scope='selected RAW legacy Linux/x64 FD sets and inode metadata only; paths and modern layouts excluded', engine_build_sha256=next(iter(builds)), image_sha256=image_hash, symbols_sha256=symbols_hash, active_tasks=len(tasks), descriptors=len(found), timestamp_fields_verified=raw_timestamps, zero_timestamps_preserved=zero_timestamps, closed_fd_zero_with_later_open_slots=null_zero_with_open)
    finally:
        space.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'active', 'image'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--isf', required=True)
    p.add_argument('--kernel-dtb', required=True, type=lambda s: int(s, 0))
    args = p.parse_args()
    print(json.dumps(verify(args.native, args.active, args.image, args.isf, args.kernel_dtb), indent=2))


if __name__ == '__main__':
    main()
