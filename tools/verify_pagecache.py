#!/usr/bin/env python3
"""Independent legacy RAW/x64 radix page-cache oracle, not a runtime dependency.

Uses Python struct/ISF offsets and an independent physical page-table walker.
Checks complete leaf sets, inode/page ownership, flags, PFNs, file bytes and
logical/physical gap coordinates. XArray/folios and modern memory models are
outside this selected-corpus oracle and must not be inferred as accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from compare_extractions import digest, member
from verify_elf_extractions import RawX64, load_isf
from verify_lsof import resolve_field


def page_physical(address, base, size, max_pfn):
    if size <= 0 or address < base or (address - base) % size:
        raise ValueError('misaligned struct page')
    pfn = (address - base) // size
    if not 0 <= pfn < max_pfn or pfn >= 1 << 52:
        raise ValueError('PFN outside memory model')
    return pfn * 4096


def reconstruct(pages, size, physical_read, logical_layer, physical_layer):
    if not 0 <= size <= 16 << 20:
        raise ValueError('selected oracle file size exceeds bound')
    output, gaps, position = bytearray(), [], 0
    for index, physical in sorted(pages):
        offset = index * 4096
        if index < 0 or offset < position or offset >= size:
            raise ValueError('invalid or repeated cache index')
        if position < offset:
            gaps.append((position, offset - position, position, logical_layer))
            output.extend(bytes(offset - position))
        n = min(4096, size - offset)
        data = physical_read(physical, n)
        if len(data) > n:
            raise ValueError('invalid physical read count')
        output.extend(data)
        if len(data) < n:
            gaps.append((offset + len(data), n - len(data), physical + len(data), physical_layer))
            output.extend(bytes(n - len(data)))
        position = offset + n
    if position < size:
        gaps.append((position, size - position, position, logical_layer))
        output.extend(bytes(size - position))
    return bytes(output), gaps


def verify(native, case, image, isf, dtb):
    table, symbols_hash = load_isf(isf)
    rows = [json.loads(line) for line in native.read_text().splitlines()]
    if not rows or len({r['provenance']['engine_build'] for r in rows}) != 1:
        raise ValueError('empty/mixed native output')
    image_hash = digest(image)
    if any(r['provenance']['image_sha256'] != image_hash or r['provenance']['symbols_sha256'] != symbols_hash or r['provenance']['plugin'] != 'linux.inodepages' for r in rows):
        raise ValueError('image/symbol/plugin identity differs')
    inode_set = {int(r['provenance']['parameters']['inode'], 0) for r in rows}
    if len(inode_set) != 1 or any(r['provenance']['parameters']['dump'] != 'true' for r in rows):
        raise ValueError('one dumped inode required')
    inode = inode_set.pop()
    if 'vmemmap_base' in table['symbols'] or 'mem_section' not in table['symbols'] or table['base_types']['pointer']['size'] != 8:
        raise ValueError('oracle supports legacy fixed-vmemmap x64 only')
    space = RawX64(image, dtb)
    try:
        def field(typ, name):
            return resolve_field(table, typ, name)

        def uint(address, typ, name):
            f = field(typ, name)
            ref = f['type']
            width = 8 if ref['kind'] == 'pointer' else table['base_types'][ref['name']]['size']
            return int.from_bytes(space.read(address + f['offset'], width)[0], 'little')

        size, mapping = uint(inode, 'inode', 'i_size'), uint(inode, 'inode', 'i_mapping')
        if uint(inode, 'inode', 'i_mode') & 0o170000 != 0o100000:
            raise ValueError('nonregular inode')
        root = mapping + field('address_space', 'page_tree')['offset']
        height, head = uint(root, 'radix_tree_root', 'height'), uint(root, 'radix_tree_root', 'rnode')
        slots = field('radix_tree_node', 'slots')
        count = slots['type']['count']
        if count not in (16, 64):
            raise ValueError('unsupported legacy radix chunk')
        seen, leaves = set(), {}

        def walk(pointer, level, index):
            if not pointer or pointer & 2 or not 0 <= level <= 11:
                raise ValueError('invalid legacy tree entry')
            if level == 0:
                if pointer & 7 or index in leaves:
                    raise ValueError('invalid/repeated page')
                leaves[index] = pointer
                return
            node = pointer & ~3
            if node in seen or len(seen) >= 4096:
                raise ValueError('cyclic/excessive tree')
            seen.add(node)
            if uint(node, 'radix_tree_node', 'height') != level:
                raise ValueError('node/root height differs')
            data = space.read(node + slots['offset'], count * 8)[0]
            for i in range(count):
                entry = int.from_bytes(data[i * 8:(i + 1) * 8], 'little')
                if entry:
                    walk(entry, level - 1, index + i * count ** (level - 1))

        if head:
            walk(head, height, 0)
        native_pages = [r for r in rows if r['cells']['RecordType']['value'] == 'page']
        summary = [r for r in rows if r['cells']['RecordType']['value'] == 'summary']
        if len(native_pages) != len(leaves) or len(summary) != 1 or len(rows) != len(leaves) + 1:
            raise ValueError('complete cache leaf set differs')
        max_pfn = space.uint(table['symbols']['max_pfn']['address'])
        page_size = table['user_types']['page']['size']
        page_flags = table['enums']['pageflags']['constants']
        recovered, checked_indices = [], set()
        for row in native_pages:
            c = row['cells']
            index = int(c['TreeIndex']['value'])
            address = int(c['PageVAddr']['value'], 16)
            if index in checked_indices or leaves.get(index) != address or c['Error'].get('error'):
                raise ValueError('cache page set/diagnostic differs')
            checked_indices.add(index)
            actual_index, actual_mapping, flags = (uint(address, 'page', n) for n in ('index', 'mapping', 'flags'))
            if actual_index != index or actual_mapping != mapping:
                raise ValueError('page index/mapping ownership differs')
            physical = page_physical(address, 0xffffea0000000000, page_size, max_pfn)
            names = ','.join(sorted(n[3:] for n, bit in page_flags.items() if n.startswith('PG_') and 0 <= bit < 64 and flags & (1 << bit)))
            expected = {'Index': str(index), 'Span': '1', 'FlagsRaw': str(flags), 'Flags': names, 'MappingAddr': f'0x{mapping:016x}', 'PagePAddr': f'0x{physical:016x}', 'DumpSafe': index * 4096 < size, 'Captured': len(os.pread(space.file.fileno(), 4096, physical)) == 4096}
            if any(c[k].get('value') != v for k, v in expected.items()):
                raise ValueError('independent raw page field differs')
            if expected['DumpSafe']:
                recovered.append((index, physical))
        c = summary[0]['cells']
        if c['Error'].get('error') or c['Size']['value'] != str(size) or c['CachedPages']['value'] != str(uint(mapping, 'address_space', 'nrpages')) or int(c['TreeNodes']['value']) != len(seen) or int(c['TreeEntries']['value']) != len(leaves):
            raise ValueError('summary coverage differs')
        artifact = c['FileOutput']['value']
        logical = f'file-cache:inode:0x{inode:x}'
        # The selected corpus has fully captured physical payloads; physical
        # gap reconstruction is separately unit tested without GoMem.
        expected_bytes, gaps = reconstruct(recovered, size, lambda a, n: os.pread(space.file.fileno(), n, a), logical, 'physical')
        file, log = member(case, artifact['path']), member(case, artifact['gaps_path'])
        if file.read_bytes() != expected_bytes or digest(file) != artifact['sha256'] or file.stat().st_size != int(artifact['size']):
            raise ValueError('recovered bytes/hash differ')
        if digest(log) != artifact['gaps_sha256'] or log.stat().st_size != int(artifact['gaps_size']):
            raise ValueError('padding log identity differs')
        actual_gaps = [json.loads(s) for s in log.read_text().splitlines()]
        coordinates = [(int(g['offset'], 16), int(g['length']), int(g['address'], 16), g['layer']) for g in actual_gaps]
        if coordinates != gaps or any(not g['error'] or 'uncached_page' not in g['error'] for g in actual_gaps):
            raise ValueError('logical gap provenance differs')
        missing = sum(g[1] for g in gaps)
        if artifact['missing_bytes'] != str(missing) or artifact['gap_count'] != str(len(gaps)) or artifact['expected_size'] != str(size) or artifact['state'] != ('completed_with_gaps' if gaps else 'completed'):
            raise ValueError('artifact coverage/state differs')
        if artifact['provenance']['layer'] != logical or artifact['provenance']['offset'] != '0x0':
            raise ValueError('file logical coordinate system differs')
        for key in ('image_sha256', 'symbols_sha256', 'engine_build', 'plugin', 'parameters'):
            if artifact['provenance'][key] != summary[0]['provenance'][key]:
                raise ValueError('artifact/row provenance differs')
        return dict(verified=True, scope='Selected legacy RAW/x64 fixed-vmemmap radix inode only', inode=hex(inode), pages=len(leaves), tree_nodes=len(seen), file_size=str(size), verified_file_bytes=str(size), uncached_bytes=str(missing), logical_gaps=len(gaps), sha256=artifact['sha256'], image_sha256=image_hash, symbols_sha256=symbols_hash, engine_build_sha256=rows[0]['provenance']['engine_build'])
    finally:
        space.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native', type=Path, required=True)
    p.add_argument('--case', type=Path, required=True)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--symbols', required=True)
    p.add_argument('--dtb', type=lambda v: int(v, 0), required=True)
    a = p.parse_args()
    print(json.dumps(verify(a.native, a.case, a.image, a.symbols, a.dtb), indent=2))


if __name__ == '__main__':
    main()
