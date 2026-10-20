#!/usr/bin/env python3
"""Independent selected-corpus oracle: RAW, four-level x64, ELF64 little endian.

Walks raw physical page tables and parses ELF headers using Python struct/ISF
field offsets, without calling GoMem or importing Volatility. Verifies every
extracted byte and the logical-offset/source-address padding relationships.
This is a developer check, not a runtime dependency or format certification.
"""
import argparse
import collections
import functools
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import struct
import zipfile

from compare_extractions import digest, member

MASK64 = (1 << 64) - 1
PHYS = (1 << 52) - 1


class RawX64:
    def __init__(self, path, root):
        self.file = path.open('rb')
        self.root = root & PHYS & ~4095
        if not self.root:
            raise ValueError('zero page-table root')

    @functools.lru_cache(maxsize=8192)
    def entry(self, offset):
        data = os.pread(self.file.fileno(), 8, offset)
        if len(data) != 8:
            raise ValueError('uncaptured page-table entry')
        return struct.unpack('<Q', data)[0]

    def translate(self, address):
        if not 0 <= address <= MASK64 or address >> 48 != (0xffff if address & (1 << 47) else 0):
            raise ValueError('noncanonical x64 address')
        table = self.root
        for shift in (39, 30, 21, 12):
            entry = self.entry(table + ((address >> shift) & 511) * 8)
            if not entry & 1:
                raise ValueError('nonpresent Linux page')
            if shift in (30, 21) and entry & 128:
                return (entry & PHYS & ~((1 << shift) - 1)) + (address & ((1 << shift) - 1))
            table = entry & PHYS & ~4095
        return table + (address & 4095)

    def read(self, address, length, pad=False):
        if length < 0 or length > 16 << 20 or address < 0 or length and length - 1 > MASK64 - address:
            raise ValueError('invalid oracle read range')
        out, gaps = bytearray(), []
        while len(out) < length:
            start = address + len(out)
            n = min(4096 - (start & 4095), length - len(out))
            try:
                physical = self.translate(start)
                data = os.pread(self.file.fileno(), n, physical)
                if len(data) != n and not pad:
                    raise ValueError('uncaptured physical data')
            except ValueError:
                if not pad:
                    raise
                data = b''
            out.extend(data)
            if len(data) < n:
                gaps.append((len(out), start + len(data), n - len(data)))
                out.extend(bytes(n - len(data)))
        return bytes(out), gaps

    def uint(self, address):
        return struct.unpack('<Q', self.read(address, 8)[0])[0]

    def close(self):
        self.entry.cache_clear()
        self.file.close()


def load_isf(spec):
    path, sep, entry = spec.partition('#')
    if sep:
        with zipfile.ZipFile(path) as archive:
            data = archive.read(entry)
        suffix = entry
    else:
        data, suffix = Path(path).read_bytes(), path
    if suffix.endswith('.xz'):
        data = lzma.decompress(data)
    elif suffix.endswith('.gz'):
        data = gzip.decompress(data)
    return json.loads(data), hashlib.sha256(data).hexdigest()


def expected_plan(space, base, layout):
    header = space.read(base, 64)[0]
    if header[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('oracle requires captured ELF64 little endian headers')
    typ, machine, version, entry, phoff = struct.unpack_from('<HHIQQ', header, 16)
    ehsize, entsize, count = struct.unpack_from('<HHH', header, 52)
    if typ not in (2, 3) or version != 1 or ehsize != 64 or entsize != 56 or not 0 < count <= 4096 or not 64 <= phoff <= 16 << 20:
        raise ValueError('invalid oracle ELF header bounds')
    table = space.read(base + phoff, count * 56)[0]
    loads = []
    for i in range(count):
        pt, flags, off, va, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', table, i * 56)
        if pt == 1:
            loads.append((i, flags, off, va, filesz, memsz, align))
    anchors = [s[3] for s in loads if s[2] == 0 and s[4] >= 64 and s[3] % 4096 == 0]
    if layout not in ('mapped', 'reference') or layout == 'mapped' and (len(anchors) != 1 or typ == 2 and anchors[0] != base):
        raise ValueError('unresolved oracle ELF load address')
    sections = {}
    for i, flags, off, va, filesz, memsz, align in loads:
        if filesz > memsz or va + memsz > MASK64 or off + filesz > MASK64 or align > 1 and (align & (align - 1) or off % align != va % align):
            raise ValueError('invalid oracle load interval')
        if not memsz and layout == 'mapped':
            continue
        start, end = va // 4096 * 4096, (va + memsz + 4095) // 4096 * 4096
        size = end - start
        if not size:
            continue
        source = base + start if layout == 'reference' else base + start - anchors[0]
        if source < 0 or source + size - 1 > MASK64 or size > (1 << 32) - 1:
            raise ValueError('oracle source address cannot be represented in uint64')
        sections[start] = dict(program_header=str(i), source=hex(source), length=hex(size), p_offset=hex(off), p_vaddr=hex(va), p_filesz=hex(filesz), p_memsz=hex(memsz), p_align=hex(align), p_flags=hex(flags))
    offset = 0
    spans = []
    for _, span in sorted(sections.items()):
        span['output_offset'] = hex(offset)
        offset += int(span['length'], 16)
        spans.append(span)
    if not offset or offset > (1 << 32) - 1:
        raise ValueError('oracle extraction is empty or too large')
    return dict(layout=layout, format='page-rounded-PT_LOAD-concatenation', base=hex(base), **{'class': '2'}, byte_order='little', type=str(typ), machine=str(machine), entry=hex(entry), size=hex(offset), segments=spans, headers_rewritten=False)


def verify(native, case, image, isf, kernel_dtb):
    table, symbols_hash = load_isf(isf)
    mm_offset = table['user_types']['task_struct']['fields']['mm']['offset']
    pgd_offset = table['user_types']['mm_struct']['fields']['pgd']['offset']
    image_hash = digest(image)
    kernel = RawX64(image, kernel_dtb)
    results, skipped = [], collections.Counter()
    builds = set()
    try:
        for line in native.read_text().splitlines():
            row = json.loads(line)
            c = row['cells']
            if c['FileOutput']['kind'] != 'artifact':
                skipped[c['FileOutput'].get('reason', 'non-artifact')] += 1
                continue
            artifact = c['FileOutput']['value']
            proof = row['provenance']
            if proof['image_sha256'] != image_hash or proof['symbols_sha256'] != symbols_hash:
                raise ValueError('oracle source image/symbols differ from row provenance')
            builds.add(proof['engine_build'])
            task = int(c['Offset' if proof['plugin'] == 'linux.pslist' else 'ProcessOffset']['value'], 16)
            mm = kernel.uint(task + mm_offset)
            pgd = kernel.uint(mm + pgd_offset)
            space = RawX64(image, kernel.translate(pgd))
            try:
                meta = c['ELF']['value']
                plan = expected_plan(space, int(meta['base'], 16), meta['layout'])
                if plan != meta:
                    raise ValueError('independently parsed ELF load plan differs')
                if artifact['state'] not in ('completed', 'completed_with_gaps') or int(artifact['size']) != int(plan['size'], 16):
                    raise ValueError('incomplete artifact')
                file = member(case, artifact['path'])
                if digest(file) != artifact['sha256']:
                    raise ValueError('artifact digest changed')
                missing, gaps, logical = 0, [], 0
                with file.open('rb') as captured:
                    for span in plan['segments']:
                        start, size = int(span['source'], 16), int(span['length'], 16)
                        offset = 0
                        while offset < size:
                            length = min(4096, size - offset)
                            data, absent = space.read(start + offset, length, pad=True)
                            if captured.read(length) != data:
                                raise ValueError('artifact bytes differ from independent raw page-table reads')
                            for relative, address, count in absent:
                                gaps.append((hex(logical + offset + relative), hex(address), str(count)))
                                missing += count
                            offset += length
                        logical += size
                    if captured.read(1):
                        raise ValueError('unexpected artifact suffix')
                actual = [json.loads(s) for s in member(case, artifact['gaps_path']).read_text().splitlines()]
                if [(g['offset'], g['address'], g['length']) for g in actual] != gaps or any(g['layer'] != artifact['provenance']['layer'] for g in actual) or missing != int(artifact['missing_bytes']):
                    raise ValueError('padding source/output relationship differs')
                results.append(dict(name=artifact['name'], elf_type=plan['type'], layout=plan['layout'], base=plan['base'], bytes_verified=str(logical), missing_bytes=str(missing), segments=len(plan['segments']), sha256=artifact['sha256'], process_root=hex(space.root)))
            finally:
                space.close()
    finally:
        kernel.close()
    if not results or len(builds) != 1 or digest(image) != image_hash:
        raise ValueError('empty check, mixed builds or source image changed')
    return dict(verified=True, scope='selected ELF64 extractions from RAW four-level x64 only; no full capability acceptance', image_sha256=image_hash, symbols_sha256=symbols_hash, engine_build_sha256=next(iter(builds)), results=results, skipped=dict(skipped))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'case', 'image'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--isf', required=True)
    parser.add_argument('--kernel-dtb', type=lambda s: int(s, 0), required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.native, args.case, args.image, args.isf, args.kernel_dtb), indent=2))


if __name__ == '__main__':
    main()
