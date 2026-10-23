#!/usr/bin/env python3
"""Run original linked Shimcache entry predicates on all ten non-XP layouts."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_shimcache_resource_oracle import kernel_layout

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winshimcache/testdata/entry-oracle.json'
SCENARIOS = ['normal', 'same-links', 'null-forward', 'null-backward', 'null-both',
             'backward-target-hole', 'forward-container-hole', 'forward-member-hole',
             'forward-field-hole', 'backward-field-hole', 'zero-backlink',
             'wrong-backlink', 'self-forward', 'self-backward', 'entry-zero',
             'masked-forward', 'masked-backlink', 'masked-zero-forward']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols import native
    from volatility3.framework.symbols.windows.extensions import shimcache
    cases = []
    with tempfile.TemporaryDirectory() as temporary:
        for path in sorted((source / 'volatility3/framework/symbols/windows/shimcache').glob('*.json')):
            doc = json.loads(path.read_text())
            entry = doc['user_types']['SHIM_CACHE_ENTRY']
            if 'ListEntry' not in entry['fields']:
                continue
            width = doc['base_types']['pointer']['size']
            kernel_path = Path(temporary) / 'kernel.json'
            kernel = kernel_layout(width, 0)
            kernel_path.write_text(json.dumps(kernel))
            for mask in ([0xffffffff] if width == 4 else [0xffffffffffff, 0xffffffffffffffff]):
                for scenario in SCENARIOS:
                    data, holes, reads = bytearray(0x10000), [], []
                    at = 0 if scenario == 'entry-zero' else 0x1000
                    member = at + entry['fields']['ListEntry']['offset']
                    flink, blink, backlink = 0x2000, 0x3000, 0x1000
                    high = 1 << (width * 8 - 1)
                    if scenario == 'same-links':
                        blink = flink
                    if scenario in ('null-forward', 'null-both'):
                        flink = 0
                    if scenario in ('null-backward', 'null-both'):
                        blink = 0
                    if scenario == 'self-forward':
                        flink = member
                    if scenario == 'self-backward':
                        blink = member
                    if scenario == 'masked-forward':
                        flink |= high
                    if scenario == 'masked-zero-forward':
                        flink = high
                    if scenario == 'masked-backlink':
                        backlink |= high
                    if scenario == 'zero-backlink':
                        backlink = 0
                    if scenario == 'wrong-backlink':
                        backlink = 0x4321
                    def put(offset, value):
                        struct.pack_into('<Q' if width == 8 else '<I', data, offset, value)
                    put(member, flink)
                    put(member + width, blink)
                    if (flink & mask) + width < len(data):
                        put((flink & mask) + width, backlink)
                    faults = {'backward-target-hole': (blink, width),
                              'forward-container-hole': (flink & mask, width),
                              'forward-member-hole': ((flink & mask) + width, width),
                              'forward-field-hole': (member, width),
                              'backward-field-hole': (member + width, width)}
                    if scenario in faults:
                        holes.append(faults[scenario])

                    class OriginalLayer(BufferDataLayer):
                        @property
                        def address_mask(self):
                            return mask

                        def read(self, offset, length, pad=False):
                            reads.append([offset, length])
                            if any(offset < start + size and start < offset + length for start, size in holes):
                                raise exceptions.InvalidAddressException(self.name, offset)
                            return super().read(offset, length, pad)

                    context = contexts.Context()
                    context.layers.add_layer(OriginalLayer(context, 'memory', 'memory', bytes(data)))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', kernel_path.as_uri()))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'shim', 'shim', path.as_uri(), class_types=shimcache.class_types, native_types=native.x64NativeTable if width == 8 else native.x86NativeTable, table_mapping={'nt_symbols': 'kernel'}))
                    valid = context.object('shim!SHIM_CACHE_ENTRY', 'memory', at).is_valid()
                    cases.append(dict(layout=path.stem, scenario=scenario, width=width, mask=hex(mask), at=at, size=len(data), kernel=kernel, holes=holes, valid=valid, reads=reads,
                                      writes=[dict(offset=offset, data=data[offset:offset+128].hex()) for offset in range(0, len(data), 128) if any(data[offset:offset+128])]))
    assert len(cases) == 270
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Shimcache linked entry oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original linked Shimcache entry controls verified')


if __name__ == '__main__':
    main()
