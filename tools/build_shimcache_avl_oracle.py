#!/usr/bin/env python3
"""Run unmodified Shimcache RTL_AVL_TABLE validity against all 12 layouts."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winshimcache/testdata/avl-oracle.json'
SCENARIOS = ['normal', 'parent-wrong', 'parent-zero', 'allocate-before',
             'allocate-start', 'allocate-end', 'allocate-after',
             'compare-before', 'compare-start', 'compare-end', 'compare-after',
             'same-routine-values', 'free-outside', 'free-zero', 'parent-hole',
             'allocate-hole', 'compare-hole', 'free-hole', 'reversed-range',
             'table-zero', 'maximum-compare', 'unreachable-free-hole']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import shimcache
    cases, layouts = [], {}
    for path in sorted((source / 'volatility3/framework/symbols/windows/shimcache').glob('*.json')):
        raw = path.read_bytes()
        doc = json.loads(raw)
        width = doc['base_types']['pointer']['size']
        fields = doc['user_types']['_RTL_AVL_TABLE']['fields']
        root_offset = fields['BalancedRoot']['offset']
        parent_offset = doc['user_types']['_RTL_BALANCED_LINKS']['fields']['Parent']['offset']
        # Python 3.12 gzip.compress(mtime=0) embeds zlib's platform OS byte;
        # lossless raw base64 keeps oracle output identical across CI hosts.
        layouts[path.stem] = dict(sha256=hashlib.sha256(raw).hexdigest(), source_base64=base64.b64encode(raw).decode())
        for scenario in SCENARIOS:
            data, holes, reads = bytearray(0x10000), [], []
            at = 0 if scenario == 'table-zero' else 0x1000
            start, end = (0x4000, 0x3000) if scenario == 'reversed-range' else (0x3000, 0x4000)
            def put(offset, value):
                struct.pack_into('<Q' if width == 8 else '<I', data, offset, value)
            parent_at = at + root_offset + parent_offset
            put(parent_at, 0x2000 if scenario == 'parent-wrong' else 0 if scenario == 'parent-zero' else at + root_offset)
            for member, value in [('AllocateRoutine', 0x3020), ('CompareRoutine', 0x3040), ('FreeRoutine', 0x3060)]:
                if scenario == 'same-routine-values':
                    value = 0x3020
                if member == 'AllocateRoutine':
                    value = {'allocate-before': 0x2fff, 'allocate-start': 0x3000, 'allocate-end': 0x4000, 'allocate-after': 0x4001, 'unreachable-free-hole': 0x2fff}.get(scenario, value)
                if member == 'CompareRoutine':
                    value = {'compare-before': 0x2fff, 'compare-start': 0x3000, 'compare-end': 0x4000, 'compare-after': 0x4001, 'maximum-compare': (1 << (width * 8)) - 1}.get(scenario, value)
                if member == 'FreeRoutine':
                    value = {'free-outside': 0x5000, 'free-zero': 0}.get(scenario, value)
                put(at + fields[member]['offset'], value)
            fault = {'parent-hole': parent_at, 'allocate-hole': at + fields['AllocateRoutine']['offset'], 'compare-hole': at + fields['CompareRoutine']['offset'], 'free-hole': at + fields['FreeRoutine']['offset'], 'unreachable-free-hole': at + fields['FreeRoutine']['offset']}.get(scenario)
            if fault is not None:
                holes.append((fault, width))

            class OriginalLayer(BufferDataLayer):
                @property
                def address_mask(self):
                    return (1 << (width * 8)) - 1

                def read(self, offset, length, pad=False):
                    reads.append([offset, length])
                    for begin, size in holes:
                        if offset < begin + size and begin < offset + length:
                            raise exceptions.InvalidAddressException(self.name, max(offset, begin))
                    return super().read(offset, length, pad)

            context = contexts.Context()
            context.layers.add_layer(OriginalLayer(context, 'memory', 'memory', bytes(data)))
            context.symbol_space.append(IntermediateSymbolTable(context, 'shim', 'shim', path.as_uri(), class_types=shimcache.class_types))
            table = context.object('shim!_RTL_AVL_TABLE', 'memory', at)
            valid = table.is_valid(start, end)
            cases.append(dict(layout=path.stem, scenario=scenario, width=width, at=at, page_start=start, page_end=end, size=len(data), holes=holes, valid=valid, reads=reads,
                              writes=[dict(offset=offset, data=data[offset:offset + 128].hex()) for offset in range(0, len(data), 128) if any(data[offset:offset + 128])]))
    assert len(layouts) == 12 and len(cases) == 264
    for case in cases:
        if case['scenario'] in ('normal', 'same-routine-values', 'free-outside', 'free-zero', 'table-zero', 'allocate-start', 'allocate-end', 'compare-start', 'compare-end'):
            assert case['valid'], (case['layout'], case['scenario'])
    return json.dumps(dict(commit=COMMIT, scope=__doc__, layouts=layouts, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Shimcache AVL oracle drift')
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original Shimcache AVL controls verified')


if __name__ == '__main__':
    main()
