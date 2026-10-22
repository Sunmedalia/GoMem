#!/usr/bin/env python3
"""Run pinned pool-header scanner and built-in constraints on byte-backed headers."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-pool-header-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER, POOL_HEADER_VISTA
    from volatility3.plugins.windows.poolscanner import PoolScanner, PoolHeaderScanner

    constraints = PoolScanner.builtin_constraints('kernel')
    normalized = [dict(tag=c.tag.hex(), type_name=c.type_name.split('!')[1],
                       object_type=c.object_type, page_type=int(c.page_type),
                       size=c.size, skip_type=bool(c.skip_type_test),
                       additional=c.additional_structures or []) for c in constraints]
    layouts = []
    for width in (4, 8):
        alignment = 16 if width == 8 else 8
        header_size = 16 if width == 8 else 8
        isf = dict(metadata={'format': '6.2.0'}, base_types={
            'pointer': dict(kind='int', size=width, signed=False, endian='little'),
            'u8': dict(kind='int', size=1, signed=False, endian='little'),
            'u32': dict(kind='int', size=4, signed=False, endian='little')},
            user_types={'_POOL_HEADER': dict(kind='struct', size=header_size, fields={
                name: dict(offset=offset, type=dict(kind='base', name=base))
                for name, offset, base in [('BlockSize', 2, 'u8'), ('PoolType', 3, 'u8'), ('PoolTag', 4, 'u32')]})},
            enums={}, symbols={})
        for vista in (False, True):
            cases = []
            for constraint in constraints:
                threshold = (constraint.size[0] + alignment - 1) // alignment
                for block in (threshold - 1, threshold, threshold + 1):
                    for pool_type in (0, 1, 2, 3, 4, 5, 0x80, 0x81):
                        at = 32 + len(cases) * 32
                        cases.append(dict(offset=at, tag=constraint.tag.hex(), block=block, pool_type=pool_type))
            data = bytearray(32 + len(cases) * 32)
            for case in cases:
                at = case['offset']
                data[at + 2] = case['block']
                data[at + 3] = case['pool_type']
                data[at + 4:at + 8] = bytes.fromhex(case['tag'])
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
            with tempfile.TemporaryDirectory(prefix='gomem-pool-header-') as directory:
                path = Path(directory) / 'kernel.json'
                path.write_text(json.dumps(isf))
                context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(),
                    class_types={'_POOL_HEADER': POOL_HEADER_VISTA if vista else POOL_HEADER}))
                module = context.module('kernel', 'physical', 0)
                scanner = PoolHeaderScanner(module, {c.tag: c for c in constraints}, alignment)
                accepted = {int(header.vol.offset) for _, header in scanner(bytes(data), 0)}
                for case in cases:
                    header = context.object('kernel!_POOL_HEADER', layer_name='physical', offset=case['offset'])
                    case.update(accepted=case['offset'] in accepted, free=header.is_free_pool(),
                                paged=header.is_paged_pool(), nonpaged=header.is_nonpaged_pool())
            layouts.append(dict(width=width, vista=vista, isf=isf, data=data.hex(), cases=cases))
    assert len(normalized) == 15 and len(layouts) == 4
    return json.dumps(dict(commit=COMMIT, scope=__doc__, constraints=normalized, layouts=layouts), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('pool-header oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    doc = json.loads(generated)
    print(f'{len(doc["constraints"])} built-in constraints and {sum(len(x["cases"]) for x in doc["layouts"])} actual pool headers verified')


if __name__ == '__main__':
    main()
