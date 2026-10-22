#!/usr/bin/env python3
"""Run actual pinned callback constraint factories and pool-index/header filters."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-callback-pool-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER, POOL_HEADER_VISTA
    from volatility3.plugins.windows.callbacks import Callbacks
    from volatility3.plugins.windows.poolscanner import PoolHeaderScanner

    layouts = []
    for width in (4, 8):
        filename = 'callbacks-x64.json' if width == 8 else 'callbacks-x86.json'
        original = source / 'volatility3/framework/symbols/windows' / filename
        alignment, header_size = width * 2, width * 2
        for vista in (False, True):
            isf = dict(metadata={'format': '6.2.0'}, base_types={
                'pointer': dict(kind='int', size=width, signed=False, endian='little'),
                'u8': dict(kind='int', size=1, signed=False, endian='little'),
                'u32': dict(kind='int', size=4, signed=False, endian='little')},
                user_types={'_POOL_HEADER': dict(kind='struct', size=header_size, fields={
                    name: dict(offset=offset, type=dict(kind='base', name=base))
                    for name, offset, base in [('PoolIndex', 1, 'u8'), ('BlockSize', 2, 'u8'), ('PoolType', 3, 'u8'), ('PoolTag', 4, 'u32')]})},
                enums={}, symbols={})
            context = contexts.Context()
            with tempfile.TemporaryDirectory(prefix='gomem-callback-headers-') as directory:
                path = Path(directory) / 'kernel.json'
                path.write_text(json.dumps(isf))
                context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(),
                    class_types={'_POOL_HEADER': POOL_HEADER_VISTA if vista else POOL_HEADER}))
                context.symbol_space.append(IntermediateSymbolTable(context, 'callbacks', 'callbacks', original.as_uri()))
                constraints = Callbacks.create_callback_scan_constraints(context, 'callbacks', vista)
                normalized = [dict(tag=c.tag.hex(), type_name=c.type_name.split('!')[1],
                                   page_type=int(c.page_type), size=c.size, index=c.index) for c in constraints]
                cases = []
                for c in constraints:
                    threshold = (c.size[0] + alignment - 1) // alignment
                    blocks = sorted({threshold - 1, threshold, threshold + 1} | ({c.size[1] // alignment + 1} if c.size[1] else set()))
                    for block in blocks:
                        for pool_type in (0, 1, 2, 3, 4, 5, 0x80, 0x81):
                            for index in (0, 1, 2, 255):
                                cases.append(dict(offset=32 + len(cases) * 32, tag=c.tag.hex(),
                                                  block=block, pool_type=pool_type, index=index))
                data = bytearray(32 + len(cases) * 32)
                for case in cases:
                    at = case['offset']
                    data[at + 1:at + 4] = bytes([case['index'], case['block'], case['pool_type']])
                    data[at + 4:at + 8] = bytes.fromhex(case['tag'])
                context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
                module = context.module('kernel', 'physical', 0)
                scanner = PoolHeaderScanner(module, {c.tag: c for c in constraints}, alignment)
                accepted = {int(header.vol.offset) for _, header in scanner(bytes(data), 0)}
                for case in cases:
                    case['accepted'] = case['offset'] in accepted
            layouts.append(dict(width=width, vista=vista, source_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                                isf=isf, data=data.hex(), constraints=normalized, cases=cases))
    return json.dumps(dict(commit=COMMIT, scope=__doc__, layouts=layouts), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('callback pool oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    doc = json.loads(generated)
    print(f'{len(doc["layouts"])} callback layouts and {sum(len(x["cases"]) for x in doc["layouts"])} actual pool headers verified')


if __name__ == '__main__':
    main()
