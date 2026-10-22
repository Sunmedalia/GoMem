#!/usr/bin/env python3
"""Run the pinned complete pool generator over real nonexecutive allocations."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-poolscanner-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import UNICODE_STRING
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER, POOL_HEADER_VISTA
    from volatility3.plugins.windows.poolscanner import PoolScanner

    cases = []
    for width in (4, 8):
        for vista in (False, True):
            for pool_type in (0, 1, 2):
                for delta in (-1, 0, 1):
                    b = lambda n: dict(kind='base', name=n)
                    s = lambda n: dict(kind='struct', name=n)
                    field = lambda off, t: dict(offset=off, type=t)
                    typ = lambda size, fields: dict(kind='struct', size=size, fields=fields)
                    header_size = 16 if width == 8 else 8
                    alignment = 16 if width == 8 else 8
                    types = {'_POOL_HEADER': typ(header_size, {'BlockSize': field(2, b('u8')), 'PoolType': field(3, b('u8')), 'PoolTag': field(4, b('u32'))}),
                             '_OBJECT_HEADER': typ(64, {'Body': field(48, s('_QUAD'))}),
                             '_QUAD': typ(8, {}), '_HANDLE_TABLE': typ(8, {'HandleCount': field(0, b('u32'))}),
                             '_UNICODE_STRING': typ(16, {'Length': field(0, b('u16')), 'Buffer': field(8, dict(kind='pointer', subtype=b('u16')))}),
                             '_OBJECT_TYPE': typ(16, {'Name': field(0, s('_UNICODE_STRING'))})}
                    symbols = {'ObTypeIndexTable': dict(address=0x1000)}
                    if vista:
                        symbols['KdCopyDataBlock'] = dict(address=0x1100)
                    isf = dict(metadata={'format': '6.2.0'}, base_types={name: dict(kind='int', size=size, signed=False, endian='little')
                               for name, size in [('pointer', width), ('u8', 1), ('u16', 2), ('u32', 4)]}, user_types=types, symbols=symbols, enums={})
                    data = bytearray(0x10000)
                    allocations = [('AtmT', '_RTL_ATOM_TABLE', 200), ('MmLd', '_LDR_DATA_TABLE_ENTRY', 76), ('CM10', '_CMHIVE', 800)]
                    for index, (tag, type_name, minimum) in enumerate(allocations):
                        at = 0x2000 + index * 0x1000
                        block = (minimum + alignment - 1) // alignment + delta
                        data[at + 2] = block
                        data[at + 3] = pool_type
                        data[at + 4:at + 8] = tag.encode()
                        types[type_name] = typ(minimum, {})
                    if width == 8:
                        struct.pack_into('<Q', data, 0x8000, 0x9003)
                        struct.pack_into('<Q', data, 0x9000, 0xa003)
                        struct.pack_into('<Q', data, 0xa000, 0x83)
                    else:
                        struct.pack_into('<I', data, 0x8000, 0x83)
                    context = contexts.Context()
                    context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
                    context.config['memory.memory_layer'] = 'physical'
                    context.config['memory.page_map_offset'] = 0x8000
                    context.layers.add_layer((Intel32e if width == 8 else Intel)(context, 'memory', 'memory'))
                    rows = []
                    with tempfile.TemporaryDirectory(prefix='gomem-poolscanner-') as directory:
                        path = Path(directory) / 'kernel.json'
                        path.write_text(json.dumps(isf))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(),
                            class_types={'_POOL_HEADER': POOL_HEADER_VISTA if vista else POOL_HEADER, '_UNICODE_STRING': UNICODE_STRING}))
                        context.module('kernel', 'memory', 0)
                        runner = SimpleNamespace(context=context, config={'kernel': 'kernel'},
                            builtin_constraints=PoolScanner.builtin_constraints, generate_pool_scan=PoolScanner.generate_pool_scan)
                        for _, row in PoolScanner._generator(runner):
                            rows.append([str(row[0]), int(row[1]), str(row[2]),
                                         None if isinstance(row[3], interfaces.renderers.BaseAbsentValue) else str(row[3])])
                    cases.append(dict(width=width, vista=vista, pool_type=pool_type, delta=delta, isf=isf,
                                      size=len(data), writes=[dict(offset=at, data=data[at:at+256].hex()) for at in range(0, len(data), 256) if any(data[at:at+256])], rows=rows))
    assert len(cases) == 36 and sum(len(c['rows']) for c in cases) == 56
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('poolscanner oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} complete pinned pool-generator cases verified')


if __name__ == '__main__':
    main()
