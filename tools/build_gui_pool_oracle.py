#!/usr/bin/env python3
"""Run original GUI constraints, pool-header filters and executive carving."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-gui-pool-oracle.json'
SCENARIOS = ['normal', 'sid-256', 'sid-hole', 'parent-hole', 'null-parent',
             'pointer-negative', 'pointer-high', 'free', 'short', 'paged']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import gui
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER_VISTA
    from volatility3.plugins.windows.poolscanner import PoolScanner, PoolHeaderScanner

    base = lambda name: dict(kind='base', name=name)
    field = lambda at, ref: dict(offset=at, type=ref)
    typ = lambda size, fields: dict(kind='struct', size=size, fields=fields)
    kernel = dict(metadata={'format': '6.2.0'}, base_types={
        name: dict(kind='int', size=size, signed=signed, endian='little')
        for name, size, signed in [('pointer', 8, False), ('u8', 1, False), ('u32', 4, False), ('i64', 8, True)]},
        user_types={
            '_POOL_HEADER': typ(16, {name: field(at, base(ref)) for name, at, ref in
                                     [('BlockSize', 2, 'u8'), ('PoolType', 3, 'u8'), ('PoolTag', 4, 'u32')]}),
            '_OBJECT_HEADER': typ(56, {'Body': field(48, dict(kind='struct', name='_QUAD')),
                                      'PointerCount': field(0, base('i64')), 'InfoMask': field(26, base('u8'))}),
            '_QUAD': typ(8, {}), '_OBJECT_HEADER_NAME_INFO': typ(32, {})},
        symbols={'ObTypeIndexTable': dict(address=0x1000)}, enums={})
    cases = []
    layouts = sorted(json.loads((ROOT / 'pkg/wingui/testdata/object-oracle.json').read_text())['layouts'])
    normalized = None
    for name in layouts:
        layout_path = source / 'volatility3/framework/symbols/windows/gui' / (name + '.json')
        types = json.loads(layout_path.read_text())['user_types']
        sid_at = types['tagWINDOWSTATION']['fields']['dwSessionId']['offset']
        parent_at = types['tagDESKTOP']['fields']['rpwinstaParent']['offset']
        for top_down in (False, True):
            for tag in (b'Wind', b'Desk'):
                for scenario in SCENARIOS:
                    constraints = PoolScanner.gui_poolscanner_constraints('gui', [tag])
                    c = constraints[0]
                    if normalized is None:
                        normalized = [dict(tag=x.tag.hex(), type_name=x.type_name.split('!')[1],
                                           object_type=x.object_type, page_type=int(x.page_type),
                                           size=x.size, skip_type=x.skip_type_test)
                                      for x in PoolScanner.gui_poolscanner_constraints('gui')]
                    type_name = c.type_name.split('!')[1]
                    size = types[type_name]['size']
                    rounded = (size + 15) // 16 * 16
                    block_bytes = rounded + 64
                    header = 0x2000
                    body = header + 64
                    if scenario == 'short':
                        block_bytes = 0x80
                        if not top_down:
                            body = header + block_bytes - rounded
                    data = bytearray(0x10000)
                    holes = []
                    data[header + 2] = block_bytes // 16
                    data[header + 3] = 0 if scenario == 'free' else 1 if scenario == 'paged' else 2
                    data[header + 4:header + 8] = tag
                    # Other top-down slots must fail validity rather than be
                    # removed from the original carving algorithm.
                    for candidate in (header + 64, header + 80):
                        if tag == b'Wind':
                            struct.pack_into('<I', data, candidate + sid_at, 256)
                        else:
                            struct.pack_into('<Q', data, candidate + parent_at, 0x9000)
                    struct.pack_into('<I', data, 0x9000 + sid_at, 256)
                    station = body if tag == b'Wind' else 0xa000
                    struct.pack_into('<I', data, station + sid_at, 256 if scenario == 'sid-256' else 1)
                    if tag == b'Desk':
                        struct.pack_into('<Q', data, body + parent_at, 0 if scenario == 'null-parent' else station)
                    if scenario == 'sid-hole':
                        holes.append((station + sid_at, 4))
                    if scenario == 'parent-hole' and tag == b'Desk':
                        holes.append((body + parent_at, 8))
                    if scenario in ('pointer-negative', 'pointer-high'):
                        struct.pack_into('<q', data, header + 16, -1 if scenario == 'pointer-negative' else 0x1000000)
                    class Layer(BufferDataLayer):
                        @property
                        def address_mask(self):
                            return (1 << 64) - 1

                        def read(self, at, length, pad=False):
                            for start, count in holes:
                                if at < start + count and start < at + length:
                                    if not pad:
                                        raise exceptions.InvalidAddressException(self.name, max(at, start))
                            raw = bytearray(super().read(at, length, pad))
                            if pad:
                                for start, count in holes:
                                    left, right = max(at, start), min(at + length, start + count)
                                    if left < right:
                                        raw[left - at:right - at] = bytes(right - left)
                            return bytes(raw)
                    context = contexts.Context()
                    context.layers.add_layer(Layer(context, 'memory', 'memory', bytes(data)))
                    with tempfile.TemporaryDirectory(prefix='gomem-gui-pool-') as directory:
                        path = Path(directory) / 'kernel.json'
                        path.write_text(json.dumps(kernel))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', path.as_uri(), class_types={'_POOL_HEADER': POOL_HEADER_VISTA}))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'gui', 'gui', layout_path.as_uri(), class_types=gui.GUIExtensions.class_types, table_mapping={'nt_symbols': 'kernel'}))
                        module = context.module('kernel', 'memory', 0)
                        scanner = PoolHeaderScanner(module, {tag: c}, 16)
                        accepted = header in {int(h.vol.offset) for _, h in scanner(bytes(data), 0)}
                        h = context.object('kernel!_POOL_HEADER', 'memory', header)
                        objects = [int(o.vol.offset) for o in h.get_object(c, top_down, kernel_symbol_table='kernel', native_layer_name='memory')] if accepted else []
                    cases.append(dict(layout=name, top_down=top_down, tag=tag.hex(), scenario=scenario,
                                      header=header, block_bytes=block_bytes, accepted=accepted, objects=objects,
                                      holes=holes, writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]))
    assert len(cases) == 480
    return json.dumps(dict(commit=COMMIT, scope=__doc__, kernel=kernel, size=0x10000,
                           constraints=normalized, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('GUI pool oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} original GUI pool constraints/filter/carving controls verified')


if __name__ == '__main__':
    main()
