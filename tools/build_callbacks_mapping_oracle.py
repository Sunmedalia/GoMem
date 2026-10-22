#!/usr/bin/env python3
"""Run original Callbacks generators on permuted physical pages and real PTE holes."""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-callbacks-mapping-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires locked unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import EX_FAST_REF, LIST_ENTRY, UNICODE_STRING, DEVICE_OBJECT, DRIVER_OBJECT
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER, POOL_HEADER_VISTA, OBJECT_HEADER
    from volatility3.plugins.windows.callbacks import Callbacks

    original = json.loads((ROOT / 'internal/plugins/testdata/windows-callbacks-oracle.json').read_text())
    assert original['commit'] == COMMIT and len(original['cases']) == 144
    cases = []
    for arch, intel in [('x86', Intel), ('pae', IntelPAE), ('x64', Intel32e)]:
        for version in ('pre-Vista', 'Vista', 'Windows10'):
            vista = version != 'pre-Vista'
            for legacy in (False, True):
                base = next(c for c in original['cases'] if c['arch'] == arch and c['vista'] == vista and c['legacy'] == legacy and c['scenario'] == 'normal')
                for scenario in ('normal', 'driver-hole', 'component-hole', 'module-hole', 'pool-hole'):
                    table = copy.deepcopy(base['isf'])
                    if version == 'Windows10':
                        table['metadata']['windows']['pe'].update(major=10, minor=0, build=19041)
                    virtual = bytearray(base['size'])
                    for w in base['writes']:
                        at, raw = w['offset'], bytes.fromhex(w['data'])
                        virtual[at:at + len(raw)] = raw
                    # Every source page moves and neighbouring virtual pages map
                    # to descending physical frames. Raw physical scanning sees
                    # allocation bytes in a different order and at new offsets.
                    data = bytearray(0x80000)
                    page_map = {i * 0x1000: 0x40000 + (63 - i) * 0x1000 for i in range(64)}
                    for va, pa in page_map.items():
                        data[pa:pa + 0x1000] = virtual[va:va + 0x1000]
                    hole = {'driver-hole': 0x4000, 'component-hole': 0xc000,
                            'module-hole': 0x39000, 'pool-hole': 0x34000}.get(scenario)
                    def q(at, value): struct.pack_into('<Q', data, at, value)
                    if arch == 'x86':
                        struct.pack_into('<I', data, 0x8000, 0x9003)
                        pt, stride, fmt = 0x9000, 4, '<I'
                    elif arch == 'pae':
                        q(0x8000, 0x9003); q(0x9000, 0xa003)
                        pt, stride, fmt = 0xa000, 8, '<Q'
                    else:
                        q(0x8000, 0x9003); q(0x9000, 0xa003); q(0xa000, 0xb003)
                        pt, stride, fmt = 0xb000, 8, '<Q'
                    for va, pa in page_map.items():
                        struct.pack_into(fmt, data, pt + (va // 4096) * stride, 0 if va == hole else pa | 3)
                    context = contexts.Context()
                    context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
                    context.config['memory.memory_layer'] = 'physical'
                    context.config['memory.page_map_offset'] = 0x8000
                    context.layers.add_layer(intel(context, 'memory', 'memory'))
                    rows, error = [], None
                    with tempfile.TemporaryDirectory(prefix='gomem-callbacks-mapping-') as directory:
                        path = Path(directory) / 'kernel.json'; path.write_text(json.dumps(table))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), class_types={
                            '_EX_FAST_REF': EX_FAST_REF, '_LIST_ENTRY': LIST_ENTRY, '_UNICODE_STRING': UNICODE_STRING,
                            '_DEVICE_OBJECT': DEVICE_OBJECT, '_DRIVER_OBJECT': DRIVER_OBJECT, '_OBJECT_HEADER': OBJECT_HEADER,
                            '_POOL_HEADER': POOL_HEADER_VISTA if vista else POOL_HEADER}))
                        context.module('kernel', 'memory', 0x10000)
                        runner = SimpleNamespace(context=context, _context=context, config={'kernel': 'kernel'}, config_path='plugins.Callbacks')
                        for name in ('create_callback_symbol_table', 'list_notify_routines', 'list_bugcheck_callbacks', 'list_bugcheck_reason_callbacks', 'list_registry_callbacks', 'scan'):
                            setattr(runner, name, getattr(Callbacks, name))
                        try:
                            for depth, row in Callbacks._generator(runner):
                                assert depth == 0
                                values = []
                                for value in row:
                                    if isinstance(value, interfaces.renderers.BaseAbsentValue):
                                        value = dict(missing=type(value).__name__)
                                    elif not isinstance(value, str):
                                        value = int(value)
                                    values.append(value)
                                rows.append(values)
                        except Exception as exc:
                            error = dict(type=type(exc).__name__, message=str(exc))
                    writes = [dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]
                    cases.append(dict(arch=arch, width=base['width'], version=version, vista=vista, legacy=legacy,
                                      scenario=scenario, kernel_base=0x10000, isf=table, size=len(data),
                                      page_map=[dict(virtual=va, physical=pa, present=va != hole) for va, pa in page_map.items()],
                                      writes=writes, rows=rows, error=error))
    assert len(cases) == 90
    assert all(c["error"] is None for c in cases)
    assert sum(len(c["rows"]) for c in cases) == 1104
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('callback mapping oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} permuted-page callback generators verified')


if __name__ == '__main__':
    main()
