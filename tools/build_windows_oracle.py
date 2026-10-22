#!/usr/bin/env python3
"""Run the complete unmodified original Windows generator on paged GUI memory."""
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
OUTPUT = ROOT / 'internal/plugins/testdata/windows-windowlist-oracle.json'
SCENARIOS = ['normal', 'adjacent', 'child', 'procedure-invalid', 'procedure-zero',
             'procedure-unmapped', 'name-empty', 'name-unmapped', 'name-fallback',
             'process-unmapped', 'private-process-name', 'different-window-session',
             'top-unmapped', 'next-unmapped', 'child-unmapped', 'direct-prefix-gap']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.symbols.windows.extensions import pool
    from volatility3.plugins.windows.windows import Windows
    seed = next(c for c in json.loads((ROOT / 'internal/plugins/testdata/windows-desktops-oracle.json').read_text())['cases'] if c['scenario'] == 'normal')
    types = json.loads((source / 'volatility3/framework/symbols/windows/gui/gui-win10-19041-x64.json').read_text())['user_types']
    def off(typ, member):
        return types[typ]['fields'][member]['offset']
    cases = []
    for scenario in SCENARIOS:
        data = bytearray(seed['size'])
        for write in seed['writes']:
            raw = bytes.fromhex(write['data'])
            data[write['offset']:write['offset'] + len(raw)] = raw
        def q(at, value):
            struct.pack_into('<Q', data, at, value)
        def d(at, value):
            struct.pack_into('<I', data, at, value)
        for i in range(4):
            q(0x40000 + i * 0x1000, 0)
        desktop, info = 0x55060, 0x80000
        a, b, c = 0x81000, 0x82000, 0x83000
        q(desktop + off('tagDESKTOP', 'pDeskInfo'), info)
        q(info + off('tagDESKTOPINFO', 'spwnd'), a)
        for i, at in enumerate([a, b, c]):
            head = at + off('tagWND', 'head')
            q(head + off('_THRDESKHEAD', 'rpdesk'), desktop)
            q(head + off('_THRDESKHEAD', 'pti'), 0x57000)
            q(at + off('tagWND', 'subPointer'), 0x84000 + i * 256)
            q(0x84000 + i * 256 + off('subTagWNDType', 'lpfnWndProc'), 0x7ff000001000 + i * 0x1000)
            buffer = 0x85000 + i * 512
            text = ('Window' + str(i)).encode('utf-16le')
            data[buffer:buffer + len(text)] = text
            q(at + off('tagWND', 'directName'), buffer)
            string = at + off('tagWND', 'strName')
            d(string + off('_LARGE_UNICODE_STRING', 'Length'), len(text))
            q(string + off('_LARGE_UNICODE_STRING', 'Buffer'), buffer)
        if scenario == 'adjacent':
            q(a + off('tagWND', 'spwndNext'), b)
        if scenario == 'child':
            q(a + off('tagWND', 'spwndChild'), c)
        if scenario in ('procedure-invalid', 'procedure-zero'):
            q(0x84000 + off('subTagWNDType', 'lpfnWndProc'), 0x1000 if scenario == 'procedure-invalid' else 0)
        if scenario == 'procedure-unmapped':
            q(a + off('tagWND', 'subPointer'), 0x300000)
        if scenario == 'name-empty':
            data[0x85000:0x85002] = b'\0\0'
        if scenario in ('name-unmapped', 'name-fallback'):
            q(a + off('tagWND', 'directName'), 0x300000)
            if scenario == 'name-unmapped':
                q(a + off('tagWND', 'strName') + off('_LARGE_UNICODE_STRING', 'Buffer'), 0x300000)
        if scenario == 'process-unmapped':
            q(0x5b000 + off('tagPROCESSINFO', 'Process'), 0x300000)
        if scenario == 'private-process-name':
            data[0x62000:0x63000] = data[0x20000:0x21000]
            data[0x62030:0x62040] = b'private-owner\0\0\0'
            q(0x40000 + 0x20 * 8, 0x62003)
        if scenario == 'different-window-session':
            q(a + off('tagWND', 'head') + off('_THRDESKHEAD', 'rpdesk'), 0x87000)
            q(0x87000 + off('tagDESKTOP', 'rpwinstaParent'), 0x88000)
            d(0x88000 + off('tagWINDOWSTATION', 'dwSessionId'), 2)
        if scenario == 'top-unmapped':
            q(desktop + off('tagDESKTOP', 'pDeskInfo'), 0x300000)
        if scenario in ('next-unmapped', 'child-unmapped'):
            q(a + off('tagWND', 'spwndNext' if scenario == 'next-unmapped' else 'spwndChild'), 0x300000)
        if scenario == 'direct-prefix-gap':
            q(a + off('tagWND', 'directName'), 0x89ff0)
            data[0x89ff0:0x8a000] = ('A' * 8).encode('utf-16le')
            q(0x40000 + 0x8a * 8, 0)
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
        context.config['memory.memory_layer'] = 'physical'
        context.config['memory.page_map_offset'] = 0x1000
        context.config['memory.kernel_virtual_offset'] = 0x10000
        context.layers.add_layer(Intel32e(context, 'memory', 'memory'))
        rows, error = [], None
        kernel = copy.deepcopy(seed['isf'])
        with tempfile.TemporaryDirectory(prefix='gomem-windows-') as directory:
            path = Path(directory) / 'kernel.json'
            path.write_text(json.dumps(kernel))
            context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), class_types={
                '_EPROCESS': extensions.EPROCESS, '_LIST_ENTRY': extensions.LIST_ENTRY,
                '_UNICODE_STRING': extensions.UNICODE_STRING, '_OBJECT_HEADER': pool.OBJECT_HEADER, '_POOL_HEADER': pool.POOL_HEADER_VISTA}))
            context.module('kernel', 'memory', 0x10000)
            runner = SimpleNamespace(context=context, config={'kernel': 'kernel'}, config_path='plugin', list_windows=Windows.list_windows)
            try:
                for _, row in Windows._generator(runner):
                    rows.append([None if isinstance(v, interfaces.renderers.BaseAbsentValue) else int(v) if isinstance(v, int) else str(v) for v in row])
            except Exception as exc:
                error = type(exc).__name__
        cases.append(dict(scenario=scenario, isf=kernel, size=len(data), kernel_base=0x10000, kernel_dtb=0x1000, rows=rows, error=error,
                          writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]))
    assert cases[0]['rows'] == [[0x80018, 'WinSta0', 1, 'Default', 'Window0', 0x7ff000001000, 'owner0', 100]], cases[0]['rows']
    assert all(c['error'] is None for c in cases), [(c['scenario'], c['error']) for c in cases]
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Windows generator oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} complete original Windows generator controls verified')


if __name__ == '__main__':
    main()
