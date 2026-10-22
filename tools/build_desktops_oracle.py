#!/usr/bin/env python3
"""Run unmodified original Desktops and DeskScan generators on paged GUI objects."""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_windowstations_oracle import generate as station_controls

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-desktops-oracle.json'
SCENARIOS = ['normal', 'duplicate-owner', 'owner-unmapped', 'thread-cycle',
             'thread-unmapped', 'empty-threads', 'empty-name', 'nul-name',
             'one-character-name', 'name-unmapped', 'parent-unmapped',
             'different-parent-session', 'station-one-character', 'session-missing',
             'free-desktop', 'private-process-name']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.symbols.windows.extensions import pool
    from volatility3.plugins.windows.desktops import Desktops
    from volatility3.plugins.windows.deskscan import DeskScan

    seed = next(c for c in json.loads(station_controls(source))['cases'] if c['scenario'] == 'normal')
    layout = json.loads((source / 'volatility3/framework/symbols/windows/gui/gui-win10-19041-x64.json').read_text())['user_types']
    off = lambda typ, name: layout[typ]['fields'][name]['offset']
    cases = []
    for scenario in SCENARIOS:
        data = bytearray(seed['size'])
        for w in seed['writes']:
            raw = bytes.fromhex(w['data'])
            data[w['offset']:w['offset'] + len(raw)] = raw
        q = lambda at, value: struct.pack_into('<Q', data, at, value)
        d = lambda at, value: struct.pack_into('<I', data, at, value)
        h = lambda at, value: struct.pack_into('<H', data, at, value)
        station = 0x50060
        allocation, desktop = 0x55000, 0x55060
        head = desktop + off('tagDESKTOP', 'PtiList')
        threads = [0x57000, 0x59000]
        nodes = [at + off('tagTHREADINFO', 'PtiLink') for at in threads]
        data[allocation + 2:allocation + 4] = bytes([64, 2])
        data[allocation + 4:allocation + 8] = b'Desk'
        q(allocation + 48, 1)
        data[allocation + 73:allocation + 75] = bytes([32, 2])
        for body in (allocation + 64, allocation + 80, allocation + 112):
            q(body + off('tagDESKTOP', 'rpwinstaParent'), 0xb0000)
        d(0xb0000, 256)
        q(desktop + off('tagDESKTOP', 'rpwinstaParent'), station)
        q(station + off('tagWINDOWSTATION', 'rpdeskList'), desktop)
        h(allocation + 24, 14)
        h(allocation + 26, 16)
        q(allocation + 32, allocation + 0x800)
        data[allocation + 0x800:allocation + 0x80e] = 'Default'.encode('utf-16le')
        q(head, nodes[0]); q(head + 8, nodes[-1])
        for i, thread in enumerate(threads):
            q(nodes[i], nodes[i + 1] if i == 0 else head)
            q(nodes[i] + 8, nodes[i - 1] if i else head)
            info = 0x5b000 + i * 0x400
            q(thread + off('tagTHREADINFO', 'ppi'), info)
            q(info + off('tagPROCESSINFO', 'Process'), 0x20000 + i * 0x1000)
            data[0x20030 + i * 0x1000:0x20040 + i * 0x1000] = ('owner' + str(i)).encode().ljust(16, b'\0')
        if scenario == 'duplicate-owner':
            q(0x5b400, 0x20000)
        if scenario == 'owner-unmapped':
            q(0x5b000, 0x300000)
        if scenario == 'thread-cycle':
            q(nodes[-1], nodes[0])
        if scenario == 'thread-unmapped':
            q(nodes[0], 0x300000)
        if scenario == 'empty-threads':
            q(head, head); q(head + 8, head)
        if scenario == 'empty-name':
            h(allocation + 24, 0)
        if scenario == 'nul-name':
            h(allocation + 24, 2); data[allocation + 0x800:allocation + 0x802] = b'\0\0'
        if scenario == 'one-character-name':
            h(allocation + 24, 2)
        if scenario == 'name-unmapped':
            q(allocation + 32, 0x300000)
        if scenario == 'parent-unmapped':
            q(desktop + off('tagDESKTOP', 'rpwinstaParent'), 0x300000)
        if scenario == 'different-parent-session':
            parent = 0x52060
            q(desktop + off('tagDESKTOP', 'rpwinstaParent'), parent)
            q(parent - 48, 1)
            data[parent - 48 + 25] = 32
            d(parent, 2)
            h(parent - 80 + 8, 10); h(parent - 80 + 10, 12)
            q(parent - 80 + 16, 0x52800)
            data[0x52800:0x5280a] = 'Other'.encode('utf-16le')
        if scenario == 'station-one-character':
            h(0x50018, 2)
        if scenario == 'session-missing':
            d(station, 9)
        if scenario == 'free-desktop':
            data[allocation + 3] = 0
        if scenario == 'private-process-name':
            # Session 1 reads private EPROCESS page bytes; primary memory does
            # not see the alternate owner text. Session IDs remain kernel-read.
            data[0x62000:0x63000] = data[0x20000:0x21000]
            data[0x62030:0x62040] = b'private-owner\0\0\0'
            q(0x40000 + 0x20 * 8, 0x62003)
        kernel = copy.deepcopy(seed['isf'])
        results = {}
        for name, implementation in [('desktops', Desktops.list_desktops), ('deskscan', DeskScan.scan_desktops)]:
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
            context.config['memory.memory_layer'] = 'physical'
            context.config['memory.page_map_offset'] = 0x1000
            context.config['memory.kernel_virtual_offset'] = 0x10000
            context.layers.add_layer(Intel32e(context, 'memory', 'memory'))
            rows, error = [], None
            with tempfile.TemporaryDirectory(prefix='gomem-desktops-') as directory:
                path = Path(directory) / 'kernel.json'
                path.write_text(json.dumps(kernel))
                context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), class_types={
                    '_EPROCESS': extensions.EPROCESS, '_LIST_ENTRY': extensions.LIST_ENTRY,
                    '_UNICODE_STRING': extensions.UNICODE_STRING, '_OBJECT_HEADER': pool.OBJECT_HEADER, '_POOL_HEADER': pool.POOL_HEADER_VISTA}))
                context.module('kernel', 'memory', 0x10000)
                runner = SimpleNamespace(context=context, config={'kernel': 'kernel'}, config_path='plugin', implementation=implementation)
                try:
                    for _, row in Desktops._generator(runner):
                        rows.append([int(row[0]), str(row[1]), int(row[2]), row[3], str(row[4]), int(row[5])])
                except Exception as exc:
                    error = type(exc).__name__
            results[name] = dict(rows=rows, error=error)
        cases.append(dict(scenario=scenario, isf=kernel, size=len(data), kernel_base=0x10000, kernel_dtb=0x1000, results=results,
                          writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]))
    normal = cases[0]['results']
    expected = [[0x55060, 'WinSta0', 1, 'Default', 'owner0', 100], [0x55060, 'WinSta0', 1, 'Default', 'owner1', 101]]
    assert all(r['rows'] == expected and r['error'] is None for r in normal.values()), normal
    assert len(cases) == 16
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('Desktops oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])*2} complete original desktop generator controls verified')


if __name__ == '__main__':
    main()
