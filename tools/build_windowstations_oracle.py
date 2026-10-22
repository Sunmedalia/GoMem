#!/usr/bin/env python3
"""Run the complete original WindowStations generator on actual paged memory."""
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
OUTPUT = ROOT / 'internal/plugins/testdata/windows-windowstations-oracle.json'
SCENARIOS = ['normal', 'second-station', 'root-traversal', 'missing-session',
             'invalid-session', 'one-character', 'session-private-name', 'null-next',
             'next-hole', 'name-hole', 'bad-session-cr3', 'duplicate-pid',
             'empty-processes', 'free-pool', 'short-pool', 'empty-name']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.symbols.windows.extensions import pool
    from volatility3.plugins.windows.windowstations import WindowStations

    sessions = json.loads((ROOT / 'pkg/wingui/testdata/sessions-oracle.json').read_text())
    seed = next(c for c in sessions['cases'] if c['layout'] == 'typed' and c['scenario'] == 'normal')
    names = json.loads((ROOT / 'pkg/wingui/testdata/names-oracle.json').read_text())
    name_kernel = next(c['kernel'] for c in names['cases'] if c['header_kind'] == 'offset')
    pools = json.loads((ROOT / 'internal/plugins/testdata/windows-gui-pool-oracle.json').read_text())
    cases = []
    for scenario in SCENARIOS:
        kernel = copy.deepcopy(seed['isf'])
        kernel['metadata']['windows'] = dict(pe=dict(major=10, minor=0, revision=19041, build=0))
        for section in ('base_types', 'user_types'):
            kernel[section].update({k: v for k, v in name_kernel[section].items() if k not in kernel[section]})
            kernel[section].update({k: v for k, v in pools['kernel'][section].items() if k not in kernel[section]})
        kernel['user_types']['_OBJECT_HEADER_CREATOR_INFO'] = dict(kind='struct', size=32, fields={})
        kernel['base_types']['unsigned int'] = dict(kind='int', size=4, signed=False, endian='little')
        header = kernel['user_types']['_OBJECT_HEADER']
        header['fields']['PointerCount'] = dict(offset=0, type=dict(kind='base', name='i64'))
        header['fields']['InfoMask'] = dict(offset=26, type=dict(kind='base', name='unsigned char'))
        kernel['user_types']['_OBJECT_TYPE'] = dict(kind='struct', size=16, fields={'Name': dict(offset=0, type=dict(kind='struct', name='_UNICODE_STRING'))})
        kernel['symbols']['ObTypeIndexTable'] = dict(address=0x60000)
        data = bytearray(0x200000)
        for w in seed['writes']:
            raw = bytes.fromhex(w['data'])
            data[w['offset']:w['offset'] + len(raw)] = raw
        holes = []
        q = lambda at, value: struct.pack_into('<Q', data, at, value)
        d = lambda at, value: struct.pack_into('<I', data, at, value)
        h = lambda at, value: struct.pack_into('<H', data, at, value)
        def station(at, text, sid=1, with_pool=True):
            body = at + 96
            data[at + 2] = 32
            data[at + 3] = 2
            data[at + 4:at + 8] = b'Wind' if with_pool else b'None'
            q(at + 48, 1)
            data[at + 48 + 25] = 32
            data[at + 48 + 26] = 2
            d(at + 64, 256)
            d(at + 80, 256)
            d(body, sid)
            q(body + 8, body)
            d(body + 16, 256)  # Reject the second aligned carving slot.
            info = at + 16
            raw = text.encode('utf-16le')
            buffer = at + 0x800
            h(info + 8, len(raw))
            h(info + 10, len(raw) + 2)
            q(info + 16, buffer)
            data[buffer:buffer + len(raw)] = raw
            return body
        root = station(0x50000, 'WinSta0')
        if scenario in ('second-station', 'root-traversal'):
            second = station(0x52000, 'Service', with_pool=scenario == 'second-station')
            q(root + 8, second)
            if scenario == 'root-traversal':
                third = station(0x54000, 'Unreached', with_pool=False)
                q(second + 8, third)
        if scenario == 'missing-session':
            d(root, 9)
        if scenario == 'invalid-session':
            d(root, 256)
        if scenario == 'one-character':
            station(0x50000, 'A')
        if scenario == 'empty-name':
            station(0x50000, '')
        if scenario == 'session-private-name':
            # Only the first session's process mapping sees the alternative text.
            # The original pool scan still sees the shared kernel bytes.
            data[0x61000:0x62000] = data[0x50000:0x51000]
            q(0x40000 + 0x50 * 8, 0x61003)
            data[0x61800:0x61800 + 14] = 'Session'.encode('utf-16le')
        if scenario == 'null-next':
            q(root + 8, 0)
        if scenario == 'next-hole':
            holes.append((root + 8, 8))
        if scenario == 'name-hole':
            holes.append((0x50800, 14))
        if scenario == 'bad-session-cr3':
            q(0x20000 + 24, 0x300000)
        if scenario == 'duplicate-pid':
            q(0x21000 + 16, 100)
        if scenario == 'empty-processes':
            q(0x18080, 0x18080)
            q(0x18088, 0x18080)
        if scenario == 'free-pool':
            data[0x50003] = 0
        if scenario == 'short-pool':
            data[0x50002] = 8
        class Physical(BufferDataLayer):
            def is_valid(self, at, length=1):
                return super().is_valid(at, length) and not any(at < start + size and start < at + length for start, size in holes)

            def read(self, at, length, pad=False):
                for start, size in holes:
                    if at < start + size and start < at + length and not pad:
                        raise exceptions.InvalidAddressException(self.name, max(at, start))
                raw = bytearray(super().read(at, length, pad))
                if pad:
                    for start, size in holes:
                        left, right = max(at, start), min(at + length, start + size)
                        if left < right:
                            raw[left - at:right - at] = bytes(right - left)
                return bytes(raw)
        context = contexts.Context()
        context.layers.add_layer(Physical(context, 'physical', 'physical', bytes(data)))
        context.config['memory.memory_layer'] = 'physical'
        context.config['memory.page_map_offset'] = 0x1000
        context.config['memory.kernel_virtual_offset'] = 0x10000
        context.layers.add_layer(Intel32e(context, 'memory', 'memory'))
        error = None
        rows = []
        with tempfile.TemporaryDirectory(prefix='gomem-windowstations-') as directory:
            path = Path(directory) / 'kernel.json'
            path.write_text(json.dumps(kernel))
            context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), class_types={
                '_EPROCESS': extensions.EPROCESS, '_LIST_ENTRY': extensions.LIST_ENTRY,
                '_UNICODE_STRING': extensions.UNICODE_STRING, '_OBJECT_HEADER': pool.OBJECT_HEADER, '_POOL_HEADER': pool.POOL_HEADER_VISTA}))
            context.module('kernel', 'memory', 0x10000)
            runner = SimpleNamespace(context=context, config={'kernel': 'kernel'}, config_path='plugin', scan_window_stations=WindowStations.scan_window_stations)
            try:
                for _, row in WindowStations._generator(runner):
                    rows.append([int(row[0]), str(row[1]), int(row[2])])
            except Exception as exc:
                error = type(exc).__name__
        cases.append(dict(scenario=scenario, isf=kernel, size=len(data), kernel_base=0x10000, kernel_dtb=0x1000, holes=holes, rows=rows, error=error,
                          writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]))
    normal = next(c for c in cases if c['scenario'] == 'normal')
    assert normal['rows'] == [[0x50060, 'WinSta0', 1]] and normal['error'] is None, (normal['rows'], normal['error'])
    private = next(c for c in cases if c['scenario'] == 'session-private-name')
    assert private['rows'] == [[0x50060, 'Session', 1], [0x61060, 'Session', 1]] and private['error'] is None, (private['rows'], private['error'])
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('WindowStations oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} complete original WindowStations controls verified')


if __name__ == '__main__':
    main()
