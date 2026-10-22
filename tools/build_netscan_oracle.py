#!/usr/bin/env python3
"""Run complete pinned NetScan generators over actual paged network allocations."""
import argparse
import copy
import datetime
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-netscan-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import EPROCESS, UNICODE_STRING
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER_VISTA
    from volatility3.plugins.windows.netscan import NetScan

    folder = ROOT / 'internal/plugins/testdata'
    objects = json.loads((folder / 'windows-network-object-oracle.json').read_text())
    versions = json.loads((folder / 'windows-network-version-oracle.json').read_text())
    pools = json.loads((folder / 'windows-poolscanner-oracle.json').read_text())
    assert all(f['commit'] == COMMIT for f in (objects, versions, pools))
    cases = []
    for arch, intel in [('x86', Intel), ('pae', IntelPAE), ('x64', Intel32e)]:
        version = next(c for c in versions['cases'] if c['arch'] == arch and c['build'] == 7601 and c['mode'] == 'metadata')
        width = version['width']
        name = 'netscan-win7-' + ('x64' if width == 8 else 'x86')
        owner = next(l['kernel_isf'] for l in objects['layouts'] if l['name'] == name)
        pool = next(c['isf'] for c in pools['cases'] if c['width'] == width and c['vista'])
        schema = json.loads((source / 'volatility3/framework/symbols/windows/netscan' / (name + '.json')).read_text())
        for obj in (c for c in objects['cases'] if c['layout'] == name):
            table = copy.deepcopy(version['isf'])
            for key in ('base_types', 'user_types'):
                table[key].update(owner[key])
                table[key].update(pool[key])
            table['symbols'].update(ObTypeIndexTable={'address': 0x1a000}, KdCopyDataBlock={'address': 0x1b000})
            data = bytearray(0x20000)
            for w in version['writes']:
                at, raw = w['offset'], bytes.fromhex(w['data'])
                assert at + len(raw) <= len(data)
                data[at:at + len(raw)] = raw
            root = 0x12000 + width * 2
            for w in obj['writes']:
                at, raw = w['offset'], bytes.fromhex(w['data'])
                if 0x1000 <= at < 0x2000:
                    at = root + at - 0x1000
                assert at + len(raw) <= len(data)
                data[at:at + len(raw)] = raw
            typ = obj['type']
            alignment = width * 2
            size = schema['user_types'][typ]['size']
            data[0x12002] = (size + alignment - 1) // alignment
            data[0x12003] = 2
            data[0x12004:0x12008] = {'_TCP_ENDPOINT': b'TcpE', '_TCP_LISTENER': b'TcpL', '_UDP_ENDPOINT': b'UdpA'}[typ]
            results = []
            for corrupt in (False, True):
                class OriginalBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):
                        return (1 << (width * 8)) - 1

                    def is_valid(self, offset, length=1):
                        valid = super().is_valid(offset, length)
                        if not valid:
                            self.invalid_spans.append(dict(offset=offset, length=length))
                        return valid

                    def read(self, offset, length, pad=False):
                        try:
                            return super().read(offset, length, pad)
                        except exceptions.InvalidAddressException:
                            self.faults.append(dict(offset=offset, length=length))
                            raise

                context = contexts.Context()
                physical = OriginalBuffer(context, 'physical', 'physical', bytes(data))
                physical.faults = []
                physical.invalid_spans = []
                context.layers.add_layer(physical)
                context.config['memory.memory_layer'] = 'physical'
                context.config['memory.page_map_offset'] = 0x8000
                context.layers.add_layer(intel(context, 'memory', 'memory'))
                with tempfile.TemporaryDirectory(prefix='gomem-netscan-generator-') as directory:
                    path = Path(directory) / 'kernel.json'
                    path.write_text(json.dumps(table))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), class_types={
                        '_POOL_HEADER': POOL_HEADER_VISTA, '_UNICODE_STRING': UNICODE_STRING, '_EPROCESS': EPROCESS}))
                    context.module('kernel', 'memory', 0)
                    runner = SimpleNamespace(context=context, _context=context, config={'kernel': 'kernel'}, config_path='plugins.NetScan',
                                             create_netscan_symbol_table=NetScan.create_netscan_symbol_table, scan=NetScan.scan)
                    rows = []
                    for depth, row in NetScan._generator(runner, corrupt):
                        assert depth == 0
                        converted = []
                        for value in row:
                            if isinstance(value, interfaces.renderers.BaseAbsentValue):
                                value = None
                            elif isinstance(value, datetime.datetime):
                                value = value.isoformat()
                            elif not isinstance(value, str):
                                value = int(value)
                            converted.append(value)
                        rows.append(converted)
                    results.append(dict(include_corrupt=corrupt, rows=rows, read_faults=physical.faults, unavailable_checks=physical.invalid_spans))
            writes = [dict(offset=at, data=data[at:at+256].hex()) for at in range(0, len(data), 256) if any(data[at:at+256])]
            cases.append(dict(arch=arch, width=width, layout=name, type=typ, family=obj['family'], scenario=obj['scenario'],
                              isf=table, size=len(data), writes=writes, results=results))
    assert len(cases) == 144
    assert sum(bool(r['rows']) for c in cases if c['scenario'] == 'normal' for r in c['results']) == 36
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('complete netscan oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print('144 byte-backed allocations and 288 complete pinned NetScan generators verified')


if __name__ == '__main__':
    main()
