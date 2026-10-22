#!/usr/bin/env python3
"""Run complete unmodified NetStat generators, including resident RSDS/cache resolution."""
import argparse
import copy
import datetime
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-netstat-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import constants, contexts, exceptions, interfaces
    from volatility3.framework.automagic import symbol_cache
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import EPROCESS, LIST_ENTRY, UNICODE_STRING
    from volatility3.plugins.windows.netstat import NetStat

    folder = ROOT / 'internal/plugins/testdata'
    versions = json.loads((folder / 'windows-network-version-oracle.json').read_text())
    objects = json.loads((folder / 'windows-network-object-oracle.json').read_text())
    indexes = json.loads((folder / 'windows-netstat-index-oracle.json').read_text())
    assert all(x['commit'] == COMMIT for x in (versions, objects, indexes))
    cases = []
    for arch, intel in [('x86', Intel), ('pae', IntelPAE), ('x64', Intel32e)]:
        version = next(c for c in versions['cases'] if c['arch'] == arch and c['build'] == 7601 and c['mode'] == 'metadata')
        width = version['width']
        name = 'netscan-win7-' + ('x64' if width == 8 else 'x86')
        index = next(c for c in indexes['cases'] if c['layout'] == name and c['mode'] == 'direct' and c['scenario'] == 'normal')
        owner = next(c['kernel_isf'] for c in objects['layouts'] if c['name'] == name)
        network = json.loads((source / 'volatility3/framework/symbols/windows/netscan' / (name + '.json')).read_text())
        for family in (2, 23):
            for scenario in ('normal', 'wildcard', 'missing-local', 'invalid-family', 'invalid-state', 'null-owner', 'zero-time', 'missing-family'):
                data = bytearray(0x70000)
                table = copy.deepcopy(version['isf'])
                for key in ('base_types', 'user_types'):
                    table[key].update(owner[key])
                    table[key].update(index['kernel_isf'][key])
                scalar = lambda n: dict(kind='base', name=n)
                field = lambda at, ref: dict(offset=at, type=ref)
                aggregate = lambda size, fields: dict(kind='struct', size=size, fields=fields)
                for link in ('Flink', 'Blink'):
                    table['user_types']['_LIST_ENTRY']['fields'][link]['type'] = dict(kind='pointer', subtype=dict(kind='struct', name='_LIST_ENTRY'))
                table['base_types']['u16'] = dict(kind='int', size=2, signed=False, endian='little')
                table['user_types']['_UNICODE_STRING'] = aggregate(16, {'Length': field(0, scalar('u16')), 'Buffer': field(8, dict(kind='pointer', subtype=scalar('u16')))})
                table['user_types']['_KLDR_DATA_TABLE_ENTRY'] = aggregate(128, {
                    'InLoadOrderLinks': field(0, dict(kind='struct', name='_LIST_ENTRY')),
                    'DllBase': field(32, scalar('uptr')), 'SizeOfImage': field(40, scalar('uptr')),
                    'BaseDllName': field(48, dict(kind='struct', name='_UNICODE_STRING'))})
                table['symbols']['KdVersionBlock']['address'] = 0xc000
                table['symbols']['PsLoadedModuleList'] = {'address': 0xc000 + 0x1000}

                def write(at, raw):
                    assert 0 <= at and at + len(raw) <= len(data)
                    data[at:at + len(raw)] = raw

                def integer(at, value, size=width):
                    write(at, value.to_bytes(size, 'little'))

                for w in version['writes']:
                    write(w['offset'], bytes.fromhex(w['data']))
                write(0x1c000, bytes(data[0x1000:0x1100]))
                for w in index['writes']:
                    raw = bytes.fromhex(w['data'])
                    if len(raw) == width:
                        value = int.from_bytes(raw, 'little')
                        if 0x1000 <= value < 0x40000:
                            raw = (value + 0x30000).to_bytes(width, 'little')
                    write(w['offset'] + 0x30000, raw)
                for typ, destinations in [('_TCP_ENDPOINT', [0x50000, 0x51000]), ('_TCP_LISTENER', [0x52000, 0x53000]), ('_UDP_ENDPOINT', [0x54000])]:
                    obj = next(c for c in objects['cases'] if c['layout'] == name and c['type'] == typ and c['family'] == family and c['scenario'] == scenario)
                    fields = network['user_types'][typ]['fields']
                    for w in obj['writes']:
                        raw, at = bytes.fromhex(w['data']), w['offset']
                        # The old 0x20000 pointer must remain genuinely absent,
                        # despite the larger index fixture's mapped extent.
                        if at == 0x1000 + fields['InetAF']['offset'] and scenario == 'missing-family':
                            raw = (0x90000).to_bytes(width, 'little')
                        if scenario == 'missing-local' and int.from_bytes(raw, 'little') == 0x20000 and len(raw) == width:
                            raw = (0x90000).to_bytes(width, 'little')
                        if 0x1000 <= at < 0x2000:
                            for destination in destinations:
                                write(destination + at - 0x1000, raw)
                        else:
                            write(at, raw)
                integer(0x1d000, 0x1e000)
                integer(0x1d000 + width, 0x1e000)
                integer(0x1e000, 0x1d000)
                integer(0x1e000 + width, 0x1d000)
                integer(0x1e020, 0x30000)
                integer(0x1e028, 0x40000)
                integer(0x1e030, 18, 2)
                integer(0x1e038, 0x1f000)
                write(0x1f000, 'tcpip.sys'.encode('utf-16le'))
                # Actual resident PDB signature consumed by the unmodified
                # PDB scanner. Its matching data-only ISF is preseeded locally.
                write(0x30180, b'RSDS' + bytes.fromhex('42424242424242424242424242424242') + struct.pack('<I', 1) + b'tcpip.pdb\x00')
                driver = copy.deepcopy(index['tcpip_isf'])
                driver['metadata']['windows'] = {'pdb': {'database': 'tcpip.pdb', 'GUID': '42424242424242424242424242424242', 'age': 1, 'machine_type': 0x8664 if width == 8 else 0x14c}}
                results = []
                for corrupt in (False, True):
                    class Original(BufferDataLayer):
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
                    physical = Original(context, 'physical', 'physical', bytes(data))
                    physical.faults, physical.invalid_spans = [], []
                    context.layers.add_layer(physical)
                    context.config['memory.memory_layer'] = 'physical'
                    context.config['memory.page_map_offset'] = 0x8000
                    context.config['memory.kernel_virtual_offset'] = 0x10000
                    context.layers.add_layer(intel(context, 'memory', 'memory'))
                    with tempfile.TemporaryDirectory(prefix='gomem-netstat-generator-') as directory:
                        directory = Path(directory)
                        path = directory / 'kernel.json'
                        path.write_text(json.dumps(table))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), class_types={'_LIST_ENTRY': LIST_ENTRY, '_UNICODE_STRING': UNICODE_STRING, '_EPROCESS': EPROCESS}))
                        context.module('kernel', 'memory', 0x10000)
                        driver_path = directory / 'driver.json'
                        driver_path.write_text(json.dumps(driver))
                        old_cache = constants.CACHE_PATH
                        constants.CACHE_PATH = str(directory)
                        try:
                            cache = symbol_cache.SqliteCache(str(directory / constants.IDENTIFIERS_FILENAME))
                            identifier = symbol_cache.WindowsIdentifier.generate('tcpip.pdb', '42424242424242424242424242424242', 1)
                            cache._database.execute('INSERT INTO cache (location, identifier, operating_system, local) VALUES (?, ?, ?, ?)', (driver_path.as_uri(), identifier, 'windows', True))
                            cache._database.commit()
                            cache._database.close()
                            runner = SimpleNamespace(context=context, _context=context, config={'kernel': 'kernel'}, config_path='plugins.NetStat', get_tcpip_module=NetStat.get_tcpip_module, list_sockets=NetStat.list_sockets)
                            rows, failure = [], None
                            try:
                                for depth, row in NetStat._generator(runner, corrupt):
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
                            except (TypeError, ValueError) as error:
                                failure = dict(type=type(error).__name__, message=str(error))
                            results.append(dict(include_corrupt=corrupt, rows=rows, error=failure, read_faults=physical.faults, unavailable_checks=physical.invalid_spans))
                        finally:
                            constants.CACHE_PATH = old_cache
                writes = [dict(offset=at, data=data[at:at+256].hex()) for at in range(0, len(data), 256) if any(data[at:at+256])]
                cases.append(dict(arch=arch, layout=name, family=family, scenario=scenario, isf=table, driver_isf=driver, module_base=0x30000, kernel_base=0x10000, size=len(data), writes=writes, results=results))
    assert len(cases) == 48
    assert all(len(r['rows']) == 5 and not r['error'] for c in cases if c['scenario'] == 'normal' for r in c['results'])
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('complete NetStat oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print('48 paged allocations and 96 complete pinned NetStat generators verified')


if __name__ == '__main__':
    main()
