#!/usr/bin/env python3
"""Exercise actual pinned network object methods on original byte-backed layouts.

This is development-only preparation for native NetScan/NetStat. It does not
implement either plugin or establish pool acquisition or version-selection parity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-network-object-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import EPROCESS
    from volatility3.framework.symbols.windows.extensions import network

    def scalar(name):
        return dict(kind='base', name=name)

    def field(offset, typ):
        return dict(offset=offset, type=typ)

    def structure(size, fields):
        return dict(kind='struct', size=size, fields=fields)

    cases, layouts = [], []
    folder = source / 'volatility3/framework/symbols/windows/netscan'
    scenarios = ('normal', 'wildcard', 'missing-local', 'invalid-family',
                 'invalid-state', 'null-owner', 'zero-time', 'missing-family')
    for path in sorted(folder.glob('*.json')):
        raw = path.read_bytes()
        schema = json.loads(raw)
        width = schema['base_types']['pointer']['size']

        class FullAddressBuffer(BufferDataLayer):
            # BufferDataLayer otherwise derives a 16-bit mask from this small
            # buffer and turns intended 0x20000 faults into readable nulls.
            @property
            def address_mask(self):
                return (1 << (width * 8)) - 1

            def read(self, offset, length, pad=False):
                try:
                    return super().read(offset, length, pad)
                except exceptions.InvalidAddressException:
                    self.faults.append(dict(offset=offset, length=length))
                    raise

        kernel = dict(metadata={'format': '6.2.0'}, symbols={}, enums={},
                      base_types={name: dict(kind='int', size=size, signed=False, endian='little')
                                  for name, size in [('pointer', width), ('uptr', width), ('u8', 1), ('u64', 8)]},
                      user_types={
                          '_LARGE_INTEGER': structure(8, {'QuadPart': field(0, scalar('u64'))}),
                          '_LIST_ENTRY': structure(width * 2, {'Flink': field(0, scalar('uptr')), 'Blink': field(width, scalar('uptr'))}),
                          '_KPROCESS': structure(width, {'DirectoryTableBase': field(0, scalar('uptr'))}),
                          '_EPROCESS': structure(128, {
                              'UniqueProcessId': field(0, scalar('uptr')),
                              'ImageFileName': field(8, dict(kind='array', count=16, subtype=scalar('u8'))),
                              'CreateTime': field(24, dict(kind='struct', name='_LARGE_INTEGER')),
                              'ExitTime': field(32, dict(kind='struct', name='_LARGE_INTEGER')),
                              'Pcb': field(40, dict(kind='struct', name='_KPROCESS')),
                              'ThreadListHead': field(48, dict(kind='struct', name='_LIST_ENTRY'))})})
        layouts.append(dict(name=path.stem, source_sha256=hashlib.sha256(raw).hexdigest(), width=width,
                            declared_sizes={n: t['size'] for n, t in schema['user_types'].items()}))
        for typ in ('_TCP_LISTENER', '_TCP_ENDPOINT', '_UDP_ENDPOINT'):
            for family in (2, 23):
                for scenario in scenarios:
                    data = bytearray(0x10000)
                    writes = []

                    def write(at, value):
                        if at < 0 or at + len(value) > len(data):
                            raise ValueError('fixture write outside original buffer')
                        data[at:at + len(value)] = value
                        writes.append(dict(offset=at, data=value.hex()))

                    def integer(at, value, size=width, endian='little'):
                        write(at, int(value).to_bytes(size, endian))

                    def offset(name, member):
                        return schema['user_types'][name]['fields'][member]['offset']

                    def pointer(member, value):
                        integer(0x1000 + offset(typ, member), value)

                    pointer('InetAF', 0x20000 if scenario == 'missing-family' else 0x2000)
                    integer(0x2000 + offset('_INETAF', 'AddressFamily'),
                            255 if scenario == 'invalid-family' else family, 2)
                    pointer('Owner', 0 if scenario == 'null-owner' else 0x6000)
                    integer(0x6000, 4)
                    write(0x6008, b'System')
                    integer(0x6028, 0x8000)
                    integer(0x6030, 0x80001000)
                    integer(0x6030 + width, 0x80001000)
                    integer(0x1000 + offset(typ, 'CreateTime'),
                            0 if scenario == 'zero-time' else 133801632000000000, 8)
                    if typ == '_TCP_ENDPOINT':
                        pointer('AddrInfo', 0x7000)
                        integer(0x7000 + offset('_ADDRINFO', 'Local'), 0x3000)
                        integer(0x7000 + offset('_ADDRINFO', 'Remote'), 0x5100)
                        integer(0x1000 + offset(typ, 'LocalPort'), 49152, 2, 'big')
                        integer(0x1000 + offset(typ, 'RemotePort'), 443, 2, 'big')
                        enum_name = schema['user_types'][typ]['fields']['State']['type']['name']
                        integer(0x1000 + offset(typ, 'State'), 255 if scenario == 'invalid-state' else 4,
                                schema['enums'][enum_name]['size'])
                        address_type = '_LOCAL_ADDRESS'
                    else:
                        pointer('LocalAddr', 0x3000)
                        integer(0x1000 + offset(typ, 'Port'), 5353, 2, 'big')
                        address_type = schema['user_types'][typ]['fields']['LocalAddr']['type']['subtype']['name']
                    address_field = schema['user_types'][address_type]['fields']['pData']
                    target = 0 if scenario == 'wildcard' else 0x20000 if scenario == 'missing-local' else 0x5000
                    if address_field['type']['subtype']['kind'] == 'pointer':
                        integer(0x3000 + address_field['offset'], 0x4000)
                        integer(0x4000, target)
                    else:
                        integer(0x3000 + address_field['offset'], target)
                    write(0x5000, bytes.fromhex('20010db8000000000000000000000001') if family == 23 else bytes([10, 2, 3, 4]) + bytes(12))
                    write(0x5100, bytes.fromhex('20010db8000000000000000000000002') if family == 23 else bytes([192, 0, 2, 9]) + bytes(12))
                    context = contexts.Context()
                    layer = FullAddressBuffer(context, 'physical', 'physical', bytes(data))
                    layer.faults = []
                    context.layers.add_layer(layer)
                    with tempfile.TemporaryDirectory(prefix='gomem-network-oracle-') as directory:
                        kernel_path = Path(directory) / 'kernel.json'
                        kernel_path.write_text(json.dumps(kernel))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'kernel_symbols', 'kernel', kernel_path.as_uri(), class_types={'_EPROCESS': EPROCESS}))
                        class_types = network.win10_x64_class_types if width == 8 and 'win10' in path.stem else network.class_types
                        context.symbol_space.append(IntermediateSymbolTable(context, 'network_symbols', 'network', path.resolve().as_uri(), class_types=class_types, table_mapping={'nt_symbols': 'kernel'}))
                        obj = context.object('network!' + typ, layer_name='physical', offset=0x1000)

                        def observe(method):
                            try:
                                value = method()
                                if isinstance(value, interfaces.renderers.BaseAbsentValue):
                                    return dict(absent=type(value).__name__)
                                if hasattr(value, 'isoformat'):
                                    return value.isoformat()
                                if value is None or isinstance(value, (str, bool, list)):
                                    return value
                                return int(value)
                            except exceptions.InvalidAddressException:
                                return dict(error='InvalidAddressException')
                            except ValueError:
                                return dict(error='ValueError')
                            except AttributeError as error:
                                # Some shipped layouts are not selected by the
                                # version factory and lack a class extension.
                                # Keep this upstream failure explicit.
                                return dict(error='AttributeError', message=str(error))

                        observations = {name: observe(getattr(obj, method)) for name, method in
                                        [('valid', 'is_valid'), ('family', 'get_address_family'), ('pid', 'get_owner_pid'),
                                         ('owner', 'get_owner_procname'), ('created', 'get_create_time')]}
                        if typ == '_TCP_ENDPOINT':
                            observations.update(local=observe(obj.get_local_address), remote=observe(obj.get_remote_address),
                                                local_port=int(obj.LocalPort), remote_port=int(obj.RemotePort),
                                                state=observe(lambda: obj.State.description))
                        else:
                            observations.update(sockets=observe(lambda: list(obj.dual_stack_sockets())), port=int(obj.Port))
                    cases.append(dict(layout=path.stem, type=typ, family=family, scenario=scenario,
                                      size=len(data), object_offset=0x1000, writes=writes,
                                      read_faults=layer.faults,
                                      observations=observations))
    assert len(layouts) == 25 and len(cases) == 1200
    normal = [c for c in cases if c['scenario'] == 'normal']
    assert len(normal) == 150
    assert all(c['observations']['valid'] and c['observations']['pid'] == 4
               and c['observations']['owner'] == 'System' for c in normal)
    assert all(c['observations']['family'] == c['family'] for c in normal)
    assert all(c['observations']['created'] == '2025-01-01T00:00:00+00:00' for c in normal)
    assert all(not c['read_faults'] for c in normal)
    assert sum(bool(c['read_faults']) for c in cases) == 300
    assert all(c['observations']['family'] is None and c['read_faults']
               for c in cases if c['scenario'] == 'missing-family')
    assert all(c['observations']['local'] is None and c['read_faults']
               for c in cases if c['scenario'] == 'missing-local' and c['type'] == '_TCP_ENDPOINT')
    errors = [(c, key, value) for c in cases for key, value in c['observations'].items()
              if isinstance(value, dict) and 'error' in value]
    assert len(errors) == 64, [(c['layout'], c['scenario'], key, value) for c, key, value in errors]
    assert all((value['error'] == 'ValueError' and key == 'state'
                and c['scenario'] == 'invalid-state')
               or (value['error'] == 'AttributeError' and key == 'sockets'
                   and c['layout'] == 'netscan-win10-19041-x86'
                   and c['type'] == '_UDP_ENDPOINT') for c, key, value in errors)
    return json.dumps(dict(commit=COMMIT, scope=__doc__, layouts=layouts, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('network object oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print('25 original layouts and 1200 byte-backed network object cases verified')


if __name__ == '__main__':
    main()
