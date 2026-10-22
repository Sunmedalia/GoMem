#!/usr/bin/env python3
"""Run unmodified NetStat.list_sockets over original TCP/IP index layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-netstat-index-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.plugins.windows.netstat import NetStat

    cases, unsupported = [], []
    folder = source / 'volatility3/framework/symbols/windows/netscan'
    for path in sorted(folder.glob('*.json')):
        schema = json.loads(path.read_text())
        types = schema['user_types']
        required = [('_TCP_ENDPOINT', 'ListEntry'), ('_TCP_LISTENER', 'Next'), ('_UDP_ENDPOINT', 'Next'), ('_PARTITION_TABLE', 'Partitions')]
        missing = [t + '.' + f for t, f in required if f not in types.get(t, {}).get('fields', {})]
        if missing:
            unsupported.append(dict(layout=path.stem, missing=missing))
            continue
        width = schema['base_types']['pointer']['size']
        base = lambda name: dict(kind='base', name=name)
        field = lambda at, ref: dict(offset=at, type=ref)
        aggregate = lambda size, fields: dict(kind='struct', size=size, fields=fields)
        kernel = dict(metadata={'format': '6.2.0'}, symbols={}, enums={},
                      base_types={name: dict(kind='int', size=size, signed=False, endian='little')
                                  for name, size in [('pointer', width), ('u32', 4), ('uptr', width)]},
                      user_types={'_RTL_BITMAP': aggregate(width * 2, {'SizeOfBitMap': field(0, base('u32')), 'Buffer': field(width, base('uptr'))}),
                                  '_RTL_DYNAMIC_HASH_TABLE': aggregate(width * 3, {'NumEntries': field(0, base('u32')), 'Directory': field(width, base('uptr')), 'TableSize': field(width * 2, base('u32'))})})
        for mode in ('direct', 'compartment'):
            for scenario in ('normal', 'empty', 'duplicate', 'missing-bitmap', 'missing-hash', 'oversize-hash', 'oversize-bitmap', 'zero-partitions'):
                data = bytearray(0x40000)
                writes = []

                def write(at, value):
                    assert 0 <= at and at + len(value) <= len(data)
                    data[at:at + len(value)] = value
                    writes.append(dict(offset=at, data=value.hex()))

                def integer(at, value, size=width):
                    write(at, value.to_bytes(size, 'little'))

                def member(typ, name):
                    return types[typ]['fields'][name]

                def put(at, typ, name, value, size=width):
                    integer(at + member(typ, name)['offset'], value, size)

                symbols = {'PartitionTable': {'address': 0x100}, 'PartitionCount': {'address': 0x108}}
                integer(0x100, 0x1000)
                integer(0x108, 0 if scenario == 'zero-partitions' else 1, 1)
                part = 0x1000 + member('_PARTITION_TABLE', 'Partitions')['offset']
                put(part, '_PARTITION', 'Endpoints', 0x2000)
                integer(0x2000, 0 if scenario == 'empty' else 2, 4)
                integer(0x2000 + width, 0x80000 if scenario == 'missing-hash' else 0x3000)
                integer(0x2000 + width * 2, 4097 if scenario == 'oversize-hash' else 3, 4)
                alignment = width * 2
                inside = member('_TCP_ENDPOINT', 'ListEntry')['offset']
                integer(0x3000, 0x20000 + inside)
                integer(0x3000 + alignment, 0x3000 + alignment)
                integer(0x3000 + alignment * 2, (0x20000 if scenario == 'duplicate' else 0x21000) + inside)
                if mode == 'direct':
                    symbols.update(UdpPortPool={'address': 0x110}, TcpPortPool={'address': 0x118})
                    integer(0x110, 0x4000)
                    integer(0x118, 0x8000)
                else:
                    symbols.update(UdpCompartmentSet={'address': 0x110}, TcpCompartmentSet={'address': 0x118})
                    for slot, compartment, inet, protocol, pool in [(0x110, 0x16000, 0x17000, 0x18000, 0x4000), (0x118, 0x19000, 0x1a000, 0x1b000, 0x8000)]:
                        integer(slot, compartment)
                        put(compartment, '_INET_COMPARTMENT_SET', 'InetCompartment', inet)
                        put(inet, '_INET_COMPARTMENT', 'ProtocolCompartment', protocol)
                        put(protocol, '_PROTOCOL_COMPARTMENT', 'PortPool', pool)
                for pool, bitmap, assignment, big, typ, objects in [(0x4000, 0xc000, 0x10000, 0x12000, '_UDP_ENDPOINT', [0x24000]), (0x8000, 0xd000, 0x11000, 0x14000, '_TCP_LISTENER', [0x22000, 0x23000])]:
                    bitmap_at = pool + member('_INET_PORT_POOL', 'PortBitMap')['offset']
                    integer(bitmap_at, 81921 * 8 if scenario == 'oversize-bitmap' else 16, 4)
                    integer(bitmap_at + width, 0x80000 if scenario == 'missing-bitmap' else bitmap)
                    write(bitmap, bytes([0 if scenario == 'empty' else 0b101, 0]))  # port zero must be skipped
                    assignments_at = pool + member('_INET_PORT_POOL', 'PortAssignments')['offset']
                    integer(assignments_at, assignment)
                    put(assignment, '_PORT_ASSIGNMENT', 'InPaBigPoolBase', big)
                    array = member('_PORT_ASSIGNMENT_LIST', 'Assignments')
                    stride = types[array['type']['subtype']['name']]['size']
                    entry_at = big + array['offset'] + 2 * stride
                    next_offset = member(typ, 'Next')['offset']
                    put(entry_at, array['type']['subtype']['name'], 'Entry', (objects[0] + next_offset) | 3)
                    for i, at in enumerate(objects):
                        target = objects[i+1] + next_offset if i+1 < len(objects) else 0
                        put(at, typ, 'Next', target | (1 if target else 0))
                tcpip = dict(metadata={'format': '6.2.0'}, base_types=kernel['base_types'], user_types={}, enums={}, symbols=symbols)

                class Original(BufferDataLayer):
                    @property
                    def address_mask(self):
                        return (1 << (width * 8)) - 1

                    def read(self, offset, length, pad=False):
                        try:
                            return super().read(offset, length, pad)
                        except exceptions.InvalidAddressException:
                            self.faults.append(dict(offset=offset, length=length))
                            raise

                context = contexts.Context()
                layer = Original(context, 'original', 'original', bytes(data))
                layer.faults = []
                context.layers.add_layer(layer)
                with tempfile.TemporaryDirectory(prefix='gomem-netstat-index-') as directory:
                    for name, table in [('kernel', kernel), ('tcpip', tcpip)]:
                        local = Path(directory) / (name + '.json')
                        local.write_text(json.dumps(table))
                        context.symbol_space.append(IntermediateSymbolTable(context, name, name, local.as_uri()))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'network', 'network', path.resolve().as_uri(), table_mapping={'nt_symbols': 'kernel'}))
                    rows = [dict(address=int(obj.vol.offset), type=obj.vol.type_name.split('!')[-1]) for obj in
                            NetStat.list_sockets(context, 'original', 'kernel', 'network', 0, 'tcpip')]
                cases.append(dict(layout=path.stem, source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), width=width,
                                  mode=mode, scenario=scenario, kernel_isf=kernel, tcpip_isf=tcpip,
                                  size=len(data), writes=writes, rows=rows, read_faults=layer.faults))
    assert len(unsupported) == 9 and len(cases) == 256
    assert all(len(c['rows']) == 5 for c in cases if c['scenario'] == 'normal')
    return json.dumps(dict(commit=COMMIT, scope=__doc__, unsupported=unsupported, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('NetStat index oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print('256 actual NetStat.list_sockets controls and nine inapplicable schemas verified')


if __name__ == '__main__':
    main()
