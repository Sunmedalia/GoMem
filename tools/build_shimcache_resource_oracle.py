#!/usr/bin/env python3
"""Exercise the original ERESOURCE validator with synthetic kernel layouts and real bytes."""
import argparse
import json
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winshimcache/testdata/resource-oracle.json'
SCENARIOS = ['normal', 'resource-zero', 'waiter-unmapped-target', 'waiter-zero',
             'same-links', 'null-forward', 'null-backward', 'null-both',
             'wrong-backlink', 'wrong-forwardlink', 'embedded-backlinks',
             'shared-count', 'resource-hole', 'waiter-hole', 'waiter-span-hole',
             'forward-hole', 'backward-hole', 'forward-target-hole',
             'backward-target-hole', 'count-hole', 'unreachable-count-hole']


def kernel_layout(width, list_offset):
    # Synthetic types deliberately vary embedding; these are method controls,
    # not claims of support for a particular Windows kernel version.
    pointer = lambda name: dict(kind='pointer', subtype=dict(kind='struct', name=name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    doc = dict(metadata=dict(format='6.2.0', producer=dict(name='GoMem synthetic kernel control', version='1.0.0', datetime='2026-10-23T00:00:00Z')),
                base_types={name: dict(kind='int', size=size, signed=False, endian='little') for name, size in [('pointer', width), ('unsigned int', 4)]},
                user_types={
                    '_ERESOURCE': dict(kind='struct', size=128, fields={
                        'SystemResourcesList': field(list_offset, dict(kind='struct', name='_LIST_ENTRY')),
                        'SharedWaiters': field(64, pointer('_KSEMAPHORE')),
                        'NumberOfSharedWaiters': field(112, dict(kind='base', name='unsigned int'))}),
                    '_LIST_ENTRY': dict(kind='struct', size=2*width, fields={'Flink': field(0, pointer('_LIST_ENTRY')), 'Blink': field(width, pointer('_LIST_ENTRY'))}),
                    '_KSEMAPHORE': dict(kind='struct', size=32, fields={})}, symbols={}, enums={})
    if list_offset == 0:
        doc['base_types']['void'] = dict(kind='void', size=0, signed=True, endian='little')
        doc['user_types']['_ERESOURCE']['fields']['SharedWaiters']['type']['subtype'] = dict(kind='base', name='void')
    return doc


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import ERESOURCE
    cases, layouts = [], {}
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        for width in (4, 8):
            for list_offset in (0, 16):
                name = f'w{width}-list{list_offset}'
                doc = kernel_layout(width, list_offset)
                layouts[name] = doc
                path = Path(temporary) / (name + '.json')
                path.write_text(json.dumps(doc))
                for scenario in SCENARIOS:
                    data, holes = bytearray(0x10000), []
                    at = 0 if scenario == 'resource-zero' else 0x1000
                    fmt = '<Q' if width == 8 else '<I'
                    def put(offset, value):
                        struct.pack_into(fmt, data, offset, value)
                    flink, blink = 0x2000, 0x3000
                    if scenario == 'same-links':
                        blink = flink
                    if scenario in ('null-forward', 'null-both'):
                        flink = 0
                    if scenario in ('null-backward', 'null-both'):
                        blink = 0
                    put(at + list_offset, flink)
                    put(at + list_offset + width, blink)
                    # Original does not test SharedWaiters' target mapping.
                    put(at + 64, 0 if scenario == 'waiter-zero' else 0x20000)
                    put(flink + width, at + list_offset if scenario == 'embedded-backlinks' else at + 1 if scenario == 'wrong-backlink' else at)
                    put(blink, at + 1 if scenario == 'wrong-forwardlink' else at)
                    struct.pack_into('<I', data, at + 112, int(scenario == 'shared-count'))
                    faults = {'resource-hole': (at, 1), 'waiter-hole': (at + 64, width),
                              'waiter-span-hole': (at + 64 + width, 1),
                              'forward-hole': (at + list_offset, width),
                              'backward-hole': (at + list_offset + width, width),
                              'forward-target-hole': (flink + width, width),
                              'backward-target-hole': (blink, width),
                              'count-hole': (at + 112, 4), 'unreachable-count-hole': (at + 112, 4)}
                    if scenario == 'unreachable-count-hole':
                        put(at + list_offset + width, flink)
                    if scenario in faults:
                        holes.append(faults[scenario])

                    class OriginalLayer(BufferDataLayer):
                        @property
                        def address_mask(self):
                            return (1 << (width * 8)) - 1

                        def is_valid(self, offset, length=1):
                            return super().is_valid(offset, length) and not any(offset < start + size and start < offset + length for start, size in holes)

                        def read(self, offset, length, pad=False):
                            if not self.is_valid(offset, length):
                                raise exceptions.InvalidAddressException(self.name, offset)
                            return super().read(offset, length, pad)

                    context = contexts.Context()
                    context.layers.add_layer(OriginalLayer(context, 'memory', 'memory', bytes(data)))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', path.as_uri(), class_types={'_ERESOURCE': ERESOURCE}))
                    try:
                        valid = context.object('kernel!_ERESOURCE', 'memory', at).is_valid()
                        error = None
                    except exceptions.InvalidAddressException:
                        valid, error = False, 'InvalidAddressException'
                    cases.append(dict(layout=name, scenario=scenario, at=at, size=len(data), holes=holes, valid=valid, error=error,
                                      writes=[dict(offset=offset, data=data[offset:offset+128].hex()) for offset in range(0, len(data), 128) if any(data[offset:offset+128])]))
    assert len(cases) == 84
    return json.dumps(dict(commit=COMMIT, scope=__doc__, layouts=layouts, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Shimcache resource oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original ERESOURCE controls verified')


if __name__ == '__main__':
    main()
