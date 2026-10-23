#!/usr/bin/env python3
"""Run unmodified Shimcache handle validity and head properties on byte-backed controls."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_shimcache_resource_oracle import kernel_layout

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winshimcache/testdata/handle-oracle.json'
SCENARIOS = ['normal', 'handle-zero', 'resource-zero', 'table-zero',
             'resource-high', 'table-high', 'parent-high', 'allocate-high',
             'resource-backlink-high', 'waiters-masked-zero-hole',
             'handle-hole', 'resource-pointer-hole', 'table-pointer-hole',
             'resource-hole', 'waiter-hole', 'waiter-span-hole',
             'resource-same-links', 'resource-backlink-wrong', 'resource-count',
             'resource-forward-hole', 'resource-backward-hole',
             'table-target-hole', 'table-parent-wrong', 'allocate-before',
             'compare-after', 'free-hole', 'head-flink-zero', 'head-blink-zero',
             'head-same-links', 'head-forward-hole', 'head-blink-hole',
             'head-backward-target-hole', 'head-forward-target-hole',
             'head-forward-member-hole', 'head-wrong-backlink']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols import native
    from volatility3.framework.symbols.windows.extensions import ERESOURCE, shimcache
    cases, kernels = [], {}
    with tempfile.TemporaryDirectory() as temporary:
        for path in sorted((source / 'volatility3/framework/symbols/windows/shimcache').glob('*.json')):
            doc = json.loads(path.read_text())
            if 'ListEntry' not in doc['user_types']['SHIM_CACHE_ENTRY']['fields']:
                continue
            width = doc['base_types']['pointer']['size']
            kernel = kernel_layout(width, 0)
            kernels[str(width)] = kernel
            kernel_path = Path(temporary) / 'kernel.json'
            kernel_path.write_text(json.dumps(kernel))
            handle_fields = doc['user_types']['SHIM_CACHE_HANDLE']['fields']
            table_fields = doc['user_types']['_RTL_AVL_TABLE']['fields']
            table_size = doc['user_types']['_RTL_AVL_TABLE']['size']
            parent_offset = table_fields['BalancedRoot']['offset'] + doc['user_types']['_RTL_BALANCED_LINKS']['fields']['Parent']['offset']
            list_offset = doc['user_types']['SHIM_CACHE_ENTRY']['fields']['ListEntry']['offset']
            for mask in ([0xffffffff] if width == 4 else [0xffffffffffff, 0xffffffffffffffff]):
                for scenario in SCENARIOS:
                    data, holes = bytearray(0x10000), []
                    at = 0 if scenario == 'handle-zero' else 0x1000
                    resource_at = 0 if scenario == 'resource-zero' else 0x2000
                    table_at = 0 if scenario == 'table-zero' else 0x4000
                    head_at = table_at + table_size
                    member = head_at + list_offset
                    high = 1 << (width * 8 - 1)
                    def put(offset, value):
                        struct.pack_into('<Q' if width == 8 else '<I', data, offset, value)
                    put(at + handle_fields['eresource']['offset'], resource_at | (high if scenario == 'resource-high' else 0))
                    put(at + handle_fields['rtl_avl_table']['offset'], table_at | (high if scenario == 'table-high' else 0))
                    put(resource_at, 0xa000)
                    put(resource_at + width, 0xa000 if scenario == 'resource-same-links' else 0xb000)
                    put(resource_at + 64, high if scenario == 'waiters-masked-zero-hole' else 0xc000)
                    put(0xa000 + width, resource_at + 1 if scenario == 'resource-backlink-wrong' else resource_at | (high if scenario == 'resource-backlink-high' else 0))
                    put(0xb000, resource_at)
                    struct.pack_into('<I', data, resource_at + 112, int(scenario == 'resource-count'))
                    root = table_at + table_fields['BalancedRoot']['offset']
                    put(table_at + parent_offset, root + 1 if scenario == 'table-parent-wrong' else root | (high if scenario == 'parent-high' else 0))
                    for name, value in [('AllocateRoutine', 0x8020), ('CompareRoutine', 0x8040), ('FreeRoutine', 0x8060)]:
                        if name == 'AllocateRoutine':
                            value = 0x7fff if scenario == 'allocate-before' else value | (high if scenario == 'allocate-high' else 0)
                        if name == 'CompareRoutine' and scenario == 'compare-after':
                            value = 0x9001
                        put(table_at + table_fields[name]['offset'], value)
                    put(member, 0 if scenario == 'head-flink-zero' else 0x6000)
                    put(member + width, 0 if scenario == 'head-blink-zero' else 0x6000 if scenario == 'head-same-links' else 0x7000)
                    put(0x6000 + width, 0x4321 if scenario == 'head-wrong-backlink' else head_at)
                    faults = {'handle-hole': (at, 1),
                              'resource-pointer-hole': (at + handle_fields['eresource']['offset'], width),
                              'table-pointer-hole': (at + handle_fields['rtl_avl_table']['offset'], width),
                              'resource-hole': (resource_at, 1), 'waiter-hole': (resource_at + 64, width),
                              'waiter-span-hole': (resource_at + 64 + width, 1),
                              'waiters-masked-zero-hole': (resource_at + 64 + width, 1),
                              'resource-forward-hole': (0xa000 + width, width), 'resource-backward-hole': (0xb000, width),
                              'table-target-hole': (table_at, 1), 'free-hole': (table_at + table_fields['FreeRoutine']['offset'], width),
                              'head-forward-hole': (member, width), 'head-blink-hole': (member + width, width),
                              'head-backward-target-hole': (0x7000, width), 'head-forward-target-hole': (0x6000, width),
                              'head-forward-member-hole': (0x6000 + width, width)}
                    if scenario in faults:
                        holes.append(faults[scenario])

                    class OriginalLayer(BufferDataLayer):
                        @property
                        def address_mask(self):
                            return mask

                        def is_valid(self, offset, length=1):
                            return super().is_valid(offset, length) and not any(offset < start + size and start < offset + length for start, size in holes)

                        def read(self, offset, length, pad=False):
                            if not self.is_valid(offset, length):
                                raise exceptions.InvalidAddressException(self.name, offset)
                            return super().read(offset, length, pad)

                    context = contexts.Context()
                    context.layers.add_layer(OriginalLayer(context, 'memory', 'memory', bytes(data)))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', kernel_path.as_uri(), class_types={'_ERESOURCE': ERESOURCE}))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'shim', 'shim', path.as_uri(), class_types=shimcache.class_types, native_types=native.x64NativeTable if width == 8 else native.x86NativeTable, table_mapping={'nt_symbols': 'kernel'}))
                    def result(call):
                        try:
                            value = call()
                            return dict(value=value, error=None)
                        except exceptions.InvalidAddressException:
                            return dict(value=None, error='InvalidAddressException')
                    def original():
                        return context.object('shim!SHIM_CACHE_HANDLE', 'memory', at)
                    def head():
                        value = original().head
                        return value.vol.offset if value is not None else None
                    cases.append(dict(layout=path.stem, scenario=scenario, width=width, mask=hex(mask), at=at, page_start=0x8000, page_end=0x9000, size=len(data), holes=holes,
                                      valid=result(lambda: original().is_valid(0x8000, 0x9000)), head=result(head),
                                      writes=[dict(offset=offset, data=data[offset:offset+128].hex()) for offset in range(0, len(data), 128) if any(data[offset:offset+128])]))
    assert len(cases) == 525
    return json.dumps(dict(commit=COMMIT, scope=__doc__, kernels=kernels, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Shimcache handle oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original Shimcache handle/head controls verified')


if __name__ == '__main__':
    main()
