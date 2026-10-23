#!/usr/bin/env python3
"""Run original Shimcache timestamps and execution flag properties on all layouts."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_shimcache_resource_oracle import kernel_layout

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winshimcache/testdata/temporal-oracle.json'
TIME_SCENARIOS = ['epoch', 'modified', 'updated', 'zero', 'maximum',
                  'high-bit', 'before-unix', 'out-of-range', 'modified-hole',
                  'update-hole', 'detail-hole', 'detail-zero',
                  'detail-high', 'detail-tail-hole', 'update-short-circuit']
FLAG_SCENARIOS = ['zero', 'bit-one', 'bit-two', 'bit-three', 'all', 'high-bit',
                  'insert-hole', 'blob-four', 'blob-zero', 'blob-short',
                  'blob-empty', 'blob-odd', 'blob-hole', 'blob-tail-hole',
                  'blob-unreachable-hole', 'detail-insert', 'detail-hole',
                  'detail-zero', 'detail-high', 'detail-blob-hole']


def field_kernel(width):
    kernel = kernel_layout(width, 0)
    for name, size, signed in [('unsigned char', 1, False), ('unsigned short', 2, False),
                               ('unsigned int', 4, False), ('unsigned long', 4, False),
                               ('long', 4, True), ('long long', 8, True),
                               ('unsigned long long', 8, False), ('wchar', 2, True)]:
        kernel['base_types'][name] = dict(kind='int', size=size, signed=signed, endian='little')
    kernel['user_types']['_LARGE_INTEGER'] = dict(kind='union', size=8, fields={
        'QuadPart': dict(offset=0, type=dict(kind='base', name='long long'))})
    return kernel


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import shimcache
    cases, kernels = [], {}
    with tempfile.TemporaryDirectory() as temporary:
        for path in sorted((source / 'volatility3/framework/symbols/windows/shimcache').glob('*.json')):
            doc = json.loads(path.read_text())
            width = doc['base_types']['pointer']['size']
            kernel = field_kernel(width)
            kernels[str(width)] = kernel
            kernel_path = Path(temporary) / 'kernel.json'
            kernel_path.write_text(json.dumps(kernel))
            fields = doc['user_types']['SHIM_CACHE_ENTRY']['fields']
            detail_fields = doc['user_types'].get('SHIM_CACHE_ENTRY_DETAIL', {}).get('fields', {})
            for mask in ([0xffffffff] if width == 4 else [0xffffffffffff, 0xffffffffffffffff]):
                for scenario in TIME_SCENARIOS + FLAG_SCENARIOS:
                    data, holes = bytearray(0x10000), []
                    at, detail_at = 0x1000, 0x4000
                    detail_pointer = at + fields['ListEntryDetail']['offset'] if 'ListEntryDetail' in fields else None
                    if detail_pointer is not None:
                        value = 0 if scenario == 'detail-zero' else detail_at | ((1 << (width*8-1)) if scenario == 'detail-high' else 0)
                        struct.pack_into('<Q' if width == 8 else '<I', data, detail_pointer, value)
                    modified_at = at + fields['LastModified']['offset'] if 'LastModified' in fields else detail_at + detail_fields['LastModified']['offset']
                    update_at = at + fields['LastUpdate']['offset'] if 'LastUpdate' in fields else None
                    stamps = {'epoch': 116444736000000000, 'modified': 116444736011234567,
                              'updated': 116444736022345678, 'zero': 0,
                              'maximum': (1 << 63)-1, 'high-bit': 1 << 63,
                              'before-unix': 116444735999999999,
                              'out-of-range': 2650467744000000000,
                              'detail-zero': 0, 'detail-high': 116444736000000001}
                    modified = stamps.get(scenario, stamps['modified'])
                    updated = stamps.get(scenario, stamps['updated'])
                    data[modified_at:modified_at+8] = modified.to_bytes(8, 'little')
                    if update_at is not None:
                        data[update_at:update_at+8] = updated.to_bytes(8, 'little')
                    flag_at = None
                    if 'InsertFlags' in fields:
                        flag_at = at + fields['InsertFlags']['offset']
                        value = {'zero': 0, 'bit-one': 1, 'bit-two': 2, 'bit-three': 3,
                                 'all': 0xffffffff, 'high-bit': 1 << 31}.get(scenario, 2)
                        struct.pack_into('<I', data, flag_at, value)
                    if 'InsertFlags' in detail_fields:
                        flag_at = detail_at + detail_fields['InsertFlags']['offset']
                        struct.pack_into('<I', data, flag_at, {'detail-insert': 2}.get(scenario, 1))
                    if 'BlobBuffer' in detail_fields:
                        blob_at = detail_at + detail_fields['BlobBuffer']['offset']
                        blob_size_at = detail_at + detail_fields['BlobSize']['offset']
                        blob_size = {'blob-zero': 0, 'blob-short': 3, 'blob-empty': 0,
                                     'blob-odd': 5}.get(scenario, 4)
                        blob_buffer = 0 if scenario == 'blob-unreachable-hole' else 0x6000
                        struct.pack_into('<Q' if width == 8 else '<I', data, blob_at, blob_buffer)
                        blob_type = kernel['base_types'][detail_fields['BlobSize']['type']['name']]
                        data[blob_size_at:blob_size_at+blob_type['size']] = blob_size.to_bytes(blob_type['size'], 'little')
                        data[0x6000:0x6008] = b'\x02\x00\x00\x00\x01\x00\x00\x00'
                    faults = {'modified-hole': (modified_at, 1) if scenario == 'modified-hole' else None, 'update-hole': (update_at, 1) if scenario == 'update-hole' and update_at is not None else None,
                              'detail-hole': (detail_at, 1) if scenario == 'detail-hole' else None, 'detail-tail-hole': (detail_at+1, 1) if scenario == 'detail-tail-hole' else None,
                              'insert-hole': (flag_at, 1) if scenario == 'insert-hole' and flag_at is not None else None,
                              'blob-hole': (0x6000, 1) if scenario == 'blob-hole' else None, 'blob-tail-hole': (0x6003, 1) if scenario == 'blob-tail-hole' else None,
                              'blob-unreachable-hole': (0x6000, 1) if scenario == 'blob-unreachable-hole' else None,
                              'detail-insert': (flag_at, 1) if scenario == 'detail-insert' and 'InsertFlags' in detail_fields and flag_at is not None else None,
                              'detail-blob-hole': (0x6000, 1) if scenario == 'detail-blob-hole' else None}
                    for fault in faults.values():
                        if fault is not None:
                            holes.append(fault)

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
                    kernel_table = IntermediateSymbolTable(context, 'kernel', 'kernel', kernel_path.as_uri())
                    context.symbol_space.append(kernel_table)
                    context.symbol_space.append(IntermediateSymbolTable(context, 'shim', 'shim', path.as_uri(), class_types=shimcache.class_types, native_types=kernel_table.natives, table_mapping={'nt_symbols': 'kernel'}))
                    def result(call):
                        try:
                            value = call()
                            if isinstance(value, interfaces.renderers.BaseAbsentValue):
                                return dict(missing=type(value).__name__)
                            if isinstance(value, bool):
                                return dict(bool=value)
                            if hasattr(value, 'isoformat'):
                                return dict(time=value.isoformat())
                            return dict(number=str(int(value)))
                        except exceptions.InvalidAddressException:
                            return dict(error='InvalidAddressException')
                    def original():
                        return context.object('shim!SHIM_CACHE_ENTRY', 'memory', at)
                    cases.append(dict(layout=path.stem, scenario=scenario, width=width, mask=hex(mask), at=at, size=len(data), holes=holes,
                                      last_modified=result(lambda: original().last_modified),
                                      last_update=result(lambda: original().last_update),
                                      exec_flag=result(lambda: original().exec_flag),
                                      writes=[dict(offset=offset, data=data[offset:offset+128].hex()) for offset in range(0, len(data), 128) if any(data[offset:offset+128])]))
    assert len(cases) == 595
    return json.dumps(dict(commit=COMMIT, scope=__doc__, kernels=kernels, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Shimcache temporal oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original Shimcache temporal/flag controls verified')


if __name__ == '__main__':
    main()
