#!/usr/bin/env python3
"""Run original Shimcache path and size properties on all twelve shipped layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_shimcache_resource_oracle import kernel_layout

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winshimcache/testdata/fields-oracle.json'
SCENARIOS = ['normal', 'embedded-nul', 'replacement', 'surrogate-pair',
             'high-surrogate', 'low-surrogate', 'high-odd-tail', 'odd-byte',
             'bom-le', 'bom-be', 'empty', 'full-inline', 'maximum-length',
             'length-hole', 'pointer-hole', 'maximum-length-hole', 'buffer-hole',
             'buffer-tail-hole', 'pointer-high', 'pointer-null', 'length-zero',
             'null-length-zero', 'inline-tail-hole', 'size-zero', 'size-one',
             'size-negative', 'size-maximum', 'size-hole', 'size-big']


def field_kernel(width):
    kernel = kernel_layout(width, 0)
    for name, size, signed in [('unsigned char', 1, False), ('unsigned short', 2, False),
                               ('unsigned int', 4, False), ('unsigned long', 4, False),
                               ('long', 4, True), ('long long', 8, True),
                               ('unsigned long long', 8, False), ('wchar', 2, True)]:
        kernel['base_types'][name] = dict(kind='int', size=size, signed=signed, endian='little')
    kernel['user_types']['_UNICODE_STRING'] = dict(kind='struct', size=16 if width == 8 else 8, fields={
        'Length': dict(offset=0, type=dict(kind='base', name='unsigned short')),
        'MaximumLength': dict(offset=2, type=dict(kind='base', name='unsigned short')),
        'Buffer': dict(offset=8 if width == 8 else 4, type=dict(kind='pointer', subtype=dict(kind='base', name='wchar')))})
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
            inline = fields['Path']['type']['kind'] == 'array'
            for mask in ([0xffffffff] if width == 4 else [0xffffffffffff, 0xffffffffffffffff]):
                for scenario in SCENARIOS:
                    data, holes = bytearray(0x20000), []
                    at, buffer = 0x1000, 0x4000
                    descriptor = at + fields['Path']['offset']
                    raw = {
                        'embedded-nul': 'a\0b'.encode('utf-16le'), 'replacement': 'a\ufffdb'.encode('utf-16le'),
                        'surrogate-pair': 'a\U0001f600b'.encode('utf-16le'),
                        'high-surrogate': bytes.fromhex('610000d86200'),
                        'low-surrogate': bytes.fromhex('610000dc6200'),
                        'high-odd-tail': bytes.fromhex('610000d812'), 'odd-byte': bytes.fromhex('610012'),
                        'bom-le': bytes.fromhex('fffe61006200'), 'bom-be': bytes.fromhex('feff00610062'),
                        'empty': b'', 'full-inline': b'Q\0'*260, 'maximum-length': bytes(65535)
                    }.get(scenario, 'C:\\demo.exe'.encode('utf-16le'))
                    if inline:
                        buffer = descriptor
                        raw = raw[:520]
                        data[buffer:buffer+len(raw)] = raw
                    else:
                        data[buffer:buffer+len(raw)] = raw
                        pointer_offset = descriptor + kernel['user_types']['_UNICODE_STRING']['fields']['Buffer']['offset']
                        pointer = 0 if scenario in ('pointer-null', 'null-length-zero') else buffer | ((1 << (width*8-1)) if scenario == 'pointer-high' else 0)
                        struct.pack_into('<Q' if width == 8 else '<I', data, pointer_offset, pointer)
                        length = 0 if scenario in ('length-zero', 'null-length-zero') else len(raw)
                        struct.pack_into('<HH', data, descriptor, length, 0)
                        fault = {'length-hole': (descriptor, 2), 'pointer-hole': (pointer_offset, width),
                                 'maximum-length-hole': (descriptor + 2, 2)}.get(scenario)
                        if fault is not None:
                            holes.append(fault)
                    size_at = None
                    if 'FileSize' in fields:
                        size = fields['FileSize']
                        native = kernel['base_types'][size['type']['name']]
                        value = {'size-zero': 0, 'size-one': 1, 'size-negative': -1,
                                 'size-maximum': (1 << (native['size']*8)) - 1, 'size-big': (1 << 53) + 17}.get(scenario, 123456789)
                        size_at = at + size['offset']
                        data[size_at:size_at+native['size']] = (value & ((1 << (native['size']*8))-1)).to_bytes(native['size'], 'little')
                    length = 520 if inline else len(raw)
                    fault = {'buffer-hole': (buffer, 1), 'buffer-tail-hole': (buffer + max(0,length-1), 1),
                             'inline-tail-hole': (descriptor + 519, 1) if inline else None,
                             'size-hole': (size_at, 1) if size_at is not None else None}.get(scenario)
                    if fault is not None:
                        holes.append(fault)

                    class OriginalLayer(BufferDataLayer):
                        @property
                        def address_mask(self):
                            return mask

                        def read(self, offset, length, pad=False):
                            if any(offset < start + size and start < offset + length for start, size in holes):
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
                            if isinstance(value, str):
                                return dict(string=value) if len(value) < 1024 else dict(string_sha256=hashlib.sha256(value.encode()).hexdigest(), string_length=len(value))
                            return dict(number=str(int(value)))
                        except exceptions.InvalidAddressException:
                            return dict(error='InvalidAddressException')
                    def original():
                        return context.object('shim!SHIM_CACHE_ENTRY', 'memory', at)
                    cases.append(dict(layout=path.stem, scenario=scenario, width=width, mask=hex(mask), at=at, size=len(data), inline=inline, holes=holes,
                                      path=result(lambda: original().file_path), file_size=result(lambda: original().file_size),
                                      writes=[dict(offset=offset, data=data[offset:offset+128].hex()) for offset in range(0, len(data), 128) if any(data[offset:offset+128])]))
    assert len(cases) == 493
    return json.dumps(dict(commit=COMMIT, scope=__doc__, kernels=kernels, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Shimcache path/size oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original Shimcache path/size controls verified')


if __name__ == '__main__':
    main()
