#!/usr/bin/env python3
"""Run actual pinned callback object processors and x86 shutdown validity on separate source/native layers."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-callback-object-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import DEVICE_OBJECT, DRIVER_OBJECT, LIST_ENTRY, UNICODE_STRING
    from volatility3.framework.symbols.windows.extensions.pool import OBJECT_HEADER
    from volatility3.framework.symbols.windows.extensions import callbacks
    from volatility3.plugins.windows.callbacks import Callbacks

    layouts, cases = [], []
    for width in (4, 8):
        source_path = source / 'volatility3/framework/symbols/windows' / ('callbacks-x64.json' if width == 8 else 'callbacks-x86.json')
        callback_isf = json.loads(source_path.read_text())
        for header_mode in ('legacy-type', 'index', 'encoded-index'):
            b = lambda name: dict(kind='base', name=name)
            s = lambda name: dict(kind='struct', name=name)
            p = lambda name: dict(kind='pointer', subtype=s(name))
            field = lambda at, ref: dict(offset=at, type=ref)
            aggregate = lambda size, fields: dict(kind='struct', size=size, fields=fields)
            fields = {'Body': field(0x20, b('unsigned char')), 'NameInfoOffset': field(width if header_mode == 'legacy-type' else 1, b('unsigned char'))}
            fields['Type' if header_mode == 'legacy-type' else 'TypeIndex'] = field(0, p('_OBJECT_TYPE') if header_mode == 'legacy-type' else b('unsigned char'))
            kernel = dict(metadata={'format': '6.2.0'}, base_types=copy.deepcopy(callback_isf['base_types']), enums={},
                user_types={'_LIST_ENTRY': aggregate(2 * width, {'Flink': field(0, p('_LIST_ENTRY')), 'Blink': field(width, p('_LIST_ENTRY'))}),
                            '_UNICODE_STRING': aggregate(2 * width, {'Length': field(0, b('unsigned short')), 'Buffer': field(width, dict(kind='pointer', subtype=b('unsigned short')))}),
                            '_DRIVER_OBJECT': aggregate(0x100, {'DriverStart': field(0, b('pointer')), 'DriverName': field(0x10, s('_UNICODE_STRING')), 'MajorFunction': field(0x20, dict(kind='array', count=28, subtype=dict(kind='pointer', subtype=b('void'))))}),
                            '_DEVICE_OBJECT': aggregate(0x40, {'DriverObject': field(8, p('_DRIVER_OBJECT'))}),
                            '_OBJECT_HEADER': aggregate(0x40, fields),
                            '_OBJECT_HEADER_NAME_INFO': aggregate(0x20, {'Name': field(0, s('_UNICODE_STRING'))}),
                            '_OBJECT_TYPE': aggregate(0x20, {'Name': field(0, s('_UNICODE_STRING'))})},
                symbols={'ObHeaderCookie': dict(address=0x9000)})
            # Native pointer templates require a subtype; integer addresses are words.
            kernel['base_types']['word'] = dict(kind='int', size=width, signed=False, endian='little')
            kernel['user_types']['_DRIVER_OBJECT']['fields']['DriverStart']['type'] = b('word')
            layout_index = len(layouts)
            layouts.append(dict(width=width, header_mode=header_mode, kernel_isf=kernel, callback_isf=callback_isf, source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest()))
            for typ in ('_SHUTDOWN_PACKET', '_NOTIFICATION_PACKET', '_GENERIC_CALLBACK', '_DBGPRINT_CALLBACK', '_NOTIFY_ENTRY_HEADER'):
                for scenario in ('normal', 'empty-name', 'bad-name', 'bad-driver', 'invalid-category', 'wrong-type', 'misaligned-start', 'null-device', 'bad-link', 'zero-callback', 'no-name-info', 'bad-field'):
                    allocation, native = bytearray(0xa000), bytearray(0xa000)
                    def put(data, at, value, size=width): data[at:at + size] = value.to_bytes(size, 'little')
                    def unicode(at, buffer, text):
                        raw = text.encode('utf-16-le')
                        put(native, at, len(raw), 2); put(native, at + width, buffer)
                        native[buffer:buffer + len(raw)] = raw
                    def member(name): return callback_isf['user_types'][typ]['fields'][name]['offset']
                    def header(at, index):
                        if header_mode == 'legacy-type': put(native, at, 0x7000 + (index - 1) * 0x100)
                        else:
                            value = index ^ (at >> 8) ^ 0x5a if header_mode == 'encoded-index' else index
                            put(native, at, value & 0xff, 1)
                        put(native, at + (width if header_mode == 'legacy-type' else 1), 0 if scenario == 'no-name-info' else 0x20, 1)
                    header(0x3fe0, 3 if scenario == 'wrong-type' else 1)
                    header(0x2fe0, 3 if scenario == 'wrong-type' else 2)
                    put(native, 0x9000, 0x5a, 4)
                    put(native, 0x3008, 0x50000 if scenario == 'bad-driver' else 0x4000)
                    put(native, 0x4000, 0x8001 if scenario == 'misaligned-start' else 0x8000)
                    put(native, 0x4020 + 16 * width, 0 if scenario == 'zero-callback' else 0x8800)
                    unicode(0x4010, 0x6000, '' if scenario == 'empty-name' else r'\Driver\body')
                    unicode(0x3fc0, 0x6200, '' if scenario == 'empty-name' else r'\Driver\header')
                    if scenario == 'bad-name':
                        put(native, 0x4010 + width, 0x50000); put(native, 0x3fc0 + width, 0x50000)
                    for i, name in enumerate(('Driver', 'Device', 'File')): unicode(0x7000 + i * 0x100, 0x6500 + i * 0x100, name)
                    address = 0 if scenario == 'zero-callback' else 0x8800
                    callback_field = {'_GENERIC_CALLBACK': 'Callback', '_NOTIFICATION_PACKET': 'NotificationRoutine', '_DBGPRINT_CALLBACK': 'Function', '_NOTIFY_ENTRY_HEADER': 'CallbackRoutine'}.get(typ)
                    if callback_field:
                        size = 4 if width == 4 and typ in ('_NOTIFICATION_PACKET', '_NOTIFY_ENTRY_HEADER') else width
                        put(allocation, 0x1000 + member(callback_field), address, size)
                    if typ == '_SHUTDOWN_PACKET':
                        put(allocation, 0x1000, 0x50000 if scenario == 'bad-link' else 0x2000)
                        put(allocation, 0x1000 + width, 0x2000)
                        put(allocation, 0x1000 + member('DeviceObject'), 0 if scenario == 'null-device' else 0x3000)
                    if typ == '_NOTIFY_ENTRY_HEADER':
                        put(allocation, 0x1000 + member('EventCategory'), 7 if scenario == 'invalid-category' else 2, 4)
                        put(allocation, 0x1000 + member('DriverObject'), 0x50000 if scenario == 'bad-driver' else 0x4000)
                    holes = [(0x1000 + (member(callback_field) if callback_field else member('DeviceObject')), width)] if scenario == 'bad-field' else []
                    context = contexts.Context()
                    class SourceLayer(BufferDataLayer):
                        @property
                        def address_mask(self): return (1 << (width * 8)) - 1
                        def read(self, at, length, pad=False):
                            from volatility3.framework import exceptions
                            if self.name == 'allocation' and any(at < start + size and start < at + length for start, size in holes):
                                raise exceptions.InvalidAddressException(self.name, at)
                            return super().read(at, length, pad)
                        def is_valid(self, at, length=1):
                            return not (self.name == 'allocation' and any(at < start + size and start < at + length for start, size in holes)) and super().is_valid(at, length)
                    context.layers.add_layer(SourceLayer(context, 'allocation', 'allocation', bytes(allocation)))
                    context.layers.add_layer(SourceLayer(context, 'kernel', 'kernel', bytes(native)))
                    with tempfile.TemporaryDirectory(prefix='gomem-callback-object-') as directory:
                        kernel_path = Path(directory) / 'kernel.json'; kernel_path.write_text(json.dumps(kernel))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', kernel_path.as_uri(), class_types={'_LIST_ENTRY': LIST_ENTRY, '_UNICODE_STRING': UNICODE_STRING, '_DEVICE_OBJECT': DEVICE_OBJECT, '_DRIVER_OBJECT': DRIVER_OBJECT, '_OBJECT_HEADER': OBJECT_HEADER}))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'callbacks', 'callbacks', source_path.as_uri(), table_mapping={'nt_symbols': 'kernel'}, class_types=callbacks.class_types_x86 if width == 4 else None))
                        context.module('kernel', 'kernel', 0)
                        obj = context.object('callbacks!' + typ, layer_name='allocation', native_layer_name='kernel', offset=0x1000)
                        valid, validity_error, row, error = True, None, None, None
                        try:
                            if isinstance(obj, callbacks._SHUTDOWN_PACKET): valid = obj.is_parseable({1: 'Driver', 2: 'Device', 3: 'File'})
                        except Exception as exc: valid, validity_error = False, dict(type=type(exc).__name__, message=str(exc))
                        try:
                            name, callback, detail = Callbacks._process_scanned_callback(obj, {1: 'Driver', 2: 'Device', 3: 'File'})
                            absent = lambda value: dict(missing=type(value).__name__) if isinstance(value, interfaces.renderers.BaseAbsentValue) else str(value)
                            row = [absent(name), int(callback), absent(detail)]
                        except Exception as exc: error = dict(type=type(exc).__name__, message=str(exc))
                    writes = lambda data: [dict(offset=at, data=bytes(data[at:at + 256]).hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]
                    cases.append(dict(layout=layout_index, type=typ, scenario=scenario, size=len(native), allocation_writes=writes(allocation), kernel_writes=writes(native), holes=holes, valid=valid, validity_error=validity_error, row=row, error=error))
    return json.dumps(dict(commit=COMMIT, scope=__doc__, layouts=layouts, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(); generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated: raise SystemExit('callback object oracle drift; regenerate explicitly')
    else: OUTPUT.write_text(generated)
    doc = json.loads(generated)
    print(f'{len(doc["layouts"])} layouts and {len(doc["cases"])} actual callback object controls verified')


if __name__ == '__main__': main()
