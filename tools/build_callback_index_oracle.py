#!/usr/bin/env python3
"""Run actual unmodified notification, bugcheck and registry callback walkers."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/wincallbacks/testdata/index-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import EX_FAST_REF, LIST_ENTRY, UNICODE_STRING
    from volatility3.plugins.windows.callbacks import Callbacks

    cases = []
    for width in (4, 8):
        path = source / 'volatility3/framework/symbols/windows' / ('callbacks-x64.json' if width == 8 else 'callbacks-x86.json')
        layout = json.loads(path.read_text())
        for vista in (False, True):
            for legacy in (False, True):
                for scenario in ('normal', 'empty', 'duplicate', 'zero-function', 'missing-callback', 'missing-component', 'bad-altitude', 'missing-fastref', 'array-boundaries', 'null-reference', 'both-registry-roots'):
                    b = lambda name: dict(kind='base', name=name)
                    s = lambda name: dict(kind='struct', name=name)
                    p = lambda name: dict(kind='pointer', subtype=s(name))
                    field = lambda at, ref: dict(offset=at, type=ref)
                    aggregate = lambda size, fields: dict(kind='struct', size=size, fields=fields)
                    kernel = dict(metadata={'format': '6.2.0', 'windows': {'pe': {'major': 6 if vista else 5, 'minor': 0 if vista else 1, 'revision': 0, 'build': 6000 if vista else 2600}}},
                        base_types={name: dict(kind='int', size=size, signed=False, endian='little') for name, size in [('pointer', width), ('word', width), ('unsigned int', 4), ('unsigned short', 2)]},
                        user_types={'_EX_FAST_REF': aggregate(width, {'Object': field(0, b('word'))}),
                                    '_LIST_ENTRY': aggregate(2 * width, {'Flink': field(0, p('_LIST_ENTRY')), 'Blink': field(width, p('_LIST_ENTRY'))}),
                                    '_UNICODE_STRING': aggregate(16 if width == 8 else 8, {'Length': field(0, b('unsigned short')), 'Buffer': field(width, p('_LIST_ENTRY'))})},
                        symbols={name: dict(address=at) for name, at in [('PspLoadImageNotifyRoutine', 0x1000), ('PspCreateThreadNotifyRoutine', 0x1100), ('PspCreateProcessNotifyRoutine', 0x1400), ('KeBugCheckCallbackListHead', 0x2000), ('KeBugCheckReasonCallbackListHead', 0x2020), ('CmpCallBackCount', 0x2080)]}, enums={})
                    kernel['symbols']['CmpCallBackVector' if legacy else 'CallbackListHead'] = dict(address=0x2100 if legacy else 0x2040)
                    if scenario == 'both-registry-roots':
                        kernel['symbols']['CallbackListHead'] = dict(address=0x2040)
                        kernel['symbols']['CmpCallBackVector'] = dict(address=0x2100)
                    data, holes = bytearray(0x40000), []
                    def put(at, value, size=width):
                        data[at:at + size] = value.to_bytes(size, 'little')
                    def offset(typ, name):
                        return layout['user_types'][typ]['fields'][name]['offset']
                    def link(head, at):
                        put(head, at); put(head + width, at)
                        put(at, head); put(at + width, head)
                    for head in (0x12000, 0x12020, 0x12040):
                        put(head, head); put(head + width, head)
                    if scenario != 'empty':
                        for i, root in enumerate((0x11000, 0x11100, 0x11400)):
                            at = 0x18000 + i * 0x100
                            put(root, at | (15 if width == 8 else 7))
                            put(at + offset('_GENERIC_CALLBACK', 'Callback'), 0 if scenario == 'zero-function' else 0x28000 + i * 0x100)
                            if scenario == 'duplicate': put(root + width, at | 1)
                        for head, at, typ in [(0x12000, 0x19000, '_KBUGCHECK_CALLBACK_RECORD'), (0x12020, 0x19100, '_KBUGCHECK_REASON_CALLBACK_RECORD')]:
                            link(head, at)
                            put(at + offset(typ, 'CallbackRoutine'), 0x28300)
                            put(at + offset(typ, 'Component'), 0xc000)
                        data[0xc000:0xc007] = b'reason\0'
                        data[0x1c000:0x1c009] = b'ordinary\0'
                        put(0x12080, 1, 4)
                        if legacy:
                            put(0x12100, 0x1a000 | 3)
                            put(0x1a000 + offset('_EX_CALLBACK_ROUTINE_BLOCK', 'Function'), 0 if scenario == 'zero-function' else 0x28400)
                        else:
                            link(0x12040, 0x1a000)
                            put(0x1a000 + offset('_CM_CALLBACK_ENTRY', 'Function'), 0 if scenario == 'zero-function' else 0x28400)
                            altitude = 0x1a000 + offset('_CM_CALLBACK_ENTRY', 'Altitude')
                            raw = '385000'.encode('utf-16-le')
                            put(altitude, len(raw), 2); put(altitude + width, 0x1b000)
                            data[0x1b000:0x1b000 + len(raw)] = raw
                    if scenario == 'array-boundaries':
                        for i, root in enumerate((0x11000, 0x11100, 0x11400)):
                            count = 64 if vista and i else 8
                            for slot, at, address in [(count - 1, 0x1d000 + i * 0x100, 0x29000 + i * 0x100),
                                                      (count, 0x1d800 + i * 0x100, 0x29900 + i * 0x100)]:
                                put(root + slot * width, at | 1)
                                put(at + offset('_GENERIC_CALLBACK', 'Callback'), address)
                    if scenario == 'null-reference':
                        put(offset('_GENERIC_CALLBACK', 'Callback'), 0x28700)
                    if scenario == 'both-registry-roots':
                        put(0x12100, 0x1a800 | 3)
                        put(0x1a800 + offset('_EX_CALLBACK_ROUTINE_BLOCK', 'Function'), 0x28450)
                    if scenario == 'missing-callback': holes.append((0x18100 + offset('_GENERIC_CALLBACK', 'Callback'), width))
                    if scenario == 'missing-component': holes.append((0xc000, 64))
                    if scenario == 'bad-altitude' and not legacy: holes.append((0x1b000, 12))
                    if scenario == 'missing-fastref': holes.append((0x11100, width))
                    context, faults = contexts.Context(), []
                    class OriginalLayer(BufferDataLayer):
                        @property
                        def address_mask(self): return (1 << (width * 8)) - 1
                        def read(self, at, length, pad=False):
                            for start, size in holes:
                                if at < start + size and start < at + length:
                                    faults.append(dict(offset=at, length=length))
                                    raise exceptions.InvalidAddressException(self.name, max(at, start))
                            return super().read(at, length, pad)
                        def is_valid(self, at, length=1):
                            return not any(at < start + size and start < at + length for start, size in holes) and super().is_valid(at, length)
                    context.layers.add_layer(OriginalLayer(context, 'memory', 'memory', bytes(data)))
                    with tempfile.TemporaryDirectory(prefix='gomem-callback-index-') as directory:
                        kernel_path = Path(directory) / 'kernel.json'
                        kernel_path.write_text(json.dumps(kernel))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', kernel_path.as_uri(), class_types={'_EX_FAST_REF': EX_FAST_REF, '_LIST_ENTRY': LIST_ENTRY, '_UNICODE_STRING': UNICODE_STRING}))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'callbacks', 'callbacks', path.as_uri(), table_mapping={'nt_symbols': 'kernel'}))
                        module = context.module('kernel', 'memory', 0x10000)
                        results = []
                        for method in (Callbacks.list_notify_routines, Callbacks.list_bugcheck_callbacks, Callbacks.list_bugcheck_reason_callbacks, Callbacks.list_registry_callbacks):
                            rows, error = [], None
                            try:
                                for typ, callback, detail in method(context, module.name, 'callbacks'):
                                    if isinstance(detail, interfaces.renderers.BaseAbsentValue):
                                        detail = dict(missing=type(detail).__name__)
                                    elif detail is not None: detail = str(detail)
                                    rows.append([str(typ), int(callback), detail])
                            except Exception as exc:
                                error = dict(type=type(exc).__name__, message=str(exc))
                            results.append(dict(method=method.__name__, rows=rows, error=error))
                    writes = [dict(offset=at, data=bytes(data[at:at + 256]).hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]
                    cases.append(dict(width=width, vista=vista, legacy=legacy, scenario=scenario, kernel_isf=kernel, callback_isf=layout, source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=len(data), kernel_base=0x10000, writes=writes, holes=holes, results=results, read_faults=faults))
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated: raise SystemExit('callback index oracle drift; regenerate explicitly')
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} actual callback index controls verified')


if __name__ == '__main__': main()
