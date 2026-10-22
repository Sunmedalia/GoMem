#!/usr/bin/env python3
"""Run complete pinned Callbacks generators on paged indexes and pool allocations."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-callbacks-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires locked unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import EX_FAST_REF, LIST_ENTRY, UNICODE_STRING, DEVICE_OBJECT, DRIVER_OBJECT
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER, POOL_HEADER_VISTA, OBJECT_HEADER
    from volatility3.plugins.windows.callbacks import Callbacks

    folder = ROOT / 'internal/plugins/testdata'
    indexes = json.loads((ROOT / 'pkg/wincallbacks/testdata/index-oracle.json').read_text())
    pools = json.loads((folder / 'windows-poolscanner-oracle.json').read_text())
    objects = json.loads((folder / 'windows-callback-object-oracle.json').read_text())
    assert all(item['commit'] == COMMIT for item in (indexes, pools, objects))
    cases = []
    for arch, intel in [('x86', Intel), ('pae', IntelPAE), ('x64', Intel32e)]:
        width = 8 if arch == 'x64' else 4
        for vista in (False, True):
            for legacy in (False, True):
                for scenario in ('normal', 'empty', 'duplicate', 'zero-callback', 'bad-driver', 'invalid-category', 'no-name-info', 'overlap', 'bad-pool-index', 'undersized', 'paged-pool', 'free-pool'):
                    index = next(c for c in indexes['cases'] if c['width'] == width and c['vista'] == vista and c['legacy'] == legacy and c['scenario'] == ('empty' if scenario == 'empty' else 'duplicate' if scenario == 'duplicate' else 'normal'))
                    pool = next(c['isf'] for c in pools['cases'] if c['width'] == width and c['vista'] == vista)
                    layout_index, object_layout = next((i, l) for i, l in enumerate(objects['layouts']) if l['width'] == width and l['header_mode'] == ('index' if vista else 'legacy-type'))
                    table = copy.deepcopy(index['kernel_isf'])
                    for key in ('base_types', 'user_types'):
                        table[key].update(copy.deepcopy(object_layout['kernel_isf'][key]))
                    table['base_types'].update(copy.deepcopy(pool['base_types']))
                    for name in ('_POOL_HEADER', '_HANDLE_TABLE', '_QUAD'):
                        table['user_types'][name] = copy.deepcopy(pool['user_types'][name])
                    table['user_types']['_POOL_HEADER']['fields']['PoolIndex'] = dict(offset=1, type=dict(kind='base', name='u8'))
                    table['user_types']['_KLDR_DATA_TABLE_ENTRY'] = dict(kind='struct', size=0x60, fields={
                        'InLoadOrderLinks': dict(offset=0, type=dict(kind='struct', name='_LIST_ENTRY')),
                        'DllBase': dict(offset=0x20, type=dict(kind='base', name='word')),
                        'SizeOfImage': dict(offset=0x28, type=dict(kind='base', name='unsigned int')),
                        'BaseDllName': dict(offset=0x30, type=dict(kind='struct', name='_UNICODE_STRING'))})
                    table['symbols'].update(PsLoadedModuleList=dict(address=0x1d000), ObTypeIndexTable=dict(address=0x1e000),
                                            ImageAliasA=dict(address=0), ImageAliasB=dict(address=0),
                                            ThreadHandler=dict(address=0x100), ProcessHandler=dict(address=0x200),
                                            BugCheckHandler=dict(address=0x300), RegistryHandler=dict(address=0x400))
                    if not vista:
                        table['symbols']['ObpObjectTypes'] = table['symbols'].pop('ObTypeIndexTable')
                    if vista:
                        table['symbols']['KdCopyDataBlock'] = dict(address=0x1f000)
                    data = bytearray(0x40000)
                    def write(writes):
                        for item in writes:
                            at, raw = item['offset'], bytes.fromhex(item['data'])
                            assert 0 <= at <= len(data) and at + len(raw) <= len(data)
                            data[at:at + len(raw)] = raw
                    def put(at, value, size=width):
                        data[at:at + size] = value.to_bytes(size, 'little')
                    def unicode(at, buffer, text):
                        raw = text.encode('utf-16-le')
                        put(at, len(raw), 2); put(at + width, buffer)
                        data[buffer:buffer + len(raw)] = raw
                    write(index['writes'])
                    # Actual low-address Intel page tables. Source/native addresses
                    # are identical here; independent-layer object controls remain separate.
                    if arch == 'x86':
                        put(0x8000, 0x83, 4)
                    elif arch == 'pae':
                        put(0x8000, 0x9003, 8); put(0x9000, 0x83, 8)
                    else:
                        put(0x8000, 0x9003, 8); put(0x9000, 0xa003, 8); put(0xa000, 0x83, 8)
                    put(0x2d000, 0x2d000); put(0x2d000 + width, 0x2d000)
                    if scenario != 'empty':
                        module_count = 2 if scenario == 'overlap' else 1
                        previous = 0x2d000
                        for i in range(module_count):
                            at = 0x38000 + i * 0x100
                            put(previous, at); put(at + width, previous)
                            put(at + 0x20, 0x28000); put(at + 0x28, 0x2000, 4)
                            unicode(at + 0x30, 0x39000 + i * 0x100, 'callbackdrv.sys' if i == 0 else 'overlap.sys')
                            previous = at
                        put(previous, 0x2d000); put(0x2d000 + width, previous)
                        # Include all five object structures and all three PnP tags
                        # when applicable. The original factory decides which scan.
                        allocations = [('IoFs', '_NOTIFICATION_PACKET'), ('IoSh', '_SHUTDOWN_PACKET'), ('Cbrb', '_GENERIC_CALLBACK')]
                        if vista:
                            allocations += [('DbCb', '_DBGPRINT_CALLBACK'), ('Pnp9', '_NOTIFY_ENTRY_HEADER'), ('PnpD', '_NOTIFY_ENTRY_HEADER'), ('PnpC', '_NOTIFY_ENTRY_HEADER')]
                        # Object bytes are original processor fixtures; scans and
                        # validity are executed by the real generator below.
                        object_scenario = scenario if scenario in ('zero-callback', 'bad-driver', 'invalid-category', 'no-name-info') else 'normal'
                        for i, (tag, typ) in enumerate(allocations):
                            obj = next(c for c in objects['cases'] if c['layout'] == layout_index and c['type'] == typ and c['scenario'] == object_scenario)
                            write(obj['kernel_writes'])
                            at, header = 0x30000 + i * 0x1000, width * 2
                            minimum = {'IoFs': 48 if width == 8 else 16, 'IoSh': 24 if width == 8 else 12, 'Cbrb': 24 if width == 8 else 12,
                                       'DbCb': 0x20, 'Pnp9': 0x30, 'PnpD': 0x40, 'PnpC': 0x38}[tag]
                            size = max(minimum, header + object_layout['callback_isf']['user_types'][typ]['size'])
                            put(at + 1, 2 if scenario == 'bad-pool-index' else 1 if tag.startswith('Pnp') else 0, 1)
                            put(at + 2, 1 if scenario == 'undersized' else (size + header - 1) // header, 1)
                            put(at + 3, 1 if scenario == 'paged-pool' else 0 if scenario == 'free-pool' else 2, 1)
                            data[at + 4:at + 8] = tag.encode()
                            for item in obj['allocation_writes']:
                                raw = bytes.fromhex(item['data']); offset = at + header + item['offset'] - 0x1000
                                data[offset:offset + len(raw)] = raw
                        for i in range(1, 4):
                            put(0x2e000 + i * width, 0x7000 + (i - 1) * 0x100)
                    # Source driver bytes include a cookie at the PDPT address;
                    # restore paging after copying those actual fixture bytes.
                    if arch == 'pae':
                        put(0x8000, 0x9003, 8); put(0x9000, 0x83, 8)
                    elif arch == 'x64':
                        put(0x8000, 0x9003, 8); put(0x9000, 0xa003, 8); put(0xa000, 0x83, 8)
                    context = contexts.Context()
                    context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
                    context.config['memory.memory_layer'] = 'physical'
                    context.config['memory.page_map_offset'] = 0x8000
                    context.layers.add_layer(intel(context, 'memory', 'memory'))
                    rows, error = [], None
                    with tempfile.TemporaryDirectory(prefix='gomem-callbacks-generator-') as directory:
                        path = Path(directory) / 'kernel.json'; path.write_text(json.dumps(table))
                        context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), class_types={
                            '_EX_FAST_REF': EX_FAST_REF, '_LIST_ENTRY': LIST_ENTRY, '_UNICODE_STRING': UNICODE_STRING,
                            '_DEVICE_OBJECT': DEVICE_OBJECT, '_DRIVER_OBJECT': DRIVER_OBJECT, '_OBJECT_HEADER': OBJECT_HEADER,
                            '_POOL_HEADER': POOL_HEADER_VISTA if vista else POOL_HEADER}))
                        context.module('kernel', 'memory', 0x10000)
                        runner = SimpleNamespace(context=context, _context=context, config={'kernel': 'kernel'}, config_path='plugins.Callbacks')
                        for name in ('create_callback_symbol_table', 'list_notify_routines', 'list_bugcheck_callbacks', 'list_bugcheck_reason_callbacks', 'list_registry_callbacks', 'scan'):
                            setattr(runner, name, getattr(Callbacks, name))
                        try:
                            for depth, row in Callbacks._generator(runner):
                                assert depth == 0
                                converted = []
                                for value in row:
                                    if isinstance(value, interfaces.renderers.BaseAbsentValue):
                                        value = dict(missing=type(value).__name__)
                                    elif not isinstance(value, str):
                                        value = int(value)
                                    converted.append(value)
                                rows.append(converted)
                        except Exception as exc:
                            error = dict(type=type(exc).__name__, message=str(exc))
                    writes = [dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]
                    cases.append(dict(arch=arch, width=width, vista=vista, legacy=legacy, scenario=scenario,
                                      kernel_base=0x10000, isf=table, size=len(data), writes=writes, rows=rows, error=error))
    assert len(cases) == 144
    assert sum(c['error'] is not None for c in cases) == 6
    assert sum(len(c['rows']) for c in cases) == 1612
    assert all(c['error'] is None or c['scenario'] == 'no-name-info' and c['vista'] and c['error']['type'] == 'ValueError' for c in cases)
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('complete callbacks oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} complete pinned Callbacks generators verified')


if __name__ == '__main__':
    main()
