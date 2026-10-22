#!/usr/bin/env python3
"""Run pinned complete Consoles generators on paged conhost/process objects."""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_cmdscan_oracle import version_image

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-consoles-oracle.json'
SCENARIOS = ['normal', 'uppercase-process', 'empty-title', 'zero-screen',
             'zero-count', 'empty-histories', 'unused-command', 'zero-last',
             'empty-commands', 'command-hole', 'screen-cells-hole',
             'history-cycle', 'title-hole']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.plugins.windows.consoles import Consoles

    seeds = json.loads((ROOT / 'internal/plugins/testdata/windows-cmdscan-oracle.json').read_text())
    if seeds['commit'] != COMMIT:
        raise ValueError('CmdScan seed baseline mismatch')
    cases = []
    for seed in seeds['cases']:
        if seed['scenario'] != 'normal':
            continue
        path = source / 'volatility3/framework/symbols/windows/consoles' / (seed['layout'] + '.json')
        types = json.loads(path.read_text())['user_types']
        def field(typ, name): return types[typ]['fields'][name]
        def off(typ, name): return field(typ, name)['offset']
        for scenario in SCENARIOS:
            kernel = copy.deepcopy(seed['isf'])
            data = bytearray(seed['size'])
            for write in seed['writes']:
                raw = bytes.fromhex(write['data'])
                data[write['offset']:write['offset'] + len(raw)] = raw
            data[0x100000:0x104000] = bytes(0x4000)
            if seed['revision']:
                image = version_image(seed['build'], seed['revision'])
                data[0x100000:0x100000 + len(image)] = image
            def q(at, value): struct.pack_into('<Q', data, at, value)
            def h(at, value): struct.pack_into('<H', data, at, value & 0xffff)
            def command(at, text, pointer=0x10d000):
                if len(text) < 8:
                    raw = text.encode('utf-16le')
                    data[at:at + len(raw)] = raw
                else:
                    q(at, pointer)
                    raw = text.encode('utf-16le')
                    data[pointer:pointer + len(raw)] = raw
                struct.pack_into('<I', data, at + off('_COMMAND', 'Length'), len(text))
                struct.pack_into('<I', data, at + off('_COMMAND', 'Allocated'), 1024)
            def head(owner, typ, name, external):
                at = owner + off(typ, name)
                if field(typ, name)['type']['kind'] == 'pointer':
                    q(at, external)
                    return external
                return at
            def chain(at, nodes):
                q(at, nodes[0] if nodes else at)
                q(at + 8, nodes[-1] if nodes else at)
                for i, node in enumerate(nodes):
                    q(node, nodes[i + 1] if i + 1 < len(nodes) else at)
                    q(node + 8, nodes[i - 1] if i else at)
            root = 0x100400
            hist = 0x105000
            process_node, process = 0x107000, 0x107100
            exe, alias = 0x107400, 0x107600
            screen, buffer, rows = 0x108000, 0x109000, 0x10a000
            chain(head(root, '_CONSOLE_INFORMATION', 'HistoryList', 0x104000),
                  [] if scenario == 'empty-histories' else [hist])
            chain(head(root, '_CONSOLE_INFORMATION', 'ConsoleProcessList', 0x104100), [process_node])
            chain(head(root, '_CONSOLE_INFORMATION', 'ExeAliasList', 0x104200), [exe])
            chain(head(exe, '_EXE_ALIAS_LIST', 'AliasList', 0x104300), [alias])
            q(process_node + off('_CONSOLE_PROCESS_LIST', 'ConsoleProcess'), process)
            struct.pack_into('<I', data, process + off('_CONSOLE_PROCESS', 'ProcessId'), 123)
            struct.pack_into('<I', data, process + off('_CONSOLE_PROCESS', 'ProcessHandle'), 16)
            if field('_EXE_ALIAS_LIST', 'ExeName')['type']['kind'] == 'struct':
                command(exe + off('_EXE_ALIAS_LIST', 'ExeName'), 'cmd.exe')
            else:
                q(exe + off('_EXE_ALIAS_LIST', 'ExeName'), 0x10e000)
                data[0x10e000:0x10e010] = 'cmd.exe\0'.encode('utf-16le')
            command(alias + off('_ALIAS', 'Source'), 'll')
            command(alias + off('_ALIAS', 'Target'), 'dir')
            bucket = 0x10c000
            q(hist + 16, bucket)
            q(hist + 24, bucket + (0 if scenario == 'empty-commands' else 64))
            q(hist + 32, bucket + 96)
            h(hist + off('_COMMAND_HISTORY', 'CommandCountMax'), 50)
            command(hist + off('_COMMAND_HISTORY', 'Application'), 'cmd.exe')
            q(hist + off('_COMMAND_HISTORY', 'ConsoleProcessHandle'), 0x105100)
            struct.pack_into('<I', data, 0x105100, 16)
            h(hist + off('_COMMAND_HISTORY', 'LastDisplayed'), 0 if scenario == 'zero-last' else -1)
            command(bucket, 'whoami')
            command(bucket + 32, 'echo native')
            if scenario == 'unused-command':
                command(bucket + 64, 'unused')
            for name, value in [('ScreenX', 0 if scenario == 'zero-screen' else 80),
                                ('ScreenY', 25), ('CommandHistorySize', 50),
                                ('HistoryBufferMax', 4), ('ProcessCount', 1),
                                ('HistoryBufferCount', 0 if scenario == 'zero-count' else 1)]:
                h(root + off('_CONSOLE_INFORMATION', name), value)
            for name, at, text in [('Title', 0x106000, '' if scenario == 'empty-title' else 'console'),
                                   ('OriginalTitle', 0x106200, 'original')]:
                q(root + off('_CONSOLE_INFORMATION', name), at)
                raw = (text + '\0').encode('utf-16le')
                data[at:at + len(raw)] = raw
            q(root + off('_CONSOLE_INFORMATION', 'CurrentScreenBuffer'), screen)
            q(root + off('_CONSOLE_INFORMATION', 'GetScreenBuffer'), screen)
            q(screen + off('_SCREEN_INFORMATION', 'TextBufferInfo'), buffer)
            q(buffer + off('_TEXT_BUFFER_INFO', 'BufferRows'), rows)
            h(buffer + off('_TEXT_BUFFER_INFO', 'BufferCapacity'), 3)
            h(buffer + off('_TEXT_BUFFER_INFO', 'BufferStart'), 1)
            indirect = field('_ROWS_ARRAY', 'Rows')['type']['subtype']['name'] == '_ROW_POINTER'
            for i, text in enumerate(['first ', 'middle ', '']):
                row = 0x10f000 + i * 0x100 if indirect else rows + i * types['_ROW']['size']
                if indirect:
                    q(rows + off('_ROWS_ARRAY', 'Rows') + i * types['_ROW_POINTER']['size'] + off('_ROW_POINTER', 'Row'), row)
                cells = 0x10b000 + i * 0x100
                q(row + off('_ROW', 'CharRow'), cells)
                h(row + off('_ROW', 'RowLength'), len(text))
                h(row + off('_ROW', 'RowLength2'), len(text))
                raw = b''.join(struct.pack('<HB', ord(c), 0) for c in text)
                start = cells + off('_CHAR_ROW_CELL_ARRAY', 'Chars')
                data[start:start + len(raw)] = raw
            if scenario == 'command-hole':
                q(bucket + 32, 0x300000)
            if scenario == 'screen-cells-hole':
                row = 0x10f100 if indirect else rows + types['_ROW']['size']
                q(row + off('_ROW', 'CharRow'), 0x300000)
            if scenario == 'history-cycle':
                q(hist, hist)
            if scenario == 'title-hole':
                q(0xb000 + 0x106 * 8, 0)
            if scenario == 'uppercase-process':
                data[0x418:0x428] = b'CONHOST.EXE\0' + bytes(4)
            ctx = contexts.Context()
            ctx.layers.add_layer(BufferDataLayer(ctx, 'physical', 'physical', bytes(data)))
            ctx.config['memory.memory_layer'] = 'physical'
            ctx.config['memory.page_map_offset'] = 0x8000
            ctx.config['memory.kernel_virtual_offset'] = 0x10000
            ctx.layers.add_layer(Intel32e(ctx, 'memory', 'memory'))
            result, error = [], None
            with tempfile.TemporaryDirectory(prefix='gomem-consoles-') as directory:
                kernel_path = Path(directory) / 'kernel.json'
                kernel_path.write_text(json.dumps(kernel))
                classes = {n: getattr(extensions, n.lstrip('_')) for n in ['_EPROCESS', '_LIST_ENTRY', '_MMVAD', '_MMVAD_SHORT', '_EX_FAST_REF', '_UNICODE_STRING']}
                classes['_RTL_BALANCED_NODE'] = extensions.MMVAD_SHORT
                ctx.symbol_space.append(IntermediateSymbolTable(ctx, 'symbols', 'kernel', kernel_path.as_uri(), class_types=classes))
                ctx.module('kernel', 'memory', 0x10000)
                runner = SimpleNamespace(context=ctx, _context=ctx, config_path='plugins.Consoles',
                                         config={'kernel': 'kernel', 'max_history': [50], 'max_buffers': [4], 'no_registry': True},
                                         get_console_info=Consoles.get_console_info)
                processes = PsList.list_processes(ctx, 'kernel', filter_func=lambda p: Consoles._conhost_proc_filter(runner, p))
                try:
                    for depth, row in Consoles._generator(runner, processes):
                        values = []
                        for value in row:
                            if isinstance(value, interfaces.renderers.BaseAbsentValue):
                                value = {'missing': type(value).__name__}
                            elif not isinstance(value, str):
                                value = int(value)
                            values.append(value)
                        result.append({'depth': depth, 'values': values})
                except Exception as exc:
                    error = type(exc).__name__
            assert error is None, (seed['layout'], scenario, error)
            if scenario in ('zero-count', 'title-hole'):
                assert len(result) == 1 and result[0]['values'][-1] == 'Console Information Not Found'
            else:
                names = [r['values'][3] for r in result]
                assert '_CONSOLE_INFORMATION.ScreenBuffer_0.Dump' in names, (seed['layout'], scenario, names)
                assert result[-1]['values'][-1] == ({'missing': 'NotAvailableValue'} if scenario == 'screen-cells-hole' else 'middle\n\nfirst')
                if scenario != 'empty-histories' and scenario != 'empty-commands':
                    assert sum('_Command_' in n for n in names) == (1 if scenario == 'command-hole' else 2), (seed['layout'], scenario)
            cases.append(dict(layout=seed['layout'], build=seed['build'], revision=seed['revision'],
                              scenario=scenario, isf=kernel, size=len(data),
                              writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])],
                              rows=result, error=error))
    assert len(cases) == 156
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Consoles full-generator oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} complete original Consoles controls verified')


if __name__ == '__main__':
    main()
