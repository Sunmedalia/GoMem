#!/usr/bin/env python3
"""Run original console validity, titles and list methods on pinned byte-backed objects."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winconsole/testdata/console-oracle.json'
SCENARIOS = ['normal', 'empty-title', 'both-empty', 'title-hole',
             'original-title-hole', 'both-title-hole', 'zero-count', 'excess-count',
             'zero-max', 'count-hole', 'zero-count-title-hole', 'bom-title',
             'unpaired-title', 'nul-title', 'full-title-no-nul', 'tail-title-hole',
             'null-title', 'history-cycle', 'history-link-hole', 'history-next-hole',
             'history-empty', 'null-history-head', 'process-cycle', 'alias-cycle',
             'alias-node-hole', 'blink-mismatch', 'sentinel-head-hole',
             'process-node-read-hole', 'negative-screen-size']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.symbols.windows.extensions import consoles
    b = lambda name: dict(kind='base', name=name)
    link = dict(kind='struct', name='_LIST_ENTRY')
    ptr = dict(kind='pointer', subtype=link)
    kernel = dict(metadata=dict(format='6.2.0'),
                  base_types={'pointer': dict(kind='int', size=8, signed=False, endian='little')},
                  user_types={'_LIST_ENTRY': dict(kind='struct', size=16, fields={
                      'Flink': dict(offset=0, type=ptr), 'Blink': dict(offset=8, type=ptr)})},
                  enums={}, symbols={})
    layouts, cases = {}, []
    for path in sorted((source / 'volatility3/framework/symbols/windows/consoles').glob('*.json')):
        raw = path.read_bytes()
        doc = json.loads(raw)
        types = doc['user_types']
        layouts[path.stem] = dict(source=raw.decode(), sha256=hashlib.sha256(raw).hexdigest())
        def field(typ, name): return types[typ]['fields'][name]
        def off(typ, name): return field(typ, name)['offset']
        for scenario in SCENARIOS:
            data, holes = bytearray(0x20000), []
            def q(at, value): struct.pack_into('<Q', data, at, value)
            def h(at, value): struct.pack_into('<H', data, at, value & 0xffff)
            root = 0x4000
            for name, value in [('ScreenX', -1 if scenario == 'negative-screen-size' else 80),
                                ('ScreenY', 25), ('CommandHistorySize', 50),
                                ('HistoryBufferMax', 4), ('ProcessCount', 2),
                                ('HistoryBufferCount', 0 if scenario in ('zero-count', 'zero-count-title-hole') else 5 if scenario == 'excess-count' else 1)]:
                h(root + off('_CONSOLE_INFORMATION', name), value)
            for name, address, text in [('Title', 0x10000, 'console'), ('OriginalTitle', 0x10200, 'original')]:
                q(root + off('_CONSOLE_INFORMATION', name), 0 if scenario == 'null-title' and name == 'Title' else address)
                if scenario == 'both-empty' or scenario == 'empty-title' and name == 'Title': text = ''
                encoded = (text + '\0').encode('utf-16le')
                if name == 'Title':
                    if scenario == 'bom-title': encoded = b'\xfe\xff' + 'title\0'.encode('utf-16be')
                    if scenario == 'unpaired-title': encoded = b'\0\xd8A\0\0\0'
                    if scenario == 'nul-title': encoded = 'A\0B\0'.encode('utf-16le')
                    if scenario == 'full-title-no-nul': encoded = ('X' * 256).encode('utf-16le')
                data[address:address+len(encoded)] = encoded
            def list_head(owner, typ, name, external):
                at = owner + off(typ, name)
                if field(typ, name)['type']['kind'] == 'pointer':
                    q(at, external)
                    return external
                return at
            def chain(head, nodes):
                q(head, nodes[0] if nodes else head)
                q(head+8, nodes[-1] if nodes else head)
                for i, node in enumerate(nodes):
                    q(node, nodes[i+1] if i+1 < len(nodes) else head)
                    q(node+8, nodes[i-1] if i else head)
            history_head = list_head(root, '_CONSOLE_INFORMATION', 'HistoryList', 0x8000)
            process_head = list_head(root, '_CONSOLE_INFORMATION', 'ConsoleProcessList', 0x8100)
            exe_head = list_head(root, '_CONSOLE_INFORMATION', 'ExeAliasList', 0x8200)
            alias_head = list_head(0xc000, '_EXE_ALIAS_LIST', 'AliasList', 0x8300)
            alias2 = list_head(0xc100, '_EXE_ALIAS_LIST', 'AliasList', 0x8400)
            chain(history_head, [] if scenario == 'history-empty' else [0xb000, 0xb100])
            chain(process_head, [0x9000, 0x9100])
            chain(exe_head, [0xc000, 0xc100])
            chain(alias_head, [0xd000, 0xd100])
            chain(alias2, [])
            for node, target, pid in [(0x9000, 0xa000, 123), (0x9100, 0xa100, 456)]:
                q(node + off('_CONSOLE_PROCESS_LIST', 'ConsoleProcess'), target)
                struct.pack_into('<I', data, target+off('_CONSOLE_PROCESS', 'ProcessId'), pid)
                struct.pack_into('<I', data, target+off('_CONSOLE_PROCESS', 'ProcessHandle'), 4)
            if scenario in ('title-hole', 'both-title-hole', 'zero-count-title-hole'): holes.append([0x10000, 1])
            if scenario in ('original-title-hole', 'both-title-hole'): holes.append([0x10200, 1])
            if scenario == 'tail-title-hole': holes.append([0x10190, 1])
            if scenario == 'count-hole': holes.append([root+off('_CONSOLE_INFORMATION', 'HistoryBufferCount'), 2])
            if scenario == 'history-cycle': q(0xb100, 0xb000)
            if scenario == 'history-link-hole': holes.append([0xb100, 1])
            if scenario == 'history-next-hole': holes.append([0xb108, 1])
            if scenario == 'null-history-head': q(root+off('_CONSOLE_INFORMATION', 'HistoryList'), 0)
            if scenario == 'process-cycle': q(0x9100, 0x9000)
            if scenario == 'alias-cycle': q(0xd100, 0xd000)
            if scenario == 'alias-node-hole': holes.append([0xd100, 1])
            if scenario == 'blink-mismatch': q(0xb008, 0xffffffffffffffff)
            if scenario == 'sentinel-head-hole': holes.append([history_head+8, 1])
            if scenario == 'process-node-read-hole': holes.append([0x9010, 8])
            class OriginalLayer(BufferDataLayer):
                def read(self, at, length, pad=False):
                    for start, size in holes:
                        if at < start+size and start < at+length:
                            raise exceptions.InvalidAddressException(self.name, max(start, at))
                    return super().read(at, length, pad)
            ctx = contexts.Context()
            ctx.layers.add_layer(OriginalLayer(ctx, 'memory', 'memory', bytes(data)))
            with tempfile.TemporaryDirectory(prefix='gomem-console-objects-') as directory:
                kernel_path = Path(directory) / 'kernel.json'
                kernel_path.write_text(json.dumps(kernel))
                ctx.symbol_space.append(IntermediateSymbolTable(ctx, 'kernel', 'kernel', kernel_path.as_uri(), class_types={'_LIST_ENTRY': extensions.LIST_ENTRY}))
                ctx.symbol_space.append(IntermediateSymbolTable(ctx, 'console', 'console', path.as_uri(), class_types=consoles.win10_x64_class_types, table_mapping={'nt_symbols':'kernel'}))
                c = ctx.object('console!_CONSOLE_INFORMATION', 'memory', root)
                exe = ctx.object('console!_EXE_ALIAS_LIST', 'memory', 0xc000)
                max_buffers = 0 if scenario == 'zero-max' else 4
                def result(call):
                    try: return dict(value=call())
                    except Exception as error: return dict(error=type(error).__name__)
                def addresses(iterator): return [int(v.vol.offset) for v in iterator]
                results = {
                    'title': result(c.get_title),
                    'original_title': result(c.get_original_title),
                    'valid': result(lambda: c.is_valid(max_buffers)),
                    'histories': result(lambda: addresses(c.get_histories())),
                    'processes': result(lambda: addresses(c.get_processes())),
                    'exe_aliases': result(lambda: addresses(c.get_exe_aliases())),
                    'aliases': result(lambda: addresses(exe.get_aliases())),
                    'process_values': result(lambda: [dict(pid=int(v.ConsoleProcess.ProcessId), handle=int(v.ConsoleProcess.ProcessHandle)) for v in c.get_processes()]),
                    'scalars': result(lambda: {name:int(getattr(c, name)) for name in ['ScreenX','ScreenY','CommandHistorySize','HistoryBufferCount','HistoryBufferMax','ProcessCount']})}
            cases.append(dict(layout=path.stem, scenario=scenario, size=len(data), root=root, max_buffers=max_buffers, holes=holes,
                              writes=[dict(offset=at, data=data[at:at+256].hex()) for at in range(0,len(data),256) if any(data[at:at+256])], results=results))
    assert len(cases) == len(SCENARIOS)*11
    for c in cases:
        if c['scenario'] == 'normal':
            assert c['results']['valid'] == dict(value=True)
            assert c['results']['histories'] == dict(value=[0xb000, 0xb100])
            assert c['results']['exe_aliases'] == dict(value=[0xc000, 0xc100])
    return json.dumps(dict(commit=COMMIT, scope=__doc__, kernel=kernel, layouts=layouts, cases=cases), indent=2)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT/'.cache'/('volatility3-'+COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('console object oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} original console object controls verified')


if __name__ == '__main__': main()
