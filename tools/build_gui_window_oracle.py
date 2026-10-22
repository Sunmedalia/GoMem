#!/usr/bin/env python3
"""Run original GUI window name, procedure, desktop and process methods."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/wingui/testdata/windows-oracle.json'
SCENARIOS = ['normal', 'empty-name', 'embedded-nul', 'replacement-name',
             'surrogate-name', 'bom-name', 'odd-name', 'name-hole',
             'direct-pointer-hole', 'direct-buffer-hole', 'direct-empty',
             'length-hole', 'buffer-pointer-hole', 'maximum-hole', 'length-zero',
             'procedure-hole', 'sub-pointer-hole', 'procedure-zero',
             'desktop-hole', 'parent-hole', 'session-hole', 'thread-hole',
             'owner-hole', 'process-hole', 'pid-hole', 'process-name-hole']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import gui
    seeds = json.loads((ROOT / 'pkg/wingui/testdata/object-oracle.json').read_text())
    if seeds['commit'] != COMMIT:
        raise ValueError('object seed baseline mismatch')
    cases = []
    for seed in seeds['cases']:
        if seed['scenario'] != 'normal':
            continue
        layout = source / 'volatility3/framework/symbols/windows/gui' / (seed['layout'] + '.json')
        types = json.loads(layout.read_text())['user_types']
        def off(typ, field):
            return types[typ]['fields'][field]['offset']
        for scenario in SCENARIOS:
            data, holes = bytearray(seed['size']), []
            for write in seed['writes']:
                raw = bytes.fromhex(write['data'])
                data[write['offset']:write['offset'] + len(raw)] = raw
            window, sub, direct, buffer = 0x10000, 0x11000, 0x12000, 0x13000
            desktop = seed['desktop']
            def q(at, value):
                struct.pack_into('<Q', data, at, value)
            def u(at, value):
                struct.pack_into('<I', data, at, value)
            head = window + off('tagWND', 'head')
            q(head + off('_THRDESKHEAD', 'rpdesk'), desktop)
            q(head + off('_THRDESKHEAD', 'pti'), 0xa000)
            q(desktop + off('tagDESKTOP', 'pDeskInfo'), 0x14000)
            q(0x14000 + off('tagDESKTOPINFO', 'spwnd'), window)
            proc = window + off('tagWND', 'lpfnWndProc')
            q(proc, 0x87654321)
            if 'subPointer' in types['tagWND']['fields']:
                q(window + off('tagWND', 'subPointer'), sub)
                proc = sub + off('subTagWNDType', 'lpfnWndProc')
                q(proc, 0x123456789abcdef0)
            text = {'empty-name': '', 'embedded-nul': 'A\0B',
                    'replacement-name': 'A\ufffdB', 'bom-name': '\ufeffWindow'}.get(scenario, 'Window')
            raw = text.encode('utf-16le')
            if scenario == 'surrogate-name':
                raw = b'A\0\0\xd8B\0'
            if scenario == 'odd-name':
                raw = b'A\0B'
            data[buffer:buffer + len(raw)] = raw
            data[direct:direct + len(raw)] = raw
            string = window + off('tagWND', 'strName')
            length_at = string + off('_LARGE_UNICODE_STRING', 'Length')
            buffer_at = string + off('_LARGE_UNICODE_STRING', 'Buffer')
            u(length_at, 0 if scenario == 'length-zero' else len(raw))
            q(buffer_at, buffer)
            direct_at = None
            if 'directName' in types['tagWND']['fields']:
                direct_at = window + off('tagWND', 'directName')
                q(direct_at, direct)
                # Distinguish direct-name preference from the inline fallback.
                if scenario == 'normal':
                    data[direct:direct + 12] = 'Direct'.encode('utf-16le')
            hole = {
                'name-hole': (buffer, 8), 'length-hole': (length_at, 4),
                'buffer-pointer-hole': (buffer_at, 8),
                'maximum-hole': (string + off('_LARGE_UNICODE_STRING', 'MaximumLength'), 4),
                'procedure-hole': (proc, 8),
                'desktop-hole': (head + off('_THRDESKHEAD', 'rpdesk'), 8),
                'parent-hole': (desktop + off('tagDESKTOP', 'rpwinstaParent'), 8),
                'session-hole': (seed['root'] + off('tagWINDOWSTATION', 'dwSessionId'), 4),
                'thread-hole': (head + off('_THRDESKHEAD', 'pti'), 8),
                'owner-hole': (0xa000 + off('tagTHREADINFO', 'ppi'), 8),
                'process-hole': (0xc000 + off('tagPROCESSINFO', 'Process'), 8),
                'pid-hole': (0xe010, 8), 'process-name-hole': (0xe000, 16),
            }.get(scenario)
            if hole:
                holes.append(hole)
            if direct_at is not None:
                if scenario == 'direct-pointer-hole':
                    holes.append((direct_at, 8))
                if scenario == 'direct-buffer-hole':
                    holes.append((direct, 256))
                if scenario == 'direct-empty':
                    data[direct:direct + 2] = b'\0\0'
            if scenario == 'sub-pointer-hole' and 'subPointer' in types['tagWND']['fields']:
                holes.append((window + off('tagWND', 'subPointer'), 8))
            if scenario == 'procedure-zero':
                q(proc, 0)

            class OriginalLayer(BufferDataLayer):
                @property
                def address_mask(self):
                    return (1 << 64) - 1

                def read(self, at, length, pad=False):
                    for start, size in holes:
                        if at < start + size and start < at + length:
                            raise exceptions.InvalidAddressException(self.name, max(at, start))
                    return super().read(at, length, pad)

            context = contexts.Context()
            context.layers.add_layer(OriginalLayer(context, 'memory', 'memory', bytes(data)))
            with tempfile.TemporaryDirectory(prefix='gomem-gui-window-') as directory:
                path = Path(directory) / 'kernel.json'
                path.write_text(json.dumps(seeds['kernel']))
                context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', path.as_uri()))
                context.symbol_space.append(IntermediateSymbolTable(context, 'gui', 'gui', layout.as_uri(), class_types=gui.GUIExtensions.class_types, table_mapping={'nt_symbols': 'kernel'}))
                wnd = context.object('gui!tagWND', 'memory', window)
                desk = context.object('gui!tagDESKTOP', 'memory', desktop)
                def result(call):
                    try:
                        return dict(value=call())
                    except Exception as error:
                        return dict(error=type(error).__name__)
                def address(obj):
                    return None if obj is None else int(obj.vol.offset)
                def owner():
                    p = wnd.get_process()
                    if p is None:
                        return None
                    from volatility3.framework.objects import utility
                    return dict(process=int(p.vol.offset), name=utility.array_to_string(p.ImageFileName), pid=int(p.UniqueProcessId))
                results = dict(name=result(wnd.get_name), desktop=result(lambda: address(wnd.get_desktop())),
                               session=result(wnd.get_session_id), procedure=result(wnd.get_window_procedure),
                               owner=result(owner), top=result(lambda: int(desk.pDeskInfo.spwnd)))
            cases.append(dict(layout=seed['layout'], scenario=scenario, size=len(data), window=window,
                              desktop=desktop, holes=holes, results=results,
                              writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]))
    assert len(cases) == 12 * len(SCENARIOS)
    for case in cases:
        if case['scenario'] == 'normal':
            assert case['results']['owner'] == dict(value=dict(process=0xe000, name='first', pid=100))
            assert case['results']['session'] == dict(value=1)
            assert case['results']['top'] == dict(value=0x10000)
            assert case['results']['procedure']['value'] in (0x87654321, 0x123456789abcdef0)
            assert case['results']['name']['value'] in ('Window', 'Direct')
    return json.dumps(dict(commit=COMMIT, scope=__doc__, kernel=seeds['kernel'], layouts=seeds['layouts'], cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('GUI window oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original GUI window controls verified')


if __name__ == '__main__':
    main()
