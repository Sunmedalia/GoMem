#!/usr/bin/env python3
"""Run the unmodified GUI desktop window generator with mixed pointer offsets."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/wingui/testdata/window-walk-oracle.json'
SCENARIOS = ['normal', 'adjacent', 'root-cycle', 'adjacent-cycle', 'child',
             'siblings-with-children', 'shared-child', 'child-cycle', 'null-top',
             'next-hole', 'child-hole', 'name-hole', 'limit-one', 'limit-two']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions, objects
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import gui
    seeds = json.loads((ROOT / 'pkg/wingui/testdata/windows-oracle.json').read_text())
    if seeds['commit'] != COMMIT:
        raise ValueError('window seed baseline mismatch')
    cases = []
    for seed in seeds['cases']:
        if seed['scenario'] != 'normal':
            continue
        path = source / 'volatility3/framework/symbols/windows/gui' / (seed['layout'] + '.json')
        types = json.loads(path.read_text())['user_types']
        def off(typ, field):
            return types[typ]['fields'][field]['offset']
        for scenario in SCENARIOS:
            data, holes = bytearray(seed['size']), [(0, 0x1000)]
            for write in seed['writes']:
                raw = bytes.fromhex(write['data'])
                data[write['offset']:write['offset'] + len(raw)] = raw
            a, b, c, d = seed['window'], 0x15000, 0x16000, 0x17000
            def q(at, value):
                struct.pack_into('<Q', data, at, value)
            def node(at, index, adjacent=0, child=0):
                q(at + off('tagWND', 'spwndNext'), adjacent)
                q(at + off('tagWND', 'spwndChild'), child)
                text = chr(65 + index).encode('utf-16le')
                buffer = 0x18000 + 512 * index
                data[buffer:buffer + len(text) + 2] = text + b'\0\0'
                string = at + off('tagWND', 'strName')
                struct.pack_into('<I', data, string + off('_LARGE_UNICODE_STRING', 'Length'), len(text))
                q(string + off('_LARGE_UNICODE_STRING', 'Buffer'), buffer)
                if 'directName' in types['tagWND']['fields']:
                    q(at + off('tagWND', 'directName'), buffer)
            for index, at in enumerate([a, b, c, d]):
                node(at, index)
            if scenario in ('adjacent', 'root-cycle', 'adjacent-cycle', 'siblings-with-children', 'shared-child'):
                q(a + off('tagWND', 'spwndNext'), b)
            if scenario in ('adjacent', 'adjacent-cycle'):
                q(b + off('tagWND', 'spwndNext'), c)
            if scenario == 'root-cycle':
                q(b + off('tagWND', 'spwndNext'), a)
            if scenario == 'adjacent-cycle':
                q(c + off('tagWND', 'spwndNext'), b)
            if scenario in ('child', 'siblings-with-children', 'shared-child'):
                q(a + off('tagWND', 'spwndChild'), c)
            if scenario in ('siblings-with-children', 'shared-child'):
                q(b + off('tagWND', 'spwndChild'), c if scenario == 'shared-child' else d)
            if scenario == 'child-cycle':
                q(a + off('tagWND', 'spwndChild'), a)
            if scenario == 'null-top':
                q(0x14000 + off('tagDESKTOPINFO', 'spwnd'), 0)
            if scenario in ('next-hole', 'child-hole'):
                holes.append((a + off('tagWND', 'spwndNext' if scenario == 'next-hole' else 'spwndChild'), 8))
            if scenario == 'name-hole':
                holes.append((0x18000, 256))
            limit = 1 if scenario == 'limit-one' else 2 if scenario == 'limit-two' else 16

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
            rows, error = [], None
            with tempfile.TemporaryDirectory(prefix='gomem-gui-walk-') as directory:
                kernel = Path(directory) / 'kernel.json'
                kernel.write_text(json.dumps(seeds['kernel']))
                context.symbol_space.append(IntermediateSymbolTable(context, 'kernel', 'kernel', kernel.as_uri()))
                context.symbol_space.append(IntermediateSymbolTable(context, 'gui', 'gui', path.as_uri(), class_types=gui.GUIExtensions.class_types, table_mapping={'nt_symbols': 'kernel'}))
                desk = context.object('gui!tagDESKTOP', 'memory', seed['desktop'])
                # Bound the original runtime for its known recursive child
                # cycles without replacing or mocking a generator method.
                previous_limit = sys.getrecursionlimit()
                sys.setrecursionlimit(128)
                try:
                    for window, name in desk.windows(desk.pDeskInfo.spwnd, max_windows=limit):
                        rows.append(dict(offset=int(window.vol.offset), address=int(window) if isinstance(window, objects.Pointer) else int(window.vol.offset), name=name))
                except Exception as caught:
                    error = type(caught).__name__
                finally:
                    sys.setrecursionlimit(previous_limit)
            prefix = rows[:1]
            for row in rows[1:]:
                if row['offset'] != row['address']:
                    break
                prefix.append(row)
            # AggregateType uses identity hashes. Child iteration order is
            # allocation dependent; compare the full entities without that
            # unstable order and retain the stable adjacent prefix separately.
            cases.append(dict(layout=seed['layout'], scenario=scenario, desktop=seed['desktop'],
                              size=len(data), max_windows=limit, holes=holes, error=error,
                              rows=sorted(rows, key=lambda row: (row['offset'], row['address'])), prefix=prefix,
                              writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])]))
    assert len(cases) == 12 * len(SCENARIOS)
    for case in cases:
        if case['scenario'] == 'normal':
            assert len(case['rows']) == 2 and case['prefix'][0]['address'] == 0x10000
        if case['scenario'] == 'child-cycle':
            assert case['error'] == 'RecursionError'
    return json.dumps(dict(commit=COMMIT, scope=__doc__, kernel=seeds['kernel'], layouts=seeds['layouts'],
                           ordering='complete child entities normalized; adjacent prefix ordered', cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('GUI window traversal oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original GUI window traversal controls verified')


if __name__ == '__main__':
    main()
