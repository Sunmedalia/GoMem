#!/usr/bin/env python3
"""Exercise original console screen/row methods on all bundled byte-backed layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winconsole/testdata/screen-oracle.json'
SCENARIOS = ['normal', 'trailing-empty', 'all-empty', 'negative-start',
             'large-start', 'zero-capacity', 'negative-capacity', 'negative-length',
             'empty-row', 'all-attributes', 'unicode-high-byte', 'embedded-nul',
             'python-whitespace', 'unreadable-cells', 'unreadable-row-length',
             'unreadable-pointer', 'unreadable-second-row', 'capacity-hole', 'start-hole']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import consoles

    layouts, cases = {}, []
    for path in sorted((source / 'volatility3/framework/symbols/windows/consoles').glob('*.json')):
        raw = path.read_bytes()
        layout = json.loads(raw)
        layouts[path.stem] = dict(source=raw.decode(), sha256=hashlib.sha256(raw).hexdigest())
        types = layout['user_types']
        def off(typ, field):
            return types[typ]['fields'][field]['offset']
        indirect = types['_ROWS_ARRAY']['fields']['Rows']['type']['subtype']['name'] == '_ROW_POINTER'
        for scenario in SCENARIOS:
            data, holes = bytearray(0x10000), []
            def q(at, value): struct.pack_into('<Q', data, at, value)
            def h(at, value): struct.pack_into('<h', data, at, value)
            screen, buffer, rows = 0x1000, 0x2000, 0x4000
            q(screen + off('_SCREEN_INFORMATION', 'TextBufferInfo'), buffer)
            q(buffer + off('_TEXT_BUFFER_INFO', 'BufferRows'), rows)
            h(buffer + off('_TEXT_BUFFER_INFO', 'BufferCapacity'),
              0 if scenario == 'zero-capacity' else -1 if scenario == 'negative-capacity' else 3)
            h(buffer + off('_TEXT_BUFFER_INFO', 'BufferStart'),
              -1 if scenario == 'negative-start' else 32767 if scenario == 'large-start' else 0 if scenario == 'trailing-empty' else 1)
            addresses = []
            for index in range(3):
                at = 0x5000 + index * 0x400 if indirect else rows + index * types['_ROW']['size']
                addresses.append(at)
                if indirect:
                    q(rows + off('_ROWS_ARRAY', 'Rows') + index * types['_ROW_POINTER']['size'] + off('_ROW_POINTER', 'Row'), at)
                text = ['first ', 'middle ', ''][index]
                if scenario == 'all-empty': text = ' \t'
                if scenario == 'empty-row' and index == 0: text = ''
                if scenario == 'python-whitespace' and index == 0: text = 'A\x1c\x1d\x1e\x1f\x85\xa0\t '
                if scenario == 'embedded-nul' and index == 0: text = 'A\0B '
                if scenario == 'unicode-high-byte' and index == 0: text = 'A中\ud800\u0100B'
                cells = b''.join(struct.pack('<HB', ord(c), 0) for c in text)
                if scenario == 'all-attributes' and index == 0:
                    cells = b''.join(struct.pack('<HB', ord('A'), attr) for attr in range(256))
                length = len(cells) // 3
                q(at + off('_ROW', 'CharRow'), 0x8000 + index * 0x1000)
                h(at + off('_ROW', 'RowLength'), -1 if scenario == 'negative-length' and index == 0 else length)
                # In newer layouts RowLength and RowLength2 alias each other.
                h(at + off('_ROW', 'RowLength2'), -1 if scenario == 'negative-length' and index == 0 else length)
                start = 0x8000 + index * 0x1000 + off('_CHAR_ROW_CELL_ARRAY', 'Chars')
                data[start:start + len(cells)] = cells
            row = addresses[0]
            if scenario == 'unreadable-cells': holes.append([0x8000, 1])
            if scenario == 'unreadable-row-length': holes.append([row + off('_ROW', 'RowLength'), 2])
            if scenario == 'unreadable-pointer': holes.append([row + off('_ROW', 'CharRow'), 8])
            if scenario == 'unreadable-second-row': holes.append([addresses[1] + off('_ROW', 'RowLength'), 2])
            if scenario == 'capacity-hole': holes.append([buffer + off('_TEXT_BUFFER_INFO', 'BufferCapacity'), 2])
            if scenario == 'start-hole': holes.append([buffer + off('_TEXT_BUFFER_INFO', 'BufferStart'), 2])
            class OriginalLayer(BufferDataLayer):
                def read(self, at, length, pad=False):
                    for start, size in holes:
                        if at < start + size and start < at + length:
                            raise exceptions.InvalidAddressException(self.name, max(at, start))
                    return super().read(at, length, pad)
            ctx = contexts.Context()
            ctx.layers.add_layer(OriginalLayer(ctx, 'memory', 'memory', bytes(data)))
            ctx.symbol_space.append(IntermediateSymbolTable(ctx, 'console', 'console', path.as_uri(), class_types=consoles.win10_x64_class_types))
            r = ctx.object('console!_ROW', 'memory', row)
            s = ctx.object('console!_SCREEN_INFORMATION', 'memory', screen)
            def result(call):
                try: return dict(value=call())
                except Exception as error: return dict(error=type(error).__name__)
            results = {'row': result(lambda: r.get_text(False)),
                       'row_trimmed': result(r.get_text),
                       'x': result(lambda: int(s.ScreenX)),
                       'y': result(lambda: int(s.ScreenY))}
            for trim_rows in [False, True]:
                for trim_lines in [False, True]:
                    name = f'buffer_{int(trim_rows)}_{int(trim_lines)}'
                    results[name] = result(lambda: s.get_buffer(trim_rows, trim_lines))
            cases.append(dict(layout=path.stem, scenario=scenario, size=len(data),
                              row=row, screen=screen, holes=holes,
                              writes=[dict(offset=at, data=data[at:at + 256].hex()) for at in range(0, len(data), 256) if any(data[at:at + 256])],
                              results=results))
    assert len(cases) == 209 and len(layouts) == 11
    for c in cases:
        if c['scenario'] == 'normal':
            assert c['results']['buffer_1_1'] == dict(value=['middle', '', 'first'])
        if c['scenario'] == 'all-empty':
            assert c['results']['buffer_1_1'] == dict(value=[])
    return json.dumps(dict(commit=COMMIT, scope=__doc__, layouts=layouts, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('console screen oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} original console screen controls verified')


if __name__ == '__main__':
    main()
