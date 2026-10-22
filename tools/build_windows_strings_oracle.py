#!/usr/bin/env python3
"""Actual locked Strings parser and generator over real paged process objects."""
import argparse
import io
import json
from pathlib import Path
import random
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_suspended_threads_oracle import fixture

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/engine/testdata/windows-strings-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('requires locked unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import WindowsIntel, WindowsIntel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.plugins.windows.strings import Strings

    parser = SimpleNamespace(strings_pattern=Strings.strings_pattern)
    parsed = []
    samples = [b'123', b'123\n', b'123 x', b'0 a', b'0 a\n', b'!0 !!value\r\n',
               b'0 _x', b'x123 value\n', b'999999999999999999999999999999 x\n',
               b'0 \xffab\n', b'0 abc\x00\xff\n', b'0 x\nremaining', b'\n', b'']
    rng = random.Random(20261022)
    alphabet = b'0123456789 _-!\n\x00abcXYZ\xff'
    samples += [bytes(rng.choice(alphabet) for _ in range(rng.randrange(40))) for _ in range(1024)]
    for line in samples:
        try:
            offset, string = Strings._parse_line(parser, line)
            parsed.append(dict(raw=line.hex(), offset=str(offset), text=string.hex()))
        except ValueError:
            parsed.append(dict(raw=line.hex(), error=True))
    cases = []
    scenarios = ('normal', 'second', 'filter-match', 'filter-miss', 'invalid-lines',
                 'greedy-lines', 'latin1', 'empty', 'table-hole', 'uniform-root',
                 'transition', 'high-pfn')
    for width in (4, 8):
        for scenario in scenarios:
            kernel, _, data = fixture(width, 'running')
            def put(at, value):
                struct.pack_into('<Q' if width == 8 else '<I', data, at, value)
            def root(at, entries):
                if width == 8:
                    put(at, at+0x1000|3)
                    put(at+0x1000, at+0x2000|3)
                    put(at+0x2000, at+0x3000|3)
                    table = at+0x3000
                else:
                    put(at, at+0x1000|3)
                    table = at+0x1000
                for virtual, physical, flags in entries:
                    put(table+((virtual>>12) & (511 if width == 8 else 1023))*width, physical|flags)
            if width == 4:
                data[0x8000:0xa000] = bytes(0x2000)
                put(0x8000, 0x9003)
                for index in range(512):
                    put(0x9000+index*4, index*4096|3)
            entries = [(0x100000, 0x180000, 3), (0x101000, 0x181000, 3),
                       (0x103000, 0x180000, 3), (0x104000, 0x1a0000, 3)]
            if scenario == 'transition':
                entries += [(0x105000, 0x1b0000, 0x800)]
            if scenario == 'high-pfn' and width == 8:
                entries[0] = (0x100000, 0x180000 | (1<<45), 3)
            root(0x20000, entries)
            put(0x450, 0x20000)
            if width == 8:
                # Separate high kernel aliases with non-contiguous physical pages.
                data[0x40000:0x43000] = bytes(0x3000)
                put(0x8000+256*8, 0x40003)
                put(0x40000, 0x41003)
                put(0x41000, 0x42003)
                put(0x42000, 0x180003)
                put(0x42008, 0x190003)
            if scenario in ('second', 'filter-match', 'filter-miss'):
                put(0x18080+width, 0x500)
                put(0x400, 0x500)
                put(0x500, 0x18080)
                put(0x500+width, 0x400)
                put(0x550, 0x30000)
                root(0x30000, [(0x100000, 0x1c0000, 3), (0x101000, 0x1c1000, 3), (0x107000, 0x180000, 3)])
            if scenario == 'table-hole':
                # Missing child outside the captured physical layer.
                put(0x20000, 0x300003)
            if scenario == 'uniform-root':
                data[0x20000:0x21000] = bytes(4096)
            text = b'1572864 alpha\n1048576 beta\n1576960 gamma\n1048577 delta\n0 null\n2048 xxx\n2097152 outside\n1769472 transition\n'
            if scenario == 'empty':
                text = b''
            elif scenario == 'invalid-lines':
                text += b'bad input\n0 a\n999999999999999999999999999999 overflows\n'
            elif scenario == 'greedy-lines':
                text = b'123\n123 x\n123\n0 a\n0 a'
            elif scenario == 'latin1':
                text = b'1572864 abc\xff\x00\r\n1048576 __\x80\n'
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
            context.config['memory.memory_layer'] = 'physical'
            context.config['memory.page_map_offset'] = 0x8000
            context.config['memory.kernel_virtual_offset'] = 0x10000
            context.layers.add_layer((WindowsIntel32e if width == 8 else WindowsIntel)(context, 'memory', 'memory'))
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'kernel.json'
                path.write_text(json.dumps(kernel))
                context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(),
                    class_types={name:getattr(extensions, name.lstrip('_')) for name in ('_EPROCESS', '_LIST_ENTRY')}))
                context.module('kernel', 'memory', 0x10000)
                input_path = Path(tmp) / 'strings.txt'
                input_path.write_bytes(text)
                pids = [108] if scenario == 'filter-match' else [999] if scenario == 'filter-miss' else None
                runner = SimpleNamespace(context=context, config={'kernel':'kernel', 'pid':pids, 'strings_file':input_path.as_uri()},
                    _progress_callback=lambda *_args: None, _parse_line=lambda line:Strings._parse_line(parser, line), generate_mapping=Strings.generate_mapping)
                expected = []
                for _, row in Strings._generator(runner):
                    expected.append([row[0], str(int(row[1])), sorted(row[2].split(', '))])
            # Oversized Python integers are an explicit native unsupported offset.
            expected_native = [r for r in expected if int(r[1]) <= (1<<64)-1]
            cases.append(dict(width=width, name=scenario, isf=kernel, size=len(data), input=text.hex(),
                writes=[dict(offset=at, data=bytes(data[at:at+256]).hex()) for at in range(0,len(data),256) if any(data[at:at+256])],
                expected=expected, expected_native=expected_native))
    return json.dumps(dict(commit=COMMIT, parser=parsed, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=ROOT / ('.cache/volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise SystemExit('Windows strings oracle drift')
    else:
        OUTPUT.write_text(result)
    print('24 actual paged Windows Strings generators and 1038 parser cases verified')


if __name__ == '__main__':
    main()
