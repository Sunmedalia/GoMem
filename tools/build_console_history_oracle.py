#!/usr/bin/env python3
"""Exercise unmodified conhost command/history extensions against byte-backed ISFs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winconsole/testdata/history-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import consoles

    layouts, cases = {}, []
    scenarios = ['normal', 'zero-length', 'inline-seven', 'pointer-eight', 'length-1023', 'length-1024', 'length-1025', 'allocated-zero', 'allocated-1025', 'length-over-allocated', 'embedded-nul', 'bom-big', 'bom-little', 'unpaired-surrogate', 'reversed-small', 'reversed-large', 'unaligned-end', 'last-negative', 'last-too-large', 'handle-zero', 'handle-unaligned', 'handle-large', 'unused-slot', 'length-hole', 'pointer-hole', 'text-hole', 'handle-hole', 'capacity-small', 'capacity-large', 'maximum-zero', 'bucket-hole', 'bucket-text-hole', 'empty-allocated-hole', 'invalid-count-handle-hole', 'invalid-last-handle-hole']
    for path in sorted((source / 'volatility3/framework/symbols/windows/consoles').glob('*.json')):
        layout = json.loads(path.read_text())
        layouts[path.stem] = dict(isf=layout, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        def off(typ, name):
            return layout['user_types'][typ]['fields'][name]['offset']
        for scenario in scenarios:
            data, holes = bytearray(0x8000), []
            def put(at, value, size=8):
                data[at:at + size] = value.to_bytes(size, 'little', signed=value < 0)
            cmd, history, bucket, handle, text = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000
            length = {'zero-length': 0, 'empty-allocated-hole': 0, 'inline-seven': 7, 'pointer-eight': 8, 'length-1023': 1023, 'length-1024': 1024, 'length-1025': 1025}.get(scenario, 4)
            allocated = 0 if scenario == 'allocated-zero' else 1025 if scenario == 'allocated-1025' else 1 if scenario == 'length-over-allocated' else 1024
            raw = ('X' * length).encode('utf-16-le')
            if scenario == 'embedded-nul': raw = b'A\0\0\0B\0C\0'
            if scenario == 'bom-big': raw = b'\xfe\xff\0A\0B\0C'
            if scenario == 'bom-little': raw = b'\xff\xfeA\0B\0C\0'
            if scenario == 'unpaired-surrogate': raw = b'\0\xd8A\0\0\xdcB\0'
            if length < 8: data[cmd:cmd + len(raw)] = raw
            else:
                put(cmd + off('_COMMAND', 'Pointer'), text)
                data[text:text + len(raw)] = raw
            put(cmd + off('_COMMAND', 'Length'), length, 4)
            put(cmd + off('_COMMAND', 'Allocated'), allocated, 4)
            size = layout['user_types']['_COMMAND']['size']
            begin = history + off('_COMMAND_HISTORY', 'CommandBucket')
            put(begin + off('_VECTOR', 'Begin'), bucket)
            end = bucket + 2 * size
            if scenario == 'reversed-small': end = bucket - 1
            if scenario in ('reversed-large', 'invalid-count-handle-hole'): end = bucket - size
            if scenario == 'unaligned-end': end += 1
            put(begin + off('_VECTOR', 'End'), end)
            put(begin + off('_VECTOR', 'EndCapacity'), bucket + (size if scenario == 'capacity-small' else 5 * size if scenario == 'capacity-large' else 3 * size))
            put(history + off('_COMMAND_HISTORY', 'CommandCountMax'), 0 if scenario == 'maximum-zero' else 1, 2)
            put(history + off('_COMMAND_HISTORY', 'ConsoleProcessHandle'), handle)
            put(history + off('_COMMAND_HISTORY', 'LastDisplayed'), -2 if scenario in ('last-negative', 'invalid-last-handle-hole') else 51 if scenario == 'last-too-large' else -1, 2)
            put(handle + off('_CONSOLE_PROCESS_HANDLE', 'ProcessHandle'), {'handle-zero': 0, 'handle-unaligned': 3, 'handle-large': 0x10000}.get(scenario, 4), 4)
            data[history + off('_COMMAND_HISTORY', 'Application'):history + off('_COMMAND_HISTORY', 'Application') + size] = data[cmd:cmd + size]
            data[bucket:bucket + size] = data[cmd:cmd + size]
            if scenario in ('unused-slot', 'capacity-small', 'capacity-large', 'maximum-zero'): data[bucket + 2*size:bucket + 3*size] = data[cmd:cmd + size]
            if scenario == 'capacity-large': data[bucket + 4*size:bucket + 5*size] = data[cmd:cmd + size]
            if scenario == 'bucket-hole': holes.append((bucket + off('_COMMAND', 'Length'), 4))
            if scenario == 'bucket-text-hole': holes.append((bucket, 2))
            if scenario == 'empty-allocated-hole':
                holes.append((cmd + off('_COMMAND', 'Allocated'), 4))
                holes.append((bucket + off('_COMMAND', 'Allocated'), 4))
            if scenario == 'length-hole': holes.append((cmd + off('_COMMAND', 'Length'), 4))
            if scenario == 'pointer-hole':
                put(cmd + off('_COMMAND', 'Length'), 8, 4)
                holes.append((cmd + off('_COMMAND', 'Pointer'), 8))
            if scenario == 'text-hole': holes.append((cmd, 2))
            if scenario in ('handle-hole', 'invalid-count-handle-hole', 'invalid-last-handle-hole'): holes.append((handle + off('_CONSOLE_PROCESS_HANDLE', 'ProcessHandle'), 4))
            class OriginalLayer(BufferDataLayer):
                def read(self, at, length, pad=False):
                    for start, size in holes:
                        if at < start + size and start < at + length:
                            raise exceptions.InvalidAddressException(self.name, max(at, start))
                    return super().read(at, length, pad)
            context = contexts.Context()
            context.layers.add_layer(OriginalLayer(context, 'memory', 'memory', bytes(data)))
            context.symbol_space.append(IntermediateSymbolTable(context, 'console', 'console', path.as_uri(), class_types=consoles.win10_x64_class_types))
            c = context.object('console!_COMMAND', 'memory', cmd)
            h = context.object('console!_COMMAND_HISTORY', 'memory', history)
            def result(call):
                try: return dict(value=call())
                except exceptions.InvalidAddressException: return dict(error='read')
            def rows(active):
                return [dict(index=i, address=int(c.vol.offset), valid=c.is_valid(), text=c.get_command_string()) for i, c in (h.get_commands() if active else h.scan_command_bucket())]
            results = {name: result(call) for name, call in [('valid', c.is_valid), ('text', c.get_command_string), ('count', lambda: h.CommandCount), ('history_valid', h.is_valid), ('application', h.get_application), ('active', lambda: rows(True)), ('scan', lambda: rows(False))]}
            writes = [dict(offset=at, data=bytes(data[at:at+256]).hex()) for at in range(0, len(data), 256) if any(data[at:at+256])]
            cases.append(dict(layout=path.stem, scenario=scenario, size=len(data), writes=writes, holes=holes, results=results))
    return json.dumps(dict(commit=COMMIT, scope=__doc__, layouts=layouts, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('console history oracle drift; regenerate explicitly')
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} original console history controls verified')


if __name__ == '__main__':
    main()
