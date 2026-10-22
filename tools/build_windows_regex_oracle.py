#!/usr/bin/env python3
"""Run pinned Windows VAD regex scanning on actual paged process/VAD objects."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_suspended_threads_oracle import fixture

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/engine/testdata/windows-regex-oracle.json'


def generate(source):
    if sys.version_info[:2] != (3, 12):
        raise ValueError('requires Python 3.12, matching CI')
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.plugins.windows.vadregexscan import VadRegExScan

    samples = [
        ('literal', 'MATCH', b'xxMATCHyy'),
        ('dotall', 'A.*B', b'A\nxB'),
        ('backreference', r'(AB)\1', b'ABAB'),
        ('lookbehind', r'(?<=xx)MATCH', b'xxMATCH'),
        ('utf8-pattern', 'é+', 'éé'.encode()),
        ('escaped-byte', r'\xff+', b'\xff\xff'),
        ('context-too-short', 'A{140}', b'A' * 140),
        ('zero-width', '(?=MATCH)', b'MATCH'),
        ('invalid', '(', b'MATCH'),
        ('no-vads', 'MATCH', b'MATCH'),
        ('invalid-no-vads', '(', b'MATCH'),
        ('missing-page', 'MATCH', b'MATCH'),
        ('vad-edge', 'XYZMATCH', b'MATCH'),
        ('adjacent-vads', 'XYZMATCH', b'MATCH'),
        ('padded-context', 'MATCH', b''),
        ('invalid-name', 'MATCH', b'MATCH'),
        ('pid-match', 'MATCH', b'MATCH'),
        ('pid-mismatch', 'MATCH', b'MATCH'),
        ('invalid-pid-mismatch', '(', b'MATCH'),
    ]
    cases = []
    for arch, layer_class in [('x86', Intel), ('pae', IntelPAE), ('x64', Intel32e)]:
        width = 8 if arch == 'x64' else 4
        for name, pattern, payload in samples:
            kernel, _, data = fixture(width, 'normal')
            # Small pages provide independent scan/context acquisition holes.
            if arch == 'x64':
                struct.pack_into('<Q', data, 0xa000, 0xb003)
                table, entry = 0xb000, 8
            elif arch == 'pae':
                struct.pack_into('<Q', data, 0x8000, 0x9003)
                struct.pack_into('<Q', data, 0x9000, 0xa003)
                table, entry = 0xa000, 8
            else:
                struct.pack_into('<I', data, 0x8000, 0x9003)
                table, entry = 0x9000, 4
            for index in range(512 if entry == 8 else 1024):
                struct.pack_into('<Q' if entry == 8 else '<I', data,
                                 table + index * entry, index * 4096 | 3)
            data[0x100000:0x104000] = bytes(0x4000)
            data[0x100000:0x100000 + len(payload)] = payload
            if name.endswith('no-vads'):
                struct.pack_into('<Q' if width == 8 else '<I', data, 0x430, 0)
            if name == 'missing-page':
                data[table + 0x100 * entry:table + 0x101 * entry] = bytes(entry)
            if name == 'vad-edge':
                data[0x103ffc:0x104004] = b'XYZMATCH'
            if name == 'adjacent-vads':
                struct.pack_into('<Q' if width == 8 else '<I', data, 0x1008, 0x1100)
                struct.pack_into('<Q' if width == 8 else '<I', data, 0x1110, 0x1000)
                struct.pack_into('<II', data, 0x1118, 0x104, 0x104)
                bias = 12 if width == 8 else 4
                data[0x1100-bias:0x1104-bias] = b'VadS'
                data[0x103ffc:0x104004] = b'XYZMATCH'
            if name == 'padded-context':
                data[0x103ff8:0x103ffd] = b'MATCH'
                data[table + 0x104 * entry:table + 0x105 * entry] = bytes(entry)
            if name == 'invalid-name':
                data[0x418:0x428] = b'main\xff.exe\0' + bytes(6)
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
            context.config['memory.memory_layer'] = 'physical'
            context.config['memory.page_map_offset'] = 0x8000
            context.config['memory.kernel_virtual_offset'] = 0x10000
            context.layers.add_layer(layer_class(context, 'memory', 'memory'))
            expected, error = [], None
            with tempfile.TemporaryDirectory(prefix='gomem-windows-regex-') as directory:
                path = Path(directory) / 'kernel.json'
                path.write_text(json.dumps(kernel))
                classes = {n: getattr(extensions, n.lstrip('_')) for n in
                           ('_EPROCESS', '_LIST_ENTRY', '_MMVAD', '_MMVAD_SHORT')}
                classes['_RTL_BALANCED_NODE'] = extensions.MMVAD_SHORT
                context.symbol_space.append(IntermediateSymbolTable(
                    context, 'symbols', 'kernel', path.as_uri(), class_types=classes))
                context.module('kernel', 'memory', 0x10000)
                runner = SimpleNamespace(context=context, config={'maxsize': 4},
                                         MAXSIZE_DEFAULT=128, _progress_callback=lambda *_: None)
                try:
                    pids = [108] if name.endswith('pid-mismatch') else [104] if name == 'pid-match' else []
                    processes = PsList.list_processes(context, 'kernel', filter_func=PsList.create_pid_filter(pids))
                    for _, row in VadRegExScan._generator(runner, pattern, processes):
                        expected.append([int(row[0]), str(row[1]), int(row[2]),
                                         str(row[3]), bytes(row[4]).hex()])
                except Exception as exc:
                    error = type(exc).__name__ + ': ' + str(exc)
            writes = [dict(offset=at, data=data[at:at + 256].hex())
                      for at in range(0, len(data), 256) if any(data[at:at + 256])]
            cases.append(dict(name=name, arch=arch, pattern=pattern, configured_maxsize=4,
                              pid=pids, isf=kernel, size=len(data), writes=writes, rows=expected, error=error))
    for arch in ('x86', 'pae', 'x64'):
        selected = {c['name']: c for c in cases if c['arch'] == arch}
        assert len(selected['literal']['rows']) == 1
        assert selected['literal']['rows'][0][0:3] == [104, 'main.exe', 0x100002]
        assert selected['invalid']['error'] is not None
        # Unlike Linux's null-mm early skip, Windows constructs its scanner
        # even when the process has no VAD sections.
        assert selected['invalid-no-vads']['error'] is not None
        assert selected['no-vads']['rows'] == []
        assert selected['vad-edge']['rows'] == []
        assert selected['adjacent-vads']['rows'][0][2] == 0x103ffc
        assert selected['padded-context']['rows'][0][2] == 0x103ff8
        assert selected['invalid-pid-mismatch']['error'] is None
    return json.dumps(dict(commit=COMMIT, python='3.12', scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('Windows regex oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} actual Windows VAD regex generator cases verified')


if __name__ == '__main__':
    main()
