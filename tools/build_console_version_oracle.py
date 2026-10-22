#!/usr/bin/env python3
"""Run original conhost version selection with real Intel, KUSER, debug and physical fallback objects."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winconsole/testdata/version-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows.extensions import consoles
    from volatility3.plugins.windows.consoles import Consoles

    templates = json.loads((ROOT / 'internal/plugins/testdata/windows-network-version-oracle.json').read_text())
    assert templates['commit'] == COMMIT
    cases, memories = [], {}
    for arch, cls in [('x86', Intel), ('pae', IntelPAE), ('x64', Intel32e)]:
        template = next(c for c in templates['cases'] if c['arch'] == arch and c['major'] == 10 and c['build'] == 19041)
        memories[arch] = {k: template[k] for k in ('isf', 'size', 'writes')}
        for major, minor, build in [(5, 1, 2600), (6, 1, 7601), (10, 1, 30000)] + [(10, 0, b) for b in [1, 17762, 17763, 17764, 18362, 18363, 19041, 20348, 20349, 22000, 22621, 22622, 25398, 26000]]:
            for revision in [0, 1, 1969, 1970, 2460, 2461, 2519, 2520, 3231, 3232, 3526, 3527, 65535]:
                data = bytearray(template['size'])
                for w in template['writes']:
                    raw = bytes.fromhex(w['data']); data[w['offset']:w['offset']+len(raw)] = raw
                struct.pack_into('<HH', data, 0x1000, 15, build)
                struct.pack_into('<II', data, 0x18000, major, minor)
                if revision:
                    marker = 0x22000
                    raw = ('OriginalFilename\0CONHOST.EXE').encode('utf-16be')
                    data[marker:marker+len(raw)] = raw
                    data[marker-0x400:marker-0x3fc] = b'\xbd\x04\xef\xfe'
                    # Deliberately different file/product revisions expose the
                    # original physical fallback's file-version choice.
                    struct.pack_into('<IHHHHHHHH', data, marker-0x3fc, 0x10000, 0, 10, revision, build, 0, 10, 17, build)
                context = contexts.Context()
                context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
                context.config['memory.memory_layer'] = 'physical'
                context.config['memory.page_map_offset'] = 0x8000
                context.layers.add_layer(cls(context, 'memory', 'memory'))
                with tempfile.TemporaryDirectory(prefix='gomem-console-version-') as directory:
                    path = Path(directory) / 'kernel.json'; path.write_text(json.dumps(template['isf']))
                    context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri()))
                    context.module('kernel', 'memory', 0)
                    try:
                        name, classes = Consoles.determine_conhost_version(context, 'plugins.Consoles', 'kernel', 'memory', 0x400000)
                        result = dict(name=name, win10_x64=classes is consoles.win10_x64_class_types)
                    except NotImplementedError:
                        result = dict(error='unsupported')
                cases.append(dict(arch=arch, width=template['width'], major=major, minor=minor, build=build, revision=revision, result=result))
    catalog = {p.stem: p.read_text() for p in sorted((source / 'volatility3/framework/symbols/windows/consoles').glob('*.json'))}
    return json.dumps(dict(commit=COMMIT, scope=__doc__, catalog=catalog, memories=memories, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('console version oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} original console version selections verified')


if __name__ == '__main__':
    main()
