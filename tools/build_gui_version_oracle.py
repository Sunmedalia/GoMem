#!/usr/bin/env python3
"""Exercise original GUI table selection, PE tuple quirks and symbol fallbacks."""
import argparse
import base64
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import random
import sys
import tempfile
from urllib.parse import unquote, urlparse

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/wingui/testdata/version-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.plugins.windows.windowstations import WindowStations

    rules = WindowStations._win_version_file_map
    checks = sorted({tuple(c) for rule, _ in rules for c in rule._fallback_checks}, key=str)
    typed = sorted({name for name, member, _ in checks if member is not None})
    names = sorted({name for name, member, _ in checks if member is None})
    members = sorted({(name, member) for name, member, _ in checks if member is not None})
    def kernel(width):
        return dict(metadata={'format': '6.2.0'},
                    base_types={'pointer': dict(kind='int', size=width, signed=False, endian='little'),
                                'u8': dict(kind='int', size=1, signed=False, endian='little')},
                    user_types={'_CONTROL': dict(kind='struct', size=8, fields={})}, enums={}, symbols={})
    def features(doc, present_types, present_members, present_names, symbol_names=()):
        for name in sorted(present_types | present_names):
            doc['user_types'][name] = dict(kind='struct', size=64, fields={})
        for name, member in sorted(present_members):
            if name in doc['user_types']:
                doc['user_types'][name]['fields'][member] = dict(offset=0, type=dict(kind='base', name='u8'))
        for name in sorted(symbol_names):
            doc['symbols'][name] = dict(address=0)
    inputs = []
    def add(label, doc): inputs.append((label, doc))
    # Numeric metadata boundaries, including real revision/build order and the
    # tempting but incorrect swap. The original requires four tuple elements.
    versions = [(5, 1, 2600), (6, 0, 6002), (6, 1, 7600), (6, 1, 7601), (6, 2, 9200), (6, 3, 9600)]
    for build in [10585, 10586, 10587, 15062, 15063, 15064, 16298, 16299, 16300,
                  17133, 17134, 17135, 17762, 17763, 17764, 18361, 18362, 18363,
                  19040, 19041, 19042, 19576, 19577, 19578, 22621, 26000]:
        versions.append((10, 0, build))
    for width in (4, 8):
        for major, minor, revision in versions:
            for shape in ('four', 'three', 'swapped'):
                doc = kernel(width)
                features(doc, set(typed), set(members), set(names))
                pe = dict(major=major, minor=minor, revision=revision)
                if shape == 'four': pe['build'] = 0
                if shape == 'swapped': pe.update(revision=0, build=revision)
                doc['metadata']['windows'] = dict(pe=pe)
                add(f'metadata-{width}-{major}.{minor}.{revision}-{shape}', doc)
    # Malformed metadata is deliberately accepted by the actual symbol table
    # with validate=False; these exercise selector behavior, not schema parsing.
    for index, pe in enumerate([None, [], 'bad', {},
                               dict(major=10, minor=0, revision=19577, build=None),
                               dict(major=10, minor=0, revision=19577, build='unused'),
                               dict(major=11, minor='unused', revision=[], build={}),
                               dict(major='10', minor=0, revision=19577, build=0),
                               dict(major=True, minor=0, revision=19577, build=0),
                               dict(major=10.0, minor=0.0, revision=19577.0, build=0),
                               dict(major=10, minor=0, revision=19576.5, build=0),
                               dict(major=1e100, minor=0, revision=0, build=0)]):
        doc = kernel(8)
        features(doc, set(typed), set(), set())
        doc['metadata']['windows'] = dict(pe=pe)
        add(f'malformed-metadata-{index}', doc)
    # Actual fallback condition vectors, mutated one feature at a time, and
    # deterministic mixed inputs. Missing-type behavior is intentionally kept.
    for index, (rule, filename) in enumerate(rules):
        required_members = {(n, m) for n, m, present in rule._fallback_checks if m and present}
        required_names = {n for n, m, present in rule._fallback_checks if m is None and present}
        doc = kernel(8)
        features(doc, set(typed), required_members, required_names)
        add(f'fallback-rule-{index}-{filename}', doc)
        for name in typed:
            altered = copy.deepcopy(doc)
            del altered['user_types'][name]
            add(f'fallback-rule-{index}-missing-{name}', altered)
    rng = random.Random(0x19577)
    for index in range(512):
        doc = kernel(8)
        present_types = {n for n in typed if rng.randrange(2)}
        present_members = {v for v in members if rng.randrange(2)}
        present_names = {n for n in names if rng.randrange(2)}
        symbol_names = {n for n in names if rng.randrange(2)}
        features(doc, present_types, present_members, present_names, symbol_names)
        add(f'fallback-mixed-{index}', doc)
    cases = []
    with tempfile.TemporaryDirectory(prefix='gomem-gui-version-') as directory:
        path = Path(directory) / 'kernel.json'
        for label, doc in inputs:
            path.write_text(json.dumps(doc))
            context = contexts.Context()
            context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri(), validate=False))
            try:
                table = WindowStations.create_gui_table(context, 'kernel', 'plugins.GUI')
                url = context.symbol_space[table].config['isf_url']
                filename = Path(unquote(urlparse(url).path)).stem
                rule = next(rule for rule, name in rules if name == filename)
                try:
                    major, minor, revision, build = context.symbol_space['kernel'].metadata.pe_version
                    rule._version_check((major, minor, revision, build))
                    method = 'metadata'
                except (AttributeError, ValueError, TypeError):
                    method = 'symbol-fallback'
                result = dict(name=filename, method=method)
            except NotImplementedError:
                result = dict(error='unsupported')
            cases.append(dict(label=label, isf=doc, result=result))
    catalog = {}
    for path in sorted((source / 'volatility3/framework/symbols/windows/gui').glob('*.json')):
        raw = path.read_bytes()
        output = io.BytesIO()
        with gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as target:
            target.write(raw)
        catalog[path.stem] = dict(sha256=hashlib.sha256(raw).hexdigest(), source_gzip_base64=base64.b64encode(output.getvalue()).decode())
    assert len(catalog) == 12
    return json.dumps(dict(commit=COMMIT, scope=__doc__, catalog=catalog, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('GUI version oracle drift')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} actual original GUI layout selections verified')


if __name__ == '__main__':
    main()
