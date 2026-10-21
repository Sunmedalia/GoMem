#!/usr/bin/env python3
"""Exercise the pinned IOMem traversal with explicit per-call seen sets."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-iomem-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('iomem oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.linux.iomem import IOMem
    from volatility3.framework.objects import utility
    from volatility3.framework import exceptions, renderers

    def node(name, start=0, end=0xffff, child=-1, sibling=-1):
        return dict(raw=name.encode().hex(), start=start, end=end, child=child, sibling=sibling)

    cases = []
    graphs = {
        'root': [node('PCI mem')],
        'tree': [node('root', child=1), node('one', child=2, sibling=3), node('deep'), node('last')],
        'root-sibling': [node('root', sibling=1), node('other')],
        'self-child': [node('root', child=0)],
        'self-sibling': [node('root', sibling=0)],
        'ancestor-loop': [node('root', child=1), node('one', child=0, sibling=2), node('last')],
        'shared-node': [node('root', child=1), node('one', child=2, sibling=2), node('shared')],
        'inverted': [node('inverted', start=100, end=1)],
        'uint64': [node('full', end=(1 << 64)-1)],
        'empty-name': [node('')],
        'nul-name': [dict(node('before'), raw=b'before\0after'.hex())],
        'utf8-name': [node('资源')],
        'invalid-utf8': [dict(node(''), raw=b'ab\xffcd'.hex())],
        'replacement': [node('ab\ufffdcd')],
        'name-bound': [node('a' * 150)],
        'unreadable-name': [dict(node(''), unreadable_name=True)],
        'bad-child': [dict(node('root', child=1, sibling=2)), dict(node('bad'), invalid=True), node('last')],
    }
    for name, nodes in graphs.items():
        addresses = [0x1d000 + i * 0x80 for i in range(len(nodes))]
        def obj(_, address, absolute=True):
            n = nodes[addresses.index(int(address))]
            if n.get('invalid'):
                raise exceptions.InvalidAddressException('test', int(address))
            return SimpleNamespace(name=n, start=n['start'], end=n['end'],
                child=addresses[n['child']] if n['child'] >= 0 else 0,
                sibling=addresses[n['sibling']] if n['sibling'] >= 0 else 0)
        def decode(n, count):
            if n.get('unreadable_name'):
                raise exceptions.InvalidAddressException('test', 0x300000)
            raw = bytes.fromhex(n['raw'])[:count]
            raw += b'\0' * (count - len(raw))
            return utility.bytes_to_decoded_string(raw, encoding="utf-8", errors="replace")
        context = SimpleNamespace(modules={'kernel': SimpleNamespace(object=obj)})
        with patch.object(utility, 'pointer_to_string', side_effect=decode):
            rows = [dict(depth=d, name=None if isinstance(v[0], renderers.UnreadableValue) else v[0], start=int(v[1]), end=int(v[2]))
                    for d, v in IOMem.parse_resource(context, 'kernel', addresses[0], seen=set())]
        cases.append(dict(name=name, nodes=nodes, rows=rows))
    return json.dumps(dict(commit=COMMIT, cases=cases), indent=2, ensure_ascii=False) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('iomem oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} pinned resource traversal cases verified')


if __name__ == '__main__':
    main()
