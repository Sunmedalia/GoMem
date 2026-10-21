#!/usr/bin/env python3
"""Record the pinned credential-sharing generator's grouping/skip semantics."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-check-creds-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('check_creds oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.linux.malware.check_creds import Check_creds
    from volatility3.plugins.linux import pslist

    class Pointer(int):
        def __new__(cls, address, readable):
            value = int.__new__(cls, address)
            value.readable = readable
            return value

        def is_readable(self):
            return self.readable

        def dereference(self):
            return SimpleNamespace(vol=SimpleNamespace(offset=int(self)))

    scenarios = {
        'empty': [],
        'distinct': [(100, 0x1c800, True), (101, 0x1c820, True)],
        'shared': [(100, 0x1c800, True), (101, 0x1c800, True)],
        'same-pid': [(100, 0x1c800, True), (100, 0x1c800, True)],
        'reverse-pids': [(101, 0x1c800, True), (100, 0x1c800, True)],
        'null': [(100, 0, True), (101, 0x1c800, True)],
        'unreadable': [(100, 0x1c800, False), (101, 0x1c800, True)],
        'late-shared': [(10, 0x200, True), (20, 0x100, True), (30, 0x100, True), (40, 0x200, True)],
        'partial-group': [(10, 0x100, True), (20, 0x100, False), (30, 0x100, True)],
    }
    module = SimpleNamespace(name='kernel', get_type=lambda _: SimpleNamespace(has_member=lambda _: True))
    checker = SimpleNamespace(context=SimpleNamespace(modules={'kernel': module}), config={'kernel': 'kernel'})
    cases = []
    for name, inputs in scenarios.items():
        tasks = [SimpleNamespace(pid=pid, cred=Pointer(address, readable)) for pid, address, readable in inputs]
        with patch.object(pslist.PsList, 'list_tasks', return_value=tasks):
            rows = [dict(CredVAddr=hex(int(values[0])), PIDs=values[1]) for _, values in Check_creds._generator(checker)]
        cases.append(dict(name=name, tasks=[dict(pid=p, cred=hex(a), readable=r) for p, a, r in inputs], rows=rows))
    return json.dumps(dict(commit=COMMIT, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('check_creds oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} pinned credential-sharing cases verified')


if __name__ == '__main__':
    main()
