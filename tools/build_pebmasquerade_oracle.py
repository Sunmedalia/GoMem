#!/usr/bin/env python3
"""Exercise the pinned PEB generator, including its swapped output columns."""
import argparse
import itertools
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-pebmasquerade-oracle.json'


class Descriptor:
    def __init__(self, length, maximum, fault=False):
        self.Length = length
        self.maximum = maximum
        self.fault = fault

    @property
    def MaximumLength(self):
        if self.fault:
            raise AttributeError('missing MaximumLength')
        return self.maximum


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('PEB oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.windows.malware.pebmasquerade import PebMasquerade
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.framework.renderers import NotAvailableValue
    checker = object.__new__(PebMasquerade)
    cases = []
    texts = [None, '', 'A', 'AB', '😀', 'A\ufffd']
    for index, (text, length, maximum, mode) in enumerate(itertools.product(
            texts, [0, 1, 2, 4], [0, 2, 4, 8], ['normal', 'maximum_fault', 'no_peb'])):
        command = texts[(texts.index(text) + 3) % len(texts)]
        cmd_length = (length + 2) % 8
        cmd_maximum = (maximum + 4) % 10
        peb = SimpleNamespace(ProcessParameters=SimpleNamespace(
            ImagePathName=Descriptor(length, maximum, mode == 'maximum_fault'),
            CommandLine=Descriptor(cmd_length, cmd_maximum))) if mode != 'no_peb' else None
        proc = SimpleNamespace(UniqueProcessId=100, get_peb=lambda: peb)
        names = ('proc.exe', NotAvailableValue(),
                 NotAvailableValue() if text is None else text,
                 NotAvailableValue() if command is None else command)
        with patch.object(PsList, 'list_processes', return_value=[proc]), \
                patch.object(PebMasquerade, 'get_process_names', return_value=names):
            row = list(checker._generator(None, None, 'kernel'))[0][1]
        cases.append(dict(text=text, length=length, maximum=maximum, command=command,
                          command_length=cmd_length, command_maximum=cmd_maximum, mode=mode,
                          # Read these directly from the generator, not inferred names.
                          path_spoofed=row[4], command_spoofed=row[5]))
    return json.dumps(dict(commit=COMMIT, cases=cases), ensure_ascii=False, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('PEB oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} pinned PEB generator cases verified')


if __name__ == '__main__':
    main()
