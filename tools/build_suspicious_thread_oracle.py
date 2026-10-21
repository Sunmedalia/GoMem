#!/usr/bin/env python3
"""Record pinned suspicious-thread range and note semantics without invoking the native implementation."""
import argparse
import itertools
import json
from pathlib import Path
import sys
from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-suspicious-thread-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('suspicious thread oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.windows.malware.suspicious_threads import SuspiciousThreads
    checker = object.__new__(SuspiciousThreads)
    cases = []
    for address, protection, path, exe in itertools.product(
        [0, 0x1000, 0x1800, 0x1ffe, 0x1fff, 0x2000],
        ['PAGE_EXECUTE_WRITECOPY', 'PAGE_EXECUTE_READWRITE', 'PAGE_READONLY', 'PAGE_EXECUTE_WRITECOPY|PAGE_GUARD', ''],
        [None, '', r'C:\main.exe', r'c:\MAIN.EXE', r'C:\other.exe', r'C:\module.dll', 'Σ.exe', 'ς.exe'],
        ['', r'C:\main.exe', 'Σ.exe']):
        ranges = [(0x1000,0x1fff,protection,path)]
        expected = list(checker._check_thread_address(exe,ranges,address))
        cases.append(dict(exe_path=exe,address=address,ranges=ranges,expected=expected))
    # Overlapping smeared VADs preserve first-preorder-match semantics.
    ranges = [(0x1000,0x2fff,'PAGE_EXECUTE_WRITECOPY',r'C:\main.exe'),(0x1800,0x1fff,'PAGE_READWRITE',None)]
    cases.append(dict(exe_path=r'C:\main.exe',address=0x1900,ranges=ranges,expected=list(checker._check_thread_address(r'C:\main.exe',ranges,0x1900))))
    return json.dumps(dict(commit=COMMIT,cases=cases),ensure_ascii=False,indent=2)+'\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT))
    p.add_argument('--check',action='store_true')
    args = p.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('suspicious-thread oracle differs')
    else:
        OUTPUT.write_text(result)
    print('721 pinned suspicious-thread range/note cases verified')


if __name__ == '__main__':
    main()
