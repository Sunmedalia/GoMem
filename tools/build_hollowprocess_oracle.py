#!/usr/bin/env python3
"""Record the pinned hollow-process checks, including exact rendered notes."""
import argparse
import itertools
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-hollowprocess-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('hollow-process oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.windows.malware.hollowprocesses import HollowProcesses, VadData, DLLData
    from volatility3.framework.renderers import UnreadableValue
    checker = object.__new__(HollowProcesses)
    cases = []
    for image, protection, path, present, mode in itertools.product(
        [None, 0, 0x1000, 0x2000],
        ['PAGE_EXECUTE_WRITECOPY', 'PAGE_EXECUTE_READWRITE', 'PAGE_READONLY', 'PAGE_EXECUTE_WRITECOPY|PAGE_GUARD', '', 'PAGE_EXECUTE'],
        [None, '', r'C:\main.exe', 'Σ.exe'],
        [False, True],
        ['normal', 'unreadable', 'empty']):
        proc = SimpleNamespace(SectionBaseAddress=0x1000)
        checker._get_image_base = lambda p: image
        vads = {0x2000: VadData(protection, '<Non-File Backed Region>' if not path else path)}
        if present:
            vads[0x1000] = VadData(protection, '<Non-File Backed Region>' if not path else path)
        dll_path = r'C:\module.dll' if mode == 'normal' else (None if mode == 'unreadable' else '')
        dlls = {base: DLLData(UnreadableValue() if dll_path is None else dll_path) for base in [0x1000, 0x2000, 0x3000]}
        expected = []
        for check in [checker._check_load_address, checker._check_exe_protection, checker._check_dlls_protection]:
            expected.extend(check(proc, vads, dlls))
        cases.append(dict(section=0x1000, image=image, vads=[dict(base=base, protection=data.protection, path=path) for base, data in vads.items()], dlls=[dict(base=base, path=dll_path) for base in dlls], expected=expected))
    return json.dumps(dict(commit=COMMIT, cases=cases), ensure_ascii=False, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('hollow-process oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} pinned hollow-process note cases verified')


if __name__ == '__main__':
    main()
