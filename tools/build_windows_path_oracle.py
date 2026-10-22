#!/usr/bin/env python3
"""Validate Windows module-path helpers and Unicode 16 casing against Python."""
import argparse
import json
from pathlib import Path
import sys
import unicodedata
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT/'pkg/winpath/testdata/path-oracle.json'
FULL_OUTPUT = ROOT/'pkg/winpath/testdata/unicode16-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires locked baseline')
    sys.path.insert(0, str(source))
    from volatility3.plugins.windows.pe_symbols import PESymbols
    from volatility3.framework.symbols.windows import pdbutil
    names = ['', 'x', 'xy', 'abc', 'fixture.dll', 'NTOSKRNL.EXE', 'İ.dll', 'ß.dll', 'ΟΣ.dll', 'ΟΣ', 'Σ', 'ΣΣ', 'AΣ', 'AΣ\u0301', 'AΣ\u0301A', 'AΣ\u200d', 'AΣ\u200dA', 'AΣ.A', 'AΣ\u0345', '\ufb03.dll', '\u01f0.dll', '\U00010400.dll', '\U0001f600.dll', '中文.dll', 'x:y.dll']
    prefixes = ['', 'C:', 'C:\\', '\\', '\\\\server\\share\\', '//server/share/', '\\\\?\\UNC\\server\\share\\', '\\\\?\\C:\\', '\\\\.\\device\\', 'C:\\Windows/mixed/', '\U0001f600:']
    suffixes = ['', '\\', '/', '\\tail.DLL']
    paths = list(dict.fromkeys(prefix+name+suffix for prefix in prefixes for name in names for suffix in suffixes))
    paths += ['\\\\server', '\\\\server\\share', '//server/share', '\\\\?\\UNC\\server\\share', '\\\\?\\UNC', '\\\\?\\C:', 'C:', '\\', '/', '::tail', 'C:\\x\\D:tail']
    cases = []
    for path in paths:
        name = PESymbols.filename_for_path(path)
        candidates = []
        # Only the acquisition boundary is substituted. Candidate construction
        # runs inside the actual pinned _get_pdb_module method.
        def acquire(*args, **kwargs):
            candidates.append(args[3])
            return None
        with patch.object(pdbutil.PDBUtility, 'symbol_table_from_pdb', side_effect=acquire):
            PESymbols._get_pdb_module(None, 'fixture', name, ('module', 0x1000, 0x4000))
        cases.append(dict(path=path, name=name, candidates=candidates))
    lowers = list(dict.fromkeys(names + [left+'Σ'+right for left in ('', 'A', '1', 'a\u0301', 'a\u200d', 'a\u0345', '\u0345') for right in ('', 'A', '1', '\u0301', '\u200d', '\u0345', "'A", '.A', '\u0301A', '\u200dA')]))
    return json.dumps(dict(commit=COMMIT, cases=cases, casing=[dict(input=s, lower=s.lower(), upper_initial=s[:1].upper()+s[1:]) for s in lowers]), ensure_ascii=True, indent=2)+'\n'


def full_generate():
    if unicodedata.unidata_version != '16.0.0':
        raise ValueError('full Unicode reference requires Python with Unicode 16.0.0 (Python 3.14)')
    rows = []
    for code in range(0x110000):
        if 0xd800 <= code <= 0xdfff:
            continue
        char = chr(code)
        lower, upper = char.lower(), char.upper()
        ignored = ('AΣ'+char+'A').lower()[1] == 'σ' and ('AΣ'+char).lower()[1] == 'ς'
        cased = (char+'Σ').lower().endswith('ς')
        if lower != char or upper != char or ignored or cased:
            rows.append(dict(code=code, lower=lower, upper=upper, ignored=ignored, effective_cased=cased))
    return json.dumps(dict(unicode_version='16.0.0', scalar_values=0x110000-0x800, rows=rows), ensure_ascii=True, indent=2)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = full_generate() if args.full else generate(args.source)
    output = FULL_OUTPUT if args.full else OUTPUT
    if args.check:
        if output.read_text() != result:
            raise ValueError('Windows path/casing oracle differs')
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result)
    data = json.loads(result)
    print(f"Unicode scalar reference: {data['scalar_values']} values" if args.full else f"{len(data['cases'])} pinned Windows path/candidate and {len(data['casing'])} casing cases verified")


if __name__ == '__main__':
    main()
