#!/usr/bin/env python3
"""Capture pinned PsXView name filtering, dictionary collisions and view precedence."""
import argparse
import datetime
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-psxview-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('psxview oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.windows.malware.psxview import PsXView
    from volatility3.plugins.windows import pslist
    checker = object.__new__(PsXView)
    checker._config_cache = {'kernel': 'kernel'}
    checker._context = SimpleNamespace()
    checker._proc_name_to_string = lambda p: p.name
    names = [chr(value) for value in range(256)] + ['', 'System', 'csrss.exe', 'a1.exe', 'task-host', 'task_host', ' white space ', '.exe', 'Σ.exe', '进程.exe', 'A\x00B']
    name_cases = [dict(name=name, expected=checker._is_valid_proc_name(name)) for name in names]
    merges = []
    for collision in [False, True]:
        for bits in range(1, 16):
            specs = [dict(id='a', offset=0x1220, pid=104, name='A.exe', valid=True, exited=False),
                     dict(id='b', offset=0x2220, pid=104, name='B.exe', valid=True, exited=True),
                     dict(id='c', offset=0x3220, pid=108, name='C.exe', valid=True, exited=False),
                     dict(id='invalid', offset=0x4220, pid=6, name='bad.exe', valid=False, exited=False),
                     dict(id='name', offset=0x5220, pid=116, name='bad1.exe', valid=True, exited=False)]
            procs = {}
            for spec in specs:
                exited = datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc) if spec['exited'] else None
                procs[spec['id']] = SimpleNamespace(vol=SimpleNamespace(offset=spec['offset']), name=spec['name'], UniqueProcessId=spec['pid'], is_valid=lambda value=spec['valid']: value, get_exit_time=lambda value=exited: value)
            inputs = []
            for index in range(4):
                ids = ['a', 'a'] if bits & (1 << index) else []
                if (bits + index) % 3 == 0:
                    ids += ['b', 'c']
                inputs.append(ids + ['invalid', 'name'])
            checker._translate_offset = (lambda offset: offset & 0xfff) if collision else (lambda offset: offset)
            checker._check_psscan = lambda: checker._proc_list_to_dict(procs[key] for key in inputs[1])
            checker._check_thrdscan = lambda: checker._proc_list_to_dict(procs[key] for key in inputs[2])
            checker._check_csrss_handles = lambda tasks: checker._proc_list_to_dict(procs[key] for key in inputs[3])
            with patch.object(pslist.PsList, 'list_processes', return_value=[procs[key] for key in inputs[0]]):
                expected = sorted((list(row) for _, row in checker._generator()), key=lambda row: row[0])
            merges.append(dict(collision=collision, processes=specs, inputs=inputs, expected=expected))
    return json.dumps(dict(commit=COMMIT, names=name_cases, merges=merges), ensure_ascii=False, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('psxview oracle differs')
    else:
        OUTPUT.write_text(result)
    data = json.loads(result)
    print(f'{len(data["names"])} name and {len(data["merges"])} pinned psxview merge cases verified')


if __name__ == '__main__':
    main()
