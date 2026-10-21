#!/usr/bin/env python3
"""Record pinned ptrace flags, task selection and relationship tree displays."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-ptrace-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('ptrace oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.framework.constants.linux import PT_FLAGS
    from volatility3.framework.symbols.linux.extensions import task_struct
    from volatility3.framework.objects import utility
    from volatility3.framework import renderers
    from volatility3.plugins.linux.ptrace import Ptrace
    from volatility3.plugins.linux import pslist

    members = [int(f.value) for f in PT_FLAGS]
    values = [sum(bit for i, bit in enumerate(members) if subset & (1 << i)) for subset in range(1 << len(members))]
    values += [2, 4, 1 << 17, 1 << 31, (1 << 64)-1]
    flags = []
    for value in values:
        try:
            flags.append(dict(raw=str(value), display=PT_FLAGS(value).flags, error=False))
        except ValueError:
            flags.append(dict(raw=str(value), display=None, error=True))

    def node(name='init', pid=100, tgid=100, ptrace=0, parent_tid=101, tracees=(), next_readable=True):
        return dict(name=name, pid=pid, tgid=tgid, ptrace=ptrace, parent_tid=parent_tid,
                    tracees=list(tracees), next_readable=next_readable)

    class Task:
        is_being_ptraced = task_struct.is_being_ptraced
        is_ptracing = task_struct.is_ptracing
        get_ptrace_tracer_tid = task_struct.get_ptrace_tracer_tid
        get_ptrace_tracee_tids = task_struct.get_ptrace_tracee_tids
        get_ptrace_tracee_flags = task_struct.get_ptrace_tracee_flags

        def __init__(self, n):
            self.comm = n['name']
            self.pid, self.tgid, self.ptrace = n['pid'], n['tgid'], n['ptrace']
            self.parent = SimpleNamespace(pid=n['parent_tid'])
            address = 0x1000 + self.pid * 0x100
            self.ptraced = SimpleNamespace(vol=SimpleNamespace(offset=address))
            target = address + 0x100000 if n['tracees'] else address
            self.ptraced.next = SimpleNamespace(is_readable=lambda: n['next_readable'],
                dereference=lambda: SimpleNamespace(vol=SimpleNamespace(offset=target)))
            self.ptraced.to_list = lambda *args: [SimpleNamespace(pid=p) for p in n['tracees']]

        def get_symbol_table_name(self):
            return 'kernel'

    scenarios = {
        'negative': [node()], 'tracee': [node(ptrace=1)],
        'tracer': [node(tracees=[200])], 'both': [node(ptrace=0x10009, tracees=[200, 201, 202])],
        'empty-tracee-list': [node(ptrace=8)], 'zero-tracer-tid': [node(ptrace=1, parent_tid=0)],
        'zero-tracee-tid': [node(tracees=[0])], 'duplicate-tracee-tid': [node(tracees=[200, 200])],
        'unreadable-tracer-next': [node(tracees=[200], next_readable=False)],
        'unknown-flags': [node(ptrace=2)],
        'thread': [node(name='worker0', pid=200, tgid=100, ptrace=1)],
        'two-groups': [node(tracees=[200, 201]), node(name='other', pid=101, tgid=101, ptrace=1)],
    }
    cases = []
    for name, inputs in scenarios.items():
        instance = SimpleNamespace(context=SimpleNamespace(modules={}))
        instance.enumerate_ptrace_tasks = lambda *args: Ptrace.enumerate_ptrace_tasks(*args)
        try:
            with patch.object(pslist.PsList, 'list_tasks', return_value=[Task(n) for n in inputs]) as listing, patch.object(utility, 'array_to_string', side_effect=lambda x: x):
                rows = [dict(depth=d, process=v[0], pid=int(v[1]), tid=int(v[2]),
                    tracer=None if isinstance(v[3], renderers.NotAvailableValue) else int(v[3]),
                    tracee=None if isinstance(v[4], renderers.NotAvailableValue) else int(v[4]),
                    flags=None if isinstance(v[5], renderers.NotAvailableValue) else v[5])
                    for d, v in Ptrace._generator(instance, 'kernel')]
                assert listing.call_args.kwargs['include_threads'] is True
            error = False
        except ValueError:
            rows, error = [], True
        cases.append(dict(name=name, tasks=inputs, rows=rows, error=error))
    return json.dumps(dict(commit=COMMIT, flags=flags, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('ptrace oracle differs')
    else:
        OUTPUT.write_text(result)
    data = json.loads(result)
    print(f'{len(data["flags"])} pinned flag values and {len(data["cases"])} ptrace generator cases verified')


if __name__ == '__main__':
    main()
