#!/usr/bin/env python3
"""Record the pinned Linux PID hierarchy and renderer parent semantics."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-pstree-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('Linux pstree oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.linux.pstree import PsTree
    from volatility3.plugins.linux import pslist

    def node(tid, parent, tgid=None, address=None):
        return dict(tid=tid, ppid=parent, tgid=tid if tgid is None else tgid,
                    address=address if address is not None else 0x1000+tid*0x100)

    scenarios = {
        'empty': [], 'init': [node(1, 0)], 'kthreadd': [node(2, 0)],
        'normal': [node(1, 0), node(2, 0), node(100, 1), node(101, 100)],
        'reversed': [node(101, 100), node(100, 1), node(1, 0)],
        'sorted-children': [node(1, 0), node(30, 1), node(10, 1), node(20, 1)],
        'missing-parent': [node(100, 999), node(101, 100)],
        'smeared-zero-parent': [node(100, 0), node(101, 100)],
        'threads': [node(1, 0), node(100, 1), node(201, 1, 100), node(200, 1, 100)],
        'missing-leader': [node(200, 99, 100)],
        'swapper': [node(0, 0), node(1, 0), node(2, 0)],
        'self-cycle': [node(100, 100)], 'cycle': [node(100, 101), node(101, 100)],
        'cycle-child': [node(100, 101), node(101, 100), node(102, 100)],
        'cycle-init': [node(1, 1), node(100, 1)],
        'duplicate-tid': [node(100, 999), node(100, 1, address=0x9000), node(1, 0)],
        'same-offset': [node(1, 0, address=0x1000), node(100, 1, address=0x1000)],
        'filtered-child': [node(101, 100)],
        'thread-self': [node(100, 99, 200), node(200, 99, 100)],
    }
    cases = []
    for name, nodes in scenarios.items():
        tasks = [SimpleNamespace(pid=n['tid'], tgid=n['tgid'], vol=SimpleNamespace(offset=n['address']),
                    is_thread_group_leader=n['tid'] == n['tgid'], get_parent_pid=lambda n=n: n['ppid']) for n in nodes]
        instance = SimpleNamespace()
        instance.find_level = lambda pid: PsTree.find_level(instance, pid)
        def fields(task, decorate):
            return SimpleNamespace(offset=task.vol.offset, user_pid=task.tgid, user_tid=task.pid,
                                   user_ppid=task.get_parent_pid(), name=f'task-{task.pid}')
        with patch.object(pslist.PsList, 'get_task_fields', side_effect=fields):
            outputs = list(PsTree._generator(instance, tasks))
        previous = []
        rows = []
        for level, values in outputs:
            parent_index = min(len(previous), level)
            parent = previous[parent_index-1] if parent_index > 0 else None
            depth = 0 if parent is None else rows[parent]['depth']+1
            rows.append(dict(offset=int(values[0]), pid=int(values[1]), tid=int(values[2]), ppid=int(values[3]),
                             comm=values[4], generator_depth=level, depth=depth, parent_row=parent))
            previous = previous[:parent_index] + [len(rows)-1]
        cases.append(dict(name=name, nodes=nodes, rows=rows))
    return json.dumps(dict(commit=COMMIT, cases=cases), indent=2)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('Linux pstree oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} pinned Linux hierarchy cases verified')


if __name__ == '__main__':
    main()
