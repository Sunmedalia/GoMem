#!/usr/bin/env python3
"""Record locked Linux boot datetime and namespace de-duplication semantics."""
import argparse
import datetime
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-boottime-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('boottime oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.framework.symbols.linux.extensions import Timespec64Concrete, task_struct
    from volatility3.plugins.linux.boottime import Boottime
    from volatility3.plugins.linux import pslist

    def display(nanos):
        value = Timespec64Concrete.new_from_nsec(nanos).to_datetime()
        return value.isoformat() if isinstance(value, datetime.datetime) else None

    values = [0, -1, 1, 499, 500, 501, 500000000, 999999499, 999999500, 999999999,
              1403605353691776031, 1700000000123456789, 253402300799999999999,
              253402300800000000000, 18446744073709551615000000000]
    for sec in [1, 1403605353, 1700000000, 2147483647, 253402300799]:
        for nanos in [0, 1, 499, 500, 501, 999, 1000, 123456499, 123456500, 123456501, 999999499, 999999500, 999999999]:
            values.append(sec * 1000000000 + nanos)
    timestamps = [dict(nanos=str(n), display=display(n)) for n in sorted(set(values))]

    scenarios = {
        'legacy': [None, None], 'zero': [0, 0], 'separate-zero': [None, 0],
        'distinct': [42, 43], 'duplicate': [42, 42], 'reversed': [43, 42],
    }
    groups = []
    for name, ids in scenarios.items():
        tasks = []
        for i, number in enumerate(ids):
            root, offset = 1700000000123456789, i * 1000000001
            task = SimpleNamespace(get_time_namespace_id=lambda number=number: number)
            task._get_boottime_raw = lambda root=root: Timespec64Concrete.new_from_nsec(root)
            task._get_time_namespace_boottime_offset = lambda offset=offset: Timespec64Concrete.new_from_nsec(offset)
            task.get_boottime = lambda root_time_namespace, task=task: task_struct.get_boottime(task, root_time_namespace)
            tasks.append(task)
        with patch.object(pslist.PsList, 'list_tasks', return_value=tasks):
            rows = list(Boottime.get_time_namespaces_bootime(SimpleNamespace(modules={}), 'kernel'))
        groups.append(dict(name=name, ids=ids, rows=[dict(id=n, display=v.isoformat()) for n, v in rows]))
    return json.dumps(dict(commit=COMMIT, timestamps=timestamps, groups=groups), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('boottime oracle differs')
    else:
        OUTPUT.write_text(result)
    data = json.loads(result)
    print(f'{len(data["timestamps"])} pinned boot datetime cases and {len(data["groups"])} namespace groups verified')


if __name__ == '__main__':
    main()
