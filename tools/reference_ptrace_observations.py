#!/usr/bin/env python3
"""Observe tasks yielded to the locked ptrace plugin without changing selection.

Run the unmodified plugin separately for its authoritative TreeGrid differential.
This instrumented run adds an enumeration probe so an empty result can also be
checked against the actual inspected task objects and ptrace state.
"""
import argparse
import contextlib
import json
from pathlib import Path
import sys

from baseline_matrix import ROOT, tree_digest
from reference import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(args.source) != lock['python_tree_sha256']:
        raise ValueError('ptrace observations require pinned Python source')
    config = args.output.with_suffix('.config.json')
    plugin_output = args.output.with_suffix('.plugin.json')
    manifest = args.output.with_suffix('.manifest.json')
    if any(p.exists() for p in (args.output, config, plugin_output, manifest)):
        raise ValueError('choose new output paths; never overwrite')
    image_hash = digest(args.image)
    sys.path.insert(0, str(args.source.resolve()))
    import volatility3.cli
    from volatility3.plugins.linux import pslist
    from volatility3.framework.objects import utility

    original = pslist.PsList.list_tasks.__func__
    rows = []
    calls = 0

    def observing(cls, *args, **kwargs):
        nonlocal calls
        calls += 1
        if kwargs.get('include_threads') is not True:
            raise ValueError('ptrace probe expected include_threads=True')
        for task in original(cls, *args, **kwargs):
            rows.append({'Process': utility.array_to_string(task.comm), 'PID': int(task.tgid),
                'TID': int(task.pid), 'Offset': int(task.vol.offset), 'PtraceRaw': int(task.ptrace),
                'IsBeingTraced': task.is_being_ptraced, 'IsTracer': task.is_ptracing, '__children': []})
            yield task

    pslist.PsList.list_tasks = classmethod(observing)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sys.argv = ['vol.py', '--offline', '-q', '--cache-path', str(ROOT / '.cache/reference-cache'),
                '-s', str(args.symbols.resolve()), '-f', str(args.image.resolve()),
                '--save-config', str(config.resolve()), '-r', 'json', 'linux.ptrace.Ptrace']
    with plugin_output.open('x', encoding='utf-8') as out, contextlib.redirect_stdout(out):
        volatility3.cli.main()
    if calls != 1 or not isinstance(json.loads(plugin_output.read_text()), list):
        raise ValueError('unexpected ptrace observation run')
    with args.output.open('x', encoding='utf-8') as out:
        out.write(json.dumps(rows, indent=2) + '\n')
    manifest.write_text(json.dumps(dict(
        scope='instrumented task-yield observations; original task listing and ptrace selection are retained; separate unmodified plugin differential required',
        baseline=lock, image_sha256=image_hash, output_sha256=digest(args.output),
        plugin_output_sha256=digest(plugin_output), config_sha256=digest(config),
        probe_sha256=digest(Path(__file__)), listing_calls=calls, observed_tasks=len(rows), python=sys.version,
    ), indent=2) + '\n')
    print(f'{len(rows)} tasks observed through the original listing; separate unmodified output required')


if __name__ == '__main__':
    main()
