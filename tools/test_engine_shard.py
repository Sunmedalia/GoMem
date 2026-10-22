#!/usr/bin/env python3
"""Run every engine test in exactly one stable CI shard, or all other packages."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ENGINE = 'github.com/Sunmedalia/GoMem/internal/engine'


def test_names(output):
    names = []
    for line in output.splitlines():
        if line.startswith(('Test', 'Fuzz', 'Example')):
            if not re.fullmatch(r'((Test|Fuzz)\w+|Example\w*)', line):
                raise ValueError(f'unsupported test name: {line!r}')
            names.append(line)
    if not names or len(names) != len(set(names)):
        raise ValueError('engine test discovery was empty or contained duplicates')
    return sorted(names)


def partitions(names, count):
    if not 1 <= count <= 4096:
        raise ValueError('shards must be 1..4096')
    groups = [[] for _ in range(count)]
    for name in names:
        index = int.from_bytes(hashlib.sha256(name.encode()).digest(), 'big') % count
        groups[index].append(name)
    # This audit is independent of the selection predicate used by Go's runner.
    assigned = [name for group in groups for name in group]
    if sorted(assigned) != sorted(names) or len(assigned) != len(set(assigned)):
        raise ValueError('sharding dropped or duplicated a test')
    return groups


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shard', type=int)
    parser.add_argument('--shards', type=int, default=4)
    parser.add_argument('--other-packages', action='store_true')
    parser.add_argument('--list-only', action='store_true')
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    if args.other_packages:
        if args.shard is not None or args.manifest:
            parser.error('other-packages cannot select an engine shard')
        packages = subprocess.check_output(['go', 'list', './...'], text=True).splitlines()
        if packages.count(ENGINE) != 1:
            raise ValueError('expected exactly one engine package')
        packages.remove(ENGINE)
        if not packages:
            raise ValueError('no other packages discovered')
        command = ['go', 'test', '-race', '-timeout', '30m', *packages]
    else:
        if args.shard is None or not 0 <= args.shard < args.shards:
            parser.error('shard must be 0..shards-1')
        output = subprocess.check_output(['go', 'test', '-list', '.', ENGINE], text=True)
        names = test_names(output)
        groups = partitions(names, args.shards)
        selected = groups[args.shard]
        if not selected:
            raise ValueError('selected shard is empty; refusing a false passing run')
        expression = '^(' + '|'.join(re.escape(name) for name in selected) + ')$'
        manifest = dict(schema='gomem.engine-test-shard/v1', shard=args.shard,
                        shards=args.shards, total_tests=len(names), selected=selected,
                        all_groups=groups, all_tests_exactly_once=True,
                        regex=expression)
        if args.manifest:
            args.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
        print(f'Engine shard {args.shard}/{args.shards}: {len(selected)}/{len(names)} tests and fuzz seed functions', flush=True)
        command = ['go', 'test', '-race', '-timeout', '30m', '-count=1', '-run', expression, ENGINE]
    if not args.list_only:
        subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
