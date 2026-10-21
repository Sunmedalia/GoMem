#!/usr/bin/env python3
"""Observe locked AFINFO member checks while delegating original decisions.

Use a separate unmodified reference.py run for the authoritative plugin table.
The probe covers _check_members (pre/post layouts), not the direct seq_show path.
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
        raise ValueError('AFINFO observations require pinned source')
    config = args.output.with_suffix('.config.json')
    plugin_output = args.output.with_suffix('.plugin.json')
    manifest = args.output.with_suffix('.manifest.json')
    if any(p.exists() for p in (args.output, config, plugin_output, manifest)):
        raise ValueError('choose new output paths; never overwrite')
    image_hash = digest(args.image)
    sys.path.insert(0, str(args.source.resolve()))
    import volatility3.cli
    from volatility3.framework import objects
    from volatility3.plugins.linux.malware.check_afinfo import Check_afinfo

    original = Check_afinfo._check_members.__func__
    rows, calls = [], 0

    def observing(cls, context, vmlinux_name, var_ops, var_name, members):
        nonlocal calls
        calls += 1
        kernel = context.modules[vmlinux_name]
        base = int(var_ops) if isinstance(var_ops, objects.Pointer) else var_ops.vol.offset
        for member in members:
            ignored = member.startswith('__UNIQUE_ID_rh_kabi_hide')
            address = None if ignored else int(var_ops.member(attr=member))
            names = [] if ignored or not address else list(kernel.get_symbols_by_absolute_location(address))
            status = 'ignored_rh_kabi_member' if ignored else ('unimplemented_zero' if not address else ('known_exact_symbol' if names else 'unknown_exact_symbol'))
            rows.append({'Symbol Name': var_name, 'Member': member, 'Handler Address': address,
                'OperationAddress': int(base), 'Status': status, 'ExactSymbols': [n.split('!', 1)[-1] for n in names], '__children': []})
        yield from original(cls, context, vmlinux_name, var_ops, var_name, members)

    Check_afinfo._check_members = classmethod(observing)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sys.argv = ['vol.py', '--offline', '-q', '--cache-path', str(ROOT / '.cache/reference-cache'),
        '-s', str(args.symbols.resolve()), '-f', str(args.image.resolve()),
        '--save-config', str(config.resolve()), '-r', 'json', 'linux.malware.check_afinfo.Check_afinfo']
    with plugin_output.open('x', encoding='utf-8') as out, contextlib.redirect_stdout(out):
        volatility3.cli.main()
    if calls == 0 or not isinstance(json.loads(plugin_output.read_text()), list):
        raise ValueError('AFINFO probe did not observe member checks')
    if tree_digest(args.source) != lock['python_tree_sha256']:
        raise ValueError('reference source changed during observation')
    with args.output.open('x', encoding='utf-8') as out:
        out.write(json.dumps(rows, indent=2) + '\n')
    manifest.write_text(json.dumps(dict(scope='instrumented _check_members observations; original checker delegated; direct seq_show path is not probed; separate unmodified table differential required',
        baseline=lock, image_sha256=image_hash, output_sha256=digest(args.output),
        plugin_output_sha256=digest(plugin_output), config_sha256=digest(config),
        probe_sha256=digest(Path(__file__)), member_calls=calls, observed_members=len(rows), python=sys.version), indent=2) + '\n')
    print(f'{len(rows)} operation members observed in {calls} checks; separate unmodified output required')


if __name__ == '__main__':
    main()
