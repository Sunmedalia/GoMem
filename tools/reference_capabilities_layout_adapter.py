#!/usr/bin/env python3
"""Run the locked capability plugin with an explicit legacy typedef adapter.

This is a diagnostic helper comparison, NOT an unmodified plugin differential.
Old ISFs call a cap[2] struct kernel_cap_t. The locked kernel_cap_t extension
only accepts .val and aborts. Dispatch only that method by the actual layout;
all decoding, task enumeration and rendering still use the locked source.
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
    parser.add_argument('--pids', type=int, nargs='+')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(args.source) != lock['python_tree_sha256']:
        raise ValueError('layout adapter requires pinned Python source')
    config = args.output.with_suffix('.config.json')
    manifest = args.output.with_suffix('.manifest.json')
    if any(p.exists() for p in (args.output, config, manifest)):
        raise ValueError('choose new output/config/manifest paths; never overwrite')
    image_hash = digest(args.image)
    sys.path.insert(0, str(args.source.resolve()))
    from volatility3.framework.symbols.linux import extensions
    import volatility3.cli
    original = extensions.kernel_cap_t.get_capabilities
    adaptations = 0

    def by_layout(self):
        nonlocal adaptations
        if self.has_member('val'):
            return original(self)
        adaptations += 1
        return extensions.kernel_cap_struct.get_capabilities(self)

    extensions.kernel_cap_t.get_capabilities = by_layout
    args.output.parent.mkdir(parents=True, exist_ok=True)
    parameters = ['--pids', *map(str, args.pids)] if args.pids else []
    sys.argv = ['vol.py', '--offline', '-q', '--cache-path', str(ROOT / '.cache/reference-cache'),
                '-s', str(args.symbols.resolve()), '-f', str(args.image.resolve()),
                '--save-config', str(config.resolve()), '-r', 'json',
                'linux.capabilities.Capabilities', *parameters]
    with args.output.open('x', encoding='utf-8') as out, contextlib.redirect_stdout(out):
        volatility3.cli.main()
    rows = json.loads(args.output.read_text())
    if not isinstance(rows, list):
        raise ValueError('no TreeGrid rows from adapted run')
    manifest.write_text(json.dumps(dict(
        scope='explicit legacy capability layout adapter; NOT unmodified plugin parity',
        baseline=lock, image_sha256=image_hash, output_sha256=digest(args.output),
        config_sha256=digest(config), adapter_sha256=digest(Path(__file__)),
        adaptations=adaptations, parameters=parameters, rows=len(rows), python=sys.version,
    ), indent=2) + '\n')
    print(f'{len(rows)} adapted rows; {adaptations} legacy helper calls; unmodified parity NOT established')


if __name__ == '__main__':
    main()
