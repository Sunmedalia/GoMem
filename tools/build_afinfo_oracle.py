#!/usr/bin/env python3
"""Run pinned AFINFO layout selection, member filtering and generator helpers."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-afinfo-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import exceptions
    from volatility3.plugins.linux.malware.check_afinfo import Check_afinfo

    class Ops:
        def __init__(self, values):
            self.values = values
        def member(self, attr):
            return self.values[attr]
        def has_member(self, name):
            return name in self.values
        def __getattr__(self, name):
            return self.values[name]

    members = ['write', 'owner', '__UNIQUE_ID_rh_kabi_hide_one', 'next']
    seq_members = ['stop', 'show', 'start', 'next']
    variants = ['legacy', 'modern', 'seq-show', 'seq-show-zero', 'seq-show-and-ops',
        'embedded-fops', 'global-pointer', 'all-absent', 'legacy-slide',
        'seq-show-slide', 'seq-show-relative-known', 'fops-only']
    cases = []
    for variant in variants:
        legacy = variant not in ('modern', 'global-pointer', 'all-absent')
        slide = variant in ('legacy-slide', 'seq-show-slide', 'seq-show-relative-known')
        globals_ = {}
        for i in range(2):
            fops = Ops(dict(zip(members, [0x8501, 0, 0xdeadbeef, 0x8500])))
            seq = Ops(dict(start=0, stop=0x8600, next=0x8500, show=0x8500))
            if legacy:
                values = dict(seq_fops=fops, seq_ops=seq)
                if variant in ('seq-show', 'seq-show-zero', 'seq-show-slide', 'seq-show-relative-known'):
                    del values['seq_ops']
                    values['seq_show'] = {'seq-show-zero': 0, 'seq-show-slide': 0x8500,
                        'seq-show-relative-known': 0x7500}.get(variant, 0x8600)
                if variant == 'seq-show-and-ops':
                    values['seq_show'] = 0xdeadbeef
                if variant == 'fops-only':
                    del values['seq_ops']
                globals_[['tcp4_seq_afinfo', 'udp4_seq_afinfo'][i]] = Ops(values)
            else:
                globals_[['raw_seq_ops', 'udp_seq_ops'][i]] = seq
        if variant == 'all-absent':
            globals_ = {}
        def get_type(name):
            if name == 'tcp_seq_afinfo':
                return Ops(dict(seq_fops=1) if legacy else {})
            return SimpleNamespace(members=members if name == 'file_operations' else seq_members)
        def from_symbol(name):
            if name not in globals_:
                raise exceptions.SymbolError(name, 'kernel')
            return globals_[name]
        kernel = SimpleNamespace(get_type=get_type, object_from_symbol=from_symbol,
            get_symbols_by_absolute_location=lambda at: ['alias_handler', 'known_handler'] if at == 0x8500 else [],
            get_symbols_by_location=lambda at: ['alias_handler', 'known_handler'] if at == (0x7500 if slide else 0x8500) else [])
        context = SimpleNamespace(modules={'kernel': kernel})
        instance = SimpleNamespace(context=context, config={'kernel': 'kernel'}, check_afinfo=Check_afinfo.check_afinfo)
        handlers = []
        try:
            for _, row in Check_afinfo._generator(instance):
                handlers.append(dict(global_=row[0], member=row[1], address=int(row[2])))
            error = False
        except exceptions.VolatilityException:
            error = True
        handlers = [dict(global_name=r['global_'], member=r['member'], address=r['address']) for r in handlers]
        cases.append(dict(name=variant, handlers=handlers, error=error))
    return json.dumps(dict(commit=COMMIT, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('AFINFO oracle differs')
    else:
        OUTPUT.write_text(result)
    print('12 pinned AFINFO layout/member/generator cases verified')


if __name__ == '__main__':
    main()
