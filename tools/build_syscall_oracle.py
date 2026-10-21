#!/usr/bin/env python3
"""Exercise pinned syscall metadata/next-symbol sizing and fallback generator."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-syscall-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import exceptions
    from volatility3.plugins.linux.malware import check_syscall
    cls = check_syscall.Check_syscall
    check_syscall.has_capstone = False

    sizes = []
    for width in (4, 8):
        for metadata, following in ((0, 0), (0, 1), (0, 4), (2, 0), (2, 4), (6, 4), (6, 0), (0, 3)):
            names = {f'__syscall_meta__{i}': SimpleNamespace(address=0x7000+i) for i in range(metadata)}
            names.update(table=SimpleNamespace(address=0x18000), alias_table=SimpleNamespace(address=0x18000))
            if following:
                # A non-multiple distance exercises integer truncation.
                next_address = 0x18000 + width * following + (1 if following == 3 else 0)
                names.update(next_symbol=SimpleNamespace(address=next_address), alias_next=SimpleNamespace(address=next_address))
            kernel = SimpleNamespace(symbols=list(reversed(names)), symbol_table_name='test', get_symbol=lambda name: names[name])
            instance = SimpleNamespace(context=SimpleNamespace(symbol_space={'test': SimpleNamespace(symbols=names)}))
            instance._get_table_size_meta = lambda kernel: cls._get_table_size_meta(instance, kernel)
            instance._get_table_size_next_symbol = lambda address, width, kernel: cls._get_table_size_next_symbol(instance, address, width, kernel)
            try:
                selected, error = cls._get_table_info_other(instance, 0x18000, width, kernel), False
            except ValueError:
                selected, error = 0, True
            sizes.append(dict(width=width, metadata=metadata, following=following, symbols=[dict(name=name, address=symbol.address) for name, symbol in names.items()], selected=selected, error=error))

    cases = []
    for width in (4, 8):
        for variant in ('control', 'no-meta', 'meta-short', 'no-next', 'primary-only', 'slide', 'qualified', 'zero-known'):
            slide = 0x1000 if variant == 'slide' else 0
            metadata = 0 if variant == 'no-meta' else (2 if variant == 'meta-short' else 6)
            names = {f'__syscall_meta__{i}': SimpleNamespace(address=0x7000+i-slide) for i in range(metadata)}
            names['sys_call_table'] = SimpleNamespace(address=0x18000-slide)
            if variant != 'primary-only':
                names['ia32_sys_call_table'] = SimpleNamespace(address=0x18200-slide)
            if variant != 'no-next':
                names['after_primary'] = SimpleNamespace(address=0x18000+4*width-slide)
                names['after_ia32'] = SimpleNamespace(address=0x18200+3*width-slide)
            def lookup(name):
                if name not in names:
                    raise exceptions.SymbolError(name, 'test')
                return names[name]
            def exact(address):
                if address == 0x8500:
                    return ['owner!entry!tail'] if variant == 'qualified' else ['table!alias_handler', 'table!known_handler']
                return ['table!zero_handler'] if address == 0 and variant == 'zero-known' else []
            def array(object_type, subtype, offset, count):
                values = [0x8500, 0x8501, 0, 0x8600, 0x8500, 0]
                if offset == 0x18200-slide:
                    values = [0x8500, 0, 0x8501, 0x8600, 0x8500, 0]
                return values[:count]
            kernel = SimpleNamespace(symbols=list(reversed(names)), symbol_table_name='test', get_symbol=lookup,
                get_type=lambda _: SimpleNamespace(size=width), get_symbols_by_absolute_location=exact, object=array)
            context = SimpleNamespace(modules={'kernel': kernel}, symbol_space={'test': SimpleNamespace(symbols=names)})
            instance = SimpleNamespace(context=context, config={'kernel': 'kernel'})
            instance._get_table_size_meta = lambda kernel: cls._get_table_size_meta(instance, kernel)
            instance._get_table_size_next_symbol = lambda address, width, kernel: cls._get_table_size_next_symbol(instance, address, width, kernel)
            instance._get_table_info_disassembly = lambda width, kernel: cls._get_table_info_disassembly(instance, width, kernel)
            instance._get_table_info_other = lambda address, width, kernel: cls._get_table_info_other(instance, address, width, kernel)
            instance._get_table_info = lambda kernel, name, width: cls._get_table_info(instance, kernel, name, width)
            rows = [dict(table_address=int(v[0]), table_name=v[1], index=int(v[2]), address=int(v[3]), symbol=v[4]) for _, v in cls._generator(instance)]
            cases.append(dict(width=width, name=variant, rows=rows))
    return json.dumps(dict(commit=COMMIT, capstone=False, sizes=sizes, generators=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('syscall oracle differs')
    else:
        OUTPUT.write_text(result)
    print('16 metadata/next-symbol sizing cases and 16 no-capstone generator profiles verified')


if __name__ == '__main__':
    main()
