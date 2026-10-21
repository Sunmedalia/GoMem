#!/usr/bin/env python3
"""Exercise pinned kernel-thread rendering and module pointer/symbol lookup."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-kthreads-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import exceptions, renderers
    from volatility3.framework.objects import utility
    from volatility3.framework.symbols.linux.extensions import module
    from volatility3.framework.symbols.linux.utilities.modules import Modules, ModuleInfo
    from volatility3.plugins.linux.kthreads import Kthreads
    from volatility3.plugins.linux.pslist import PsList

    # Exercise exact module helper lookup, range ordering, aliases and qualified names.
    lookup_cases = []
    for name, ranges, target in [
        ('start', [(1, 'one', 100, 200)], 100),
        ('last-byte', [(1, 'one', 100, 200)], 199),
        ('end-exclusive', [(1, 'one', 100, 200)], 200),
        ('outside', [(1, 'one', 100, 200)], 99),
        ('overlap-first', [(1, 'one', 100, 200), (2, 'two', 150, 250)], 160),
        ('overlap-reverse', [(2, 'two', 150, 250), (1, 'one', 100, 200)], 160),
        ('kernel', [(3, '__kernel__', 300, 400)], 320),
        ('kernel-no-exact', [(3, '__kernel__', 300, 400)], 321),
        ('qualified', [(4, 'qualified', 500, 600)], 520),
    ]:
        syms = {1: [('entry', 100), ('overlap', 160)], 2: [('other', 160)], 4: [('table!entry!tail', 520)]}
        kernel = SimpleNamespace(name='kernel', layer_name='test',
            get_symbols_by_absolute_location=lambda at: ['table!a_entry', 'table!z_entry'] if at == 320 else [],
            object=lambda typ, offset, absolute: SimpleNamespace(get_symbol_by_address=lambda at: module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(syms.get(offset, []))), at)))
        context = SimpleNamespace(modules={'kernel': kernel}, layers={'test': SimpleNamespace(address_mask=0xffffffffffff)})
        match, symbol = Modules.module_lookup_by_address(context, 'kernel', [ModuleInfo(*m) for m in ranges], target)
        selected_symbol = symbol
        if match and match.name != '__kernel__':
            selected_symbol = module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(syms.get(match.offset, []))), target)
            if selected_symbol and '!' in selected_symbol:
                selected_symbol = selected_symbol.split('!')[1]
        lookup_cases.append(dict(name=name, ranges=ranges, target=target, module=match.name if match else None, symbol=symbol, selected_owner_symbol=selected_symbol))

    class Pointer(int):
        def is_readable(self):
            return self.readable

        def dereference(self):
            return SimpleNamespace(cast=lambda _: self.obj)

    def pointer(value, readable=True, obj=None):
        p = Pointer(value)
        p.readable, p.obj = readable, obj
        return p

    variants = ['worker-private', 'set-child-tid', 'kallsyms-pointer', 'kallsyms-embedded',
        'signal-threads', 'full-name', 'bad-full-name', 'empty-full-name', 'user-task',
        'null-private', 'null-handler', 'unknown-module', 'interior-symbol',
        'bad-private', 'bad-handler', 'unsupported']
    cases = []
    known = [ModuleInfo(0xc000, 'active', 0x10000, 0x11000),
        ModuleInfo(0xc400, 'sys-only', 0x12000, 0x13000),
        ModuleInfo(0xc800, 'scan-only', 0x14000, 0x15000),
        ModuleInfo(0x8400, '__kernel__', 0x8400, 0x8600)]
    for variant in variants:
        tasks = []
        for i, tid in enumerate([100, 102, 101]):
            fn = [0x8500, 0x10100, 0x12100][i]
            if i == 2:
                fn = {'null-handler': 0, 'bad-handler': 0x300000,
                      'unknown-module': 0x16400, 'interior-symbol': 0x12101}.get(variant, fn)
            kth = SimpleNamespace(vol=SimpleNamespace(offset=0x17000+i*0x100), threadfn=pointer(fn, fn not in (0, 0x300000)), full_name=i,
                has_member=lambda _: variant in ('full-name', 'bad-full-name', 'empty-full-name'))
            private_value = 0 if variant == 'null-private' and i == 2 else 0x17000 + i*0x100
            private = pointer(private_value, private_value != 0 and not (variant == 'bad-private' and i == 2), kth)
            task = SimpleNamespace(pid=tid, comm=['kernel-worker', 'module-worker', 'sys-worker'][i],
                is_kernel_thread=not (variant == 'user-task' and i == 2),
                has_member=lambda _: variant != 'set-child-tid', worker_private=private, set_child_tid=private)
            tasks.append(task)
        def full_name(index, count):
            assert count == 255
            if variant == 'bad-full-name' and index == 2:
                raise exceptions.InvalidAddressException('test', 0x300000)
            if variant == 'empty-full-name' and index == 2:
                return ''
            return ['full-kernel', 'full-module', 'full-sys'][index]
        module_syms = {0xc000: [('module_entry', 0x10100)], 0xc400: [('sys_entry', 0x12100)]}
        kernel = SimpleNamespace(name='kernel', layer_name='test', get_type=lambda _: SimpleNamespace(has_member=lambda _: variant != 'unsupported'),
            get_symbols_by_absolute_location=lambda at: ['table!a_entry', 'table!z_entry'] if at == 0x8500 else [],
            object=lambda typ, offset, absolute: SimpleNamespace(get_symbol_by_address=lambda at: module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(module_syms.get(offset, []))), at)))
        context = SimpleNamespace(modules={'kernel': kernel}, layers={'test': SimpleNamespace(address_mask=0xffffffffffff)})
        instance = SimpleNamespace(context=context, config={'kernel': 'kernel'})
        with patch.object(Modules, 'run_modules_scanners', return_value=known), \
                patch.object(PsList, 'list_tasks', return_value=tasks) as listing, \
                patch.object(utility, 'array_to_string', side_effect=lambda value: value), \
                patch.object(utility, 'pointer_to_string', side_effect=full_name):
            try:
                rows = [dict(tid=int(v[0]), name=v[1], handler=int(v[2]),
                    module=None if isinstance(v[3], renderers.NotAvailableValue) else v[3],
                    symbol=None if isinstance(v[4], renderers.NotAvailableValue) else v[4]) for _, v in Kthreads._generator(instance)]
                assert listing.call_args.kwargs['include_threads'] is True
                error = False
            except exceptions.VolatilityException:
                rows, error = [], True
        for row in rows:
            row['selected_owner_symbol'] = row['symbol']
            if row['module'] in ('active', 'sys-only'):
                offset = 0xc000 if row['module'] == 'active' else 0xc400
                row['selected_owner_symbol'] = module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(module_syms.get(offset, []))), row['handler'])
        cases.append(dict(name=variant, rows=rows, unsupported=error))
    # Fixed 4096 helper has an inclusive zero-based bound: entry 4096 is visited.
    windows = []
    for count in [0, 1, 4096, 4097, 4098]:
        obj = SimpleNamespace(_context=SimpleNamespace(layers={'test': SimpleNamespace(address_mask=0xffffffffffff)}),
            vol=SimpleNamespace(layer_name='test', offset=1),
            get_symbols=lambda: (SimpleNamespace(get_name=lambda: 'entry', st_value=i) for i in range(count)))
        values = list(module.get_symbols_names_and_addresses(obj))
        windows.append(dict(count=count, visited=len(values)))
    return json.dumps(dict(commit=COMMIT, lookups=lookup_cases, generators=cases, symbol_windows=windows), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('kernel thread oracle differs')
    else:
        OUTPUT.write_text(result)
    print('9 pointer lookups, 16 kernel-thread generator profiles and 5 symbol windows verified')


if __name__ == '__main__':
    main()
