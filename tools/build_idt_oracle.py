#!/usr/bin/env python3
"""Exercise pinned IDT type priority, descriptor decoding and ownership."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-idt-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import renderers, symbols
    from volatility3.framework.symbols.linux.extensions import module
    from volatility3.framework.symbols.linux.utilities.modules import Modules, ModuleInfo
    from volatility3.plugins.linux.malware.check_idt import Check_idt

    priorities = {4: ['gate_struct', 'desc_struct', 'gate_struct32'],
                  8: ['gate_struct64', 'gate_struct', 'idt_desc']}
    selections = []
    for width, types in priorities.items():
        for bits in range(8):
            present = [name for i, name in enumerate(types) if bits & (1 << i)]
            context = SimpleNamespace(modules={'kernel': SimpleNamespace(symbol_table_name='test', has_type=lambda name: name in present)})
            with patch.object(symbols, 'symbol_table_is_64bit', return_value=width == 8):
                selected = Check_idt.get_idt_type(context, 'kernel')
            selections.append(dict(width=width, present=present, selected=selected))

    targets = [0, 0x8500, 0x8501, 0x10100, 0x12100, 0x16400] + [0x8500] * 13 + [0x11000, 0x8500]
    known = [ModuleInfo(0xc000, 'active', 0x10000, 0x11000),
             ModuleInfo(0xc400, 'sys-only', 0x12000, 0x13000),
             ModuleInfo(0xc800, 'scan-only', 0x14000, 0x15000),
             ModuleInfo(0x8400, '__kernel__', 0x8400, 0x8600)]
    module_symbols = {0xc000: [('module_entry', 0x10100)], 0xc400: [('sys_entry', 0x12100)]}
    cases = []
    for width in (4, 8):
        for variant in ('packed', 'split-low', 'split-high', 'mixed', 'probe-hole'):
            stride = 8 if variant in ('packed', 'split-low') else 16
            entries = []
            for i in range(256):
                target = targets[i] if i < 20 else (targets[-1] if i == 128 else 0xdeadbeef)
                entry = SimpleNamespace(vol=SimpleNamespace(offset=0x19000 + i*stride))
                if variant in ('packed', 'mixed'):
                    entry.a, entry.b = (target & 0xffff) | 0xcafe0000, (target & 0xffff0000) | 0xbeef
                if variant != 'packed':
                    entry.offset_low, entry.offset_middle = target & 0xffff, (target >> 16) & 0xffff
                    if variant != 'split-low':
                        entry.offset_high = 0xffff0000 if width == 8 else 0xdeadbeef
                    if variant == 'mixed':
                        entry.offset_low = 0xdead
                entries.append(entry)
            def valid(at):
                return variant != 'probe-hole' or at != 0x19000 + 7*stride
            def objects(typ=None, offset=0, absolute=False, **kwargs):
                if typ == 'module':
                    return SimpleNamespace(get_symbol_by_address=lambda at: module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(module_symbols.get(offset, []))), at))
                assert kwargs['object_type'] == 'array' and kwargs['count'] == 256
                return entries
            kernel = SimpleNamespace(name='kernel', layer_name='test', object=objects,
                get_type=lambda _: object(), object_from_symbol=lambda _: SimpleNamespace(vol=SimpleNamespace(offset=0x19000)),
                get_symbols_by_absolute_location=lambda at: ['table!a_entry', 'table!z_entry'] if at == 0x8500 else [])
            context = SimpleNamespace(modules={'kernel': kernel}, layers={'test': SimpleNamespace(address_mask=0xffffffffffff if width == 8 else 0xffffffff, is_valid=valid)})
            instance = SimpleNamespace(context=context, config={'kernel': 'kernel'}, get_idt_type=lambda *_: 'fixture')
            with patch.object(Modules, 'run_modules_scanners', return_value=known):
                rows = [dict(index=int(v[0]), address=int(v[1]),
                             module=None if isinstance(v[2], renderers.NotAvailableValue) else v[2],
                             symbol=None if isinstance(v[3], renderers.NotAvailableValue) else v[3]) for _, v in Check_idt._generator(instance)]
            for row in rows:
                row['selected_owner_symbol'] = row['symbol']
                if row['module'] in ('active', 'sys-only'):
                    offset = 0xc000 if row['module'] == 'active' else 0xc400
                    row['selected_owner_symbol'] = module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(module_symbols.get(offset, []))), row['address'])
            cases.append(dict(width=width, name=variant, rows=rows))
    return json.dumps(dict(commit=COMMIT, selections=selections, generators=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('IDT oracle differs')
    else:
        OUTPUT.write_text(result)
    print('16 IDT type priorities and 10 descriptor/generator profiles verified')


if __name__ == '__main__':
    main()
