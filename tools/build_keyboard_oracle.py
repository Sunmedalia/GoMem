#!/usr/bin/env python3
"""Exercise pinned keyboard-notifier walk and module attribution."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-keyboard-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import exceptions, renderers
    from volatility3.framework.symbols.linux.extensions import module
    from volatility3.framework.symbols.linux.utilities.modules import Modules, ModuleInfo
    from volatility3.plugins.linux.malware.keyboard_notifiers import Keyboard_notifiers
    from volatility3.framework.symbols import linux

    known = [ModuleInfo(0xc000, 'active', 0x10000, 0x11000),
             ModuleInfo(0x8400, '__kernel__', 0x8400, 0x8600)]
    module_symbols = {0xc000: [('module_entry', 0x10100)]}
    cases = []
    for variant in ('empty', 'kernel', 'module', 'unknown', 'qualified', 'repeat', 'unreadable-head', 'missing-symbol'):
        def pointer(value):
            return SimpleNamespace(vol=SimpleNamespace(offset=value), __int__=lambda: value, is_readable=lambda: value != 0x300000)
        nodes = {
            0x19000: SimpleNamespace(vol=SimpleNamespace(offset=0x19000), notifier_call=0x8500, next=pointer(0), is_readable=lambda: True),
            0x19100: SimpleNamespace(vol=SimpleNamespace(offset=0x19100), notifier_call=0x10100, next=pointer(0x19000), is_readable=lambda: True),
        }
        head = pointer(0)
        if variant == 'kernel':
            head = pointer(0x19000)
        elif variant == 'module':
            head = pointer(0x19100)
        elif variant == 'unknown':
            nodes[0x19000].notifier_call = 0x16400
            head = pointer(0x19000)
        elif variant == 'qualified':
            head = pointer(0x19000)
        elif variant == 'repeat':
            nodes[0x19000].next = pointer(0x19100)
            nodes[0x19100].next = pointer(0x19000)
            head = pointer(0x19100)
        elif variant == 'unreadable-head':
            head = pointer(0x300000)
        def exact(address):
            if address == 0x8500 and variant == 'qualified':
                return ['owner!entry!tail']
            return ['table!a_entry', 'table!z_entry'] if address == 0x8500 else []
        def objects(object_type=None, offset=0, absolute=False, **kwargs):
            if object_type == 'module':
                return SimpleNamespace(get_symbol_by_address=lambda at: module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(module_symbols.get(offset, []))), at))
            if object_type == 'atomic_notifier_head':
                return SimpleNamespace(head=head)
            node = nodes.get(offset) or SimpleNamespace(vol=SimpleNamespace(offset=offset), notifier_call=0, next=pointer(0), is_readable=lambda: offset != 0x300000)
            node.is_readable = lambda: True
            return node
        def symbol(name):
            if variant == 'missing-symbol' or name != 'keyboard_notifier_list':
                raise exceptions.SymbolError(name, 'kernel')
            return SimpleNamespace(vol=SimpleNamespace(offset=0x18000), head=head)
        kernel = SimpleNamespace(name='kernel', layer_name='test', object=objects, object_from_symbol=symbol,
            get_symbols_by_absolute_location=exact)
        valid = lambda at: at != 0x300000
        context = SimpleNamespace(modules={'kernel': kernel}, layers={'test': SimpleNamespace(address_mask=0xffffffffffff, is_valid=valid)})
        instance = SimpleNamespace(context=context, config={'kernel': 'kernel'})
        try:
            with patch.object(Modules, 'run_modules_scanners', return_value=known):
                rows = [dict(address=int(v[0]), module=None if isinstance(v[1], renderers.NotAvailableValue) else v[1],
                             symbol=None if isinstance(v[2], renderers.NotAvailableValue) else v[2]) for _, v in Keyboard_notifiers._generator(instance)]
            error = None
        except (TypeError, exceptions.VolatilityException) as exc:
            rows, error = [], type(exc).__name__
        for row in rows:
            row['selected_owner_symbol'] = row['symbol']
            if row['module'] == 'active':
                row['selected_owner_symbol'] = module.get_symbol_by_address(SimpleNamespace(get_symbols_names_and_addresses=lambda: iter(module_symbols[0xc000])), row['address'])
        cases.append(dict(name=variant, rows=rows, error=error))
    # The inclusive fixed bound yields the entry at count 4096 and then stops.
    chain = [SimpleNamespace(vol=SimpleNamespace(offset=i), next=None, is_readable=lambda: True) for i in range(1, 5000)]
    for i, node in enumerate(chain):
        node.next = chain[i+1] if i+1 < len(chain) else 0
    kernel = SimpleNamespace(object=lambda object_type, offset, absolute: next(n for n in chain if n.vol.offset == offset))
    walked = list(linux.LinuxUtilities.walk_internal_list(kernel, 'notifier_block', 'next', chain[0], max_count=4096))
    return json.dumps(dict(commit=COMMIT, cases=cases, bound=dict(visited=len(walked), last=walked[-1].vol.offset)), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('keyboard oracle differs')
    else:
        OUTPUT.write_text(result)
    print('8 keyboard notifier profiles and the inclusive 4096 walk bound verified')


if __name__ == '__main__':
    main()
