#!/usr/bin/env python3
"""Capture capability decoding semantics from the locked reference helpers."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-capability-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('capability oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.framework import objects, exceptions
    from volatility3.framework.constants.linux import CAPABILITIES
    from volatility3.framework.symbols.linux import extensions, LinuxUtilities
    from volatility3.plugins.linux.capabilities import Capabilities

    cases = []
    values = [0, 1, 2, 3, 0xffffffff, 0x100000000, 0xffffffffffffffff,
              (1 << 41) - 1, 1 << 40, 1 << 41, 1 << 63, 0xabcdef1234567890]
    values += [1 << bit for bit in range(41)]
    for layout in ['u32_cap', 'u32_cap_array_1', 'u32_cap_array_2', 'u64_val']:
        for last in [0, 1, 31, 35, 40, 41, 63, 64, 4095, None]:
            for raw in sorted(set(values)):
                if layout in ('u32_cap', 'u32_cap_array_1') and raw > 0xffffffff:
                    continue
                value = SimpleNamespace(_context=None)
                value.has_member = lambda name, layout=layout: name == ('val' if layout == 'u64_val' else 'cap')
                if layout == 'u64_val':
                    value.val = raw
                    method = extensions.kernel_cap_t.get_capabilities
                else:
                    value.cap = raw
                    if 'array' in layout:
                        value.cap = MagicMock(spec=objects.Array)
                        words = [raw & 0xffffffff]
                        if layout.endswith('_2'):
                            words.append(raw >> 32)
                        value.cap.__len__.return_value = len(words)
                        value.cap.__getitem__.side_effect = words.__getitem__
                    method = extensions.kernel_cap_struct.get_capabilities
                module = SimpleNamespace(object_from_symbol=lambda **kwargs: last)
                if last is None:
                    def missing(**kwargs):
                        raise exceptions.SymbolError('cap_last_cap', 'kernel')
                    module.object_from_symbol = missing
                value.get_kernel_cap_full = lambda: extensions.kernel_cap_struct.get_kernel_cap_full(value)
                value.get_last_cap_value = extensions.kernel_cap_struct.get_last_cap_value
                value.get_capabilities = lambda: method(value)
                value.enumerate_capabilities = lambda: extensions.kernel_cap_struct.enumerate_capabilities(value)
                value.capabilities_to_string = extensions.kernel_cap_struct.capabilities_to_string
                with patch.object(LinuxUtilities, 'get_module_from_volobj_type', return_value=module):
                    text = Capabilities._decode_cap(value)
                    masked = value.get_capabilities()
                cases.append(dict(layout=layout, last=last, raw=hex(raw), masked=hex(masked), text=text))
    return json.dumps(dict(commit=COMMIT, names=CAPABILITIES, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('Linux capability oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} pinned capability decoder cases verified')


if __name__ == '__main__':
    main()
