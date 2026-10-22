#!/usr/bin/env python3
"""Run the unmodified TCP/IP version factory on real Intel/KUSER/debug objects."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-network-version-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import versions
    from volatility3.framework.symbols.windows.extensions import network
    from volatility3.plugins.windows.netscan import NetScan

    scenarios = []
    for major, minor, builds in [(6, 0, [6000, 6001, 6002, 6003]), (6, 1, [7600, 7601, 8400]),
                                  (6, 2, [9200]), (6, 3, [9600]),
                                  (10, 0, [10240, 10586, 14393, 15063, 16299, 17134, 17763, 18362, 18363, 19041, 20348])]:
        for build in builds:
            scenarios.append((major, minor, build, 0, 'metadata', build, False))
    scenarios.extend([
        (10, 0, 18362, 0, 'metadata', 18363, False),
        (10, 0, 18362, 0, 'fallback', 18363, True),
        (10, 0, 18362, 0, 'fallback', 18362, False),
        (10, 0, 18362, 0, 'metadata', 18362, True),
        (6, 3, 9600, 19934, 'metadata', 9600, False),
        (6, 3, 9600, 19935, 'metadata', 9600, False),
        (6, 3, 9600, 19936, 'metadata', 9600, False),
        (6, 3, 9601, 19935, 'metadata', 9601, False),
        (10, 0, 22000, 0, 'metadata', 22000, False),
        (10, 0, 1, 0, 'metadata', 1, False),
        (10, 0, 19041, 19935, 'metadata', 19041, False),
        (5, 1, 2600, 0, 'metadata', 2600, False),
        (6, 4, 10000, 0, 'metadata', 10000, False),
    ])
    cases = []
    for arch, width, layer_class in [('x86', 4, Intel), ('pae', 4, IntelPAE), ('x64', 8, Intel32e)]:
        for major, minor, build, revision, mode, pe_build, has_type in scenarios:
            data = bytearray(0x30000)
            base = lambda name: dict(kind='base', name=name)
            field = lambda at, ref: dict(offset=at, type=ref)
            typ = lambda size, fields: dict(kind='struct', size=size, fields=fields)
            metadata = {'format': '6.2.0', 'windows': {'pdb': {'database': 'kernel.pdb', 'GUID': '13131313131313131313131313131313', 'age': 1, 'machine_type': 34404 if width == 8 else 332}}}
            if mode == 'metadata':
                metadata['windows']['pe'] = dict(major=major, minor=minor, revision=pe_build, build=0)
            schema = dict(metadata=metadata, base_types={name: dict(kind='int', size=size, signed=False, endian='little')
                          for name, size in [('pointer', width), ('u16', 2), ('u32', 4)]},
                          symbols={'KdVersionBlock': {'address': 0x1000}}, enums={}, user_types={
                              '_DBGKD_GET_VERSION64': typ(4, {'MajorVersion': field(0, base('u16')), 'MinorVersion': field(2, base('u16'))}),
                              '_KUSER_SHARED_DATA': typ(8, {'NtMajorVersion': field(0, base('u32')), 'NtMinorVersion': field(4, base('u32'))})})
            if has_type:
                schema['user_types']['_KQOS_GROUPING_SETS'] = typ(1, {})
            struct.pack_into('<HH', data, 0x1000, 15, build)
            struct.pack_into('<II', data, 0x18000, major, minor)
            kuser = 0xfffff78000000000 if width == 8 else 0xffdf0000
            if arch == 'x64':
                struct.pack_into('<Q', data, 0x8000, 0x9003)
                struct.pack_into('<Q', data, 0x9000, 0xa003)
                struct.pack_into('<Q', data, 0xa000, 0x83)
                for table, shift, target in [(0x8000, 39, 0xb003), (0xb000, 30, 0xc003), (0xc000, 21, 0xd003), (0xd000, 12, 0x18003)]:
                    struct.pack_into('<Q', data, table + ((kuser >> shift) & 511) * 8, target)
            elif arch == 'pae':
                for table, index, target in [(0x8000, 0, 0x9003), (0x9000, 0, 0x83), (0x8000, 3, 0xa003),
                                              (0xa000, (kuser >> 21) & 511, 0xb003), (0xb000, (kuser >> 12) & 511, 0x18003)]:
                    struct.pack_into('<Q', data, table + index * 8, target)
            else:
                struct.pack_into('<I', data, 0x8000, 0x83)
                struct.pack_into('<I', data, 0x8000 + ((kuser >> 22) & 1023) * 4, 0xb003)
                struct.pack_into('<I', data, 0xb000 + ((kuser >> 12) & 1023) * 4, 0x18003)
            if revision:
                marker = 0x22000
                value = ('OriginalFilename\x00tcpip.sys').encode('utf-16be')
                data[marker:marker + len(value)] = value
                data[marker - 0x400:marker - 0x3fc] = b'\xbd\x04\xef\xfe'
                struct.pack_into('<IHHHHHHHH', data, marker - 0x3fc, 0x10000, 3, 6, revision, 9600, 3, 6, revision, 9600)
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', bytes(data)))
            context.config['memory.memory_layer'] = 'physical'
            context.config['memory.page_map_offset'] = 0x8000
            context.layers.add_layer(layer_class(context, 'memory', 'memory'))
            with tempfile.TemporaryDirectory(prefix='gomem-network-version-') as directory:
                path = Path(directory) / 'kernel.json'
                path.write_text(json.dumps(schema))
                context.symbol_space.append(IntermediateSymbolTable(context, 'symbols', 'kernel', path.as_uri()))
                context.module('kernel', 'memory', 0)
                distinguished = versions.is_win10_18363_or_later(context, 'kernel')
                try:
                    name, classes = NetScan.determine_tcpip_version(context, 'kernel')
                    network_path = source / 'volatility3/framework/symbols/windows/netscan' / (name + '.json')
                    context.symbol_space.append(IntermediateSymbolTable(context, 'network_symbols', name,
                        network_path.resolve().as_uri(), class_types=classes, table_mapping={'nt_symbols': 'kernel'}))
                    constraints = NetScan.create_netscan_constraints(context, name)
                    result = dict(name=name, win10_x64_classes=classes is network.win10_x64_class_types,
                                  constraints=[dict(tag=c.tag.hex(), type=c.type_name.split('!')[-1],
                                                    minimum=c.size[0], page_type=int(c.page_type)) for c in constraints])
                except (NotImplementedError, exceptions.VolatilityException) as error:
                    result = dict(error=type(error).__name__)
            cases.append(dict(arch=arch, width=width, major=major, minor=minor, build=build, tcpip_revision=revision,
                              is18363=distinguished, mode=mode, pe_build=pe_build, has_fallback_type=has_type,
                              isf=schema, size=len(data),
                              writes=[dict(offset=at, data=data[at:at+256].hex()) for at in range(0, len(data), 256) if any(data[at:at+256])], result=result))
    assert len(cases) == 99
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit('network version oracle drift; regenerate explicitly')
    else:
        OUTPUT.write_text(generated)
    print('99 actual Intel/PAE/x64 network version factory cases verified')


if __name__ == '__main__':
    main()
