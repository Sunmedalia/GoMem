#!/usr/bin/env python3
"""Generate minimal Windows VAD root/traversal fixtures using the pinned upstream extensions."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile
from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-vad-roots-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('VAD oracle requires the pinned Python tree')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols import intermed
    from volatility3.framework.symbols.windows import extensions
    cases = []
    for width in [4, 8]:
        for layout in ['xp', 'balanced', 'avl', 'rtl', 'core']:
            buf = bytearray(0x2000)
            base = {'pointer': dict(kind='int', size=width, signed=False, endian='little'), 'u32': dict(kind='int', size=4, signed=False, endian='little'), 'u8': dict(kind='int', size=1, signed=False, endian='little')}
            base['u16'] = dict(kind='int', size=2, signed=False, endian='little')
            base['uptr'] = dict(kind='int', size=width, signed=False, endian='little')
            def ref(name):
                return dict(kind='struct', name=name)
            def ptr(name):
                return dict(kind='pointer', subtype=ref(name))
            def field(offset, typ):
                return dict(offset=offset, type=typ)
            def scalar(name):
                return dict(kind='base', name=name)
            def typ(fields, size=128):
                return dict(kind='struct', size=size, fields=fields)
            def putptr(offset, value):
                struct.pack_into('<I' if width == 4 else '<Q', buf, offset, value)
            def u32(offset, value):
                struct.pack_into('<I', buf, offset, value)
            types = {}
            node_name = '_MMADDRESS_NODE' if layout == 'balanced' else '_RTL_BALANCED_NODE' if layout == 'rtl' else '_MM_AVL_NODE'
            left, right = ('Left', 'Right') if layout in ['rtl', 'core'] else ('LeftChild', 'RightChild')
            parent_path = 'ParentValue' if layout in ['rtl', 'core'] else 'u1'
            link_fields = {left: field(width, ptr(node_name)), right: field(width*2, ptr(node_name))}
            if parent_path == 'ParentValue':
                link_fields[parent_path] = field(0, scalar('uptr'))
            else:
                types['_PARENT'] = typ({'Parent': field(0, scalar('uptr'))}, width)
                link_fields['u1'] = field(0, ref('_PARENT'))
            types[node_name] = typ(link_fields, width*3)
            if layout == 'xp':
                link_fields = {'Parent': field(0, ptr('_MMVAD')), 'LeftChild': field(width, ptr('_MMVAD')), 'RightChild': field(width*2, ptr('_MMVAD'))}
            vpn = {'StartingVpn': field(width*3, scalar('u32')), 'EndingVpn': field(width*3+4, scalar('u32'))}
            if layout in ['rtl', 'core']:
                vpn.update(StartingVpnHigh=field(width*3+8, scalar('u8')), EndingVpnHigh=field(width*3+9, scalar('u8')))
            short = dict(vpn)
            if layout in ['avl', 'rtl', 'core']:
                short['VadNode'] = field(0, ref(node_name))
            else:
                short.update(link_fields)
            types['_MMVAD_SHORT'] = typ(short)
            types['_MMVAD'] = typ({'Core': field(0, ref('_MMVAD_SHORT'))} if layout == 'core' else short)
            if layout == 'xp':
                vad_root = ptr('_MMVAD')
                putptr(0x108, 0x400)
            elif layout == 'balanced':
                types['_MM_AVL_TABLE'] = typ({'BalancedRoot': field(0, ref(node_name))})
                vad_root = ref('_MM_AVL_TABLE')
                putptr(0x108+width*2, 0x400)
            else:
                types['_RTL_AVL_TREE'] = typ({'Root': field(0, ptr(node_name))}, width)
                vad_root = ref('_RTL_AVL_TREE')
                putptr(0x108, 0x400)
            # One long VAD maps a file through the XP direct pointer or the
            # later subsection/fast-reference path. Other VAD tags are short.
            file_name = r'\Device\HarddiskVolume2\Windows\services.exe'
            encoded_name = file_name.encode('utf-16le')
            unicode_fields = {'Length': field(0,scalar('u16')), 'MaximumLength': field(2,scalar('u16')), 'Buffer': field(8 if width == 8 else 4,dict(kind='pointer',subtype=scalar('u16')))}
            types['_UNICODE_STRING'] = typ(unicode_fields,16 if width == 8 else 8)
            types['_FILE_OBJECT'] = typ({'FileName':field(0,ref('_UNICODE_STRING'))},32)
            types['_EX_FAST_REF'] = typ({'Value':field(0,scalar('uptr')),'Object':field(0,scalar('uptr'))},width)
            types['_CONTROL_AREA'] = typ({'FilePointer':field(0,ptr('_FILE_OBJECT') if layout == 'xp' else ref('_EX_FAST_REF'))},width)
            types['_SUBSECTION'] = typ({'ControlArea':field(0,ptr('_CONTROL_AREA'))},width)
            types['_MMVAD']['fields'] = dict(types['_MMVAD']['fields'])
            types['_MMVAD']['fields']['ControlArea' if layout == 'xp' else 'Subsection'] = field(80,ptr('_CONTROL_AREA' if layout == 'xp' else '_SUBSECTION'))
            putptr(0x600+80,0x1000 if layout == 'xp' else 0x1100)
            putptr(0x1100,0x1000)
            putptr(0x1000,0x1200 if layout == 'xp' else 0x1203)
            struct.pack_into('<HH',buf,0x1200,len(encoded_name),len(encoded_name)+2)
            putptr(0x1200+(8 if width == 8 else 4),0x1400)
            buf[0x1400:0x1400+len(encoded_name)] = encoded_name
            types['_EPROCESS'] = typ({'VadRoot': field(8, vad_root)}, 256)
            for address, parent, first, last, tag in [(0x400, 0x108 if layout == 'balanced' else 0, 0x100, 0x10f, b'VadS'), (0x600, 0x400, 0x20, 0x21, b'Vadl'), (0x800, 0x400, 0x300, 0x300, b'VadF')]:
                buf[address-(4 if width == 4 else 12):address-(4 if width == 4 else 12)+4] = tag
                putptr(address, parent if layout == 'xp' else parent | 1)
                u32(address+width*3, first)
                u32(address+width*3+4, last)
            putptr(0x400+width, 0x600)
            putptr(0x400+width*2, 0x800)
            isf = dict(metadata={'format':'4.1.0'}, base_types=base, user_types=types, enums={}, symbols={})
            for variant in ['normal'] + (['high'] if layout == 'rtl' and width == 8 else ['rollover'] if layout == 'core' and width == 8 else []):
                variant_buf = bytearray(buf)
                if variant == 'high':
                    variant_buf[0x400+width*3+8] = 1
                    variant_buf[0x400+width*3+9] = 1
                elif variant == 'rollover':
                    struct.pack_into('<II',variant_buf,0x400+width*3,0xfffffffe,0xffffffff)
                    variant_buf[0x400+width*3+9] = 1
                ctx = contexts.Context()
                layer = BufferDataLayer(ctx, 'fixture', 'memory', bytes(variant_buf))
                ctx.layers.add_layer(layer)
                class_types = {'_EPROCESS':extensions.EPROCESS, '_MMVAD':extensions.MMVAD, '_MMVAD_SHORT':extensions.MMVAD_SHORT, node_name:extensions.MMVAD_SHORT, '_UNICODE_STRING':extensions.UNICODE_STRING, '_EX_FAST_REF':extensions.EX_FAST_REF}
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'fixture.json'
                    path.write_text(json.dumps(isf))
                    table = intermed.IntermediateSymbolTable(ctx, 'fixture.symbols', 'kernel', path.as_uri(), class_types=class_types)
                ctx.symbol_space.append(table)
                process = ctx.object('kernel!_EPROCESS', layer_name='memory', offset=0x100)
                nodes = [dict(address=int(v.vol.offset), start=int(v.get_start()), end=int(v.get_end()), parent=int(v.get_parent()), left=int(v.get_left_child()), right=int(v.get_right_child()), tag=v.get_tag(), file=str(v.get_file_name()) if isinstance(v.get_file_name(),str) else None) for v in process.get_vad_root().traverse()]
                cases.append(dict(name=f'{layout}-{width*8}'+('' if variant == 'normal' else '-'+variant), isf=isf, size=len(variant_buf), segments=[dict(offset=off, hex=bytes(variant_buf[off:off+256]).rstrip(b'\0').hex()) for off in range(0,len(variant_buf),256) if any(variant_buf[off:off+256])], expected=nodes))
    return json.dumps(dict(commit=COMMIT,cases=cases), indent=2)+'\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT))
    p.add_argument('--check',action='store_true')
    args = p.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('VAD root oracle differs from the checked-in reference')
    else:
        OUTPUT.write_text(result)
    print('12 Windows VAD root/layout oracles verified')


if __name__ == '__main__':
    main()
