#!/usr/bin/env python3
"""Lock actual Python-byte RegExScanner and generic/Linux VMA generator semantics.

Uses real BufferDataLayer/Intel layers and byte-backed Linux ISF objects. No
scanner, object-field, VMA traversal or process-layer method is mocked. This is
reference evidence for native implementation, not capability acceptance.
"""
import argparse
import json
import logging
from pathlib import Path
import re
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/engine/testdata/regex-oracle.json'


def sparse(data):
    return [dict(offset=at, data=data[at:at+256].hex())
            for at in range(0, len(data), 256) if any(data[at:at+256])]


def linux_fixture(arch, payload, scenario):
    width = 8 if arch == 'x64' else 4
    base = lambda name: dict(kind='base', name=name)
    record = lambda size, fields: dict(kind='struct', size=size, fields=fields)
    pointer = lambda name: dict(kind='pointer', subtype=dict(kind='struct', name=name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    types = {
        'task_struct': record(40, dict(pid=field(0, base('u32')), tgid=field(4, base('u32')),
            comm=field(8, dict(kind='array', count=16, subtype=base('u8'))), mm=field(24, pointer('mm_struct')))),
        'mm_struct': record(32, dict(pgd=field(0, pointer('void_stub')), mmap=field(8, pointer('vm_area_struct')),
            start_brk=field(16, base('uptr')), brk=field(24, base('uptr')))),
        'vm_area_struct': record(48, dict(vm_start=field(0, base('uptr')), vm_end=field(8, base('uptr')),
            vm_next=field(16, pointer('vm_area_struct')), vm_mm=field(24, pointer('mm_struct')),
            vm_flags=field(32, base('uptr')), vm_file=field(40, pointer('void_stub')))),
        'void_stub': record(1, {}),
    }
    isf = dict(metadata={'format':'6.2.0'}, base_types={name:dict(kind='int', size=size, endian='little', signed=False)
        for name,size in [('pointer',width),('uptr',width),('u32',4),('u8',1)]}, user_types=types, symbols={}, enums={})
    data = bytearray(0x20000)
    def word(at, value):
        struct.pack_into('<Q' if width == 8 else '<I', data, at, value)
    # Independent process roots: identity mappings ensure the original bytes can
    # be checked without substituting a fake process-layer method.
    if arch == 'x64':
        word(0x8000, 0x9003); word(0x9000, 0xa003); word(0xa000, 0xb003)
        table = 0xb000
    elif arch == 'pae':
        struct.pack_into('<Q', data, 0x8000, 0x9003)
        struct.pack_into('<Q', data, 0x9000, 0xa003)
        table = 0xa000
    else:
        word(0x8000, 0x9003)
        table = 0x9000
    for i in range(32):
        struct.pack_into('<I' if arch == 'x86' else '<Q', data, table+i*(4 if arch == 'x86' else 8), i*4096|3)
    struct.pack_into('<II', data, 0x1000, 101, 100)
    data[0x1008:0x1010] = b'proc\xff\x00\x00\x00'
    word(0x1018, 0 if scenario == 'no-mm' else 0x2000)
    word(0x2000, 0x8000); word(0x2008, 0x3000)
    word(0x2010, 0x10000); word(0x2018, 0x13000)
    for vma,start,end,nxt in [(0x3000,0x10000,0x11000,0x3100),(0x3100,0x12000,0x13000,0)]:
        word(vma,start); word(vma+8,end); word(vma+16,nxt)
        word(vma+24,0x2000); word(vma+32,5)
    data[0x10000:0x10000+len(payload)] = payload
    data[0x12000:0x12000+len(payload)] = payload
    if scenario == 'vma-edge':
        data[0x10ffc:0x11004] = b'XYZMATCH'
    if scenario == 'missing-page':
        # A valid VMA whose process translation has an unavailable page.
        data[table+16*(4 if arch == 'x86' else 8):table+17*(4 if arch == 'x86' else 8)] = bytes(4 if arch == 'x86' else 8)
    return isf, bytes(data)


def generate(source):
    if sys.version_info[:2] != (3, 12):
        raise ValueError('requires Python 3.12, matching CI; byte-regex empty-match semantics changed in 3.14')
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires locked unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, IntelPAE, Intel32e
    from volatility3.framework.layers.scanners import RegExScanner
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.regexscan import RegExScan
    from volatility3.plugins.linux.vmaregexscan import VmaRegExScan
    logging.getLogger(RegExScan.__module__).setLevel(logging.CRITICAL)

    samples = [
        ('literal','MATCH',b'xxMATCH-MATCH'),
        ('dotall','A.B',b'A\nB A\x00B'),
        ('greedy','A.*B',b'AoneBtwoB'),
        ('lazy','A.*?B',b'AoneBtwoB'),
        ('backreference',r'(ab)\1',b'xxabab abac'),
        ('named-backreference',r'(?P<x>ab)(?P=x)',b'abab ab'),
        ('lookahead',r'ab(?=cd)',b'abcd abce'),
        ('lookbehind',r'(?<=ab)cd',b'abcd xxcd'),
        ('negative-lookahead',r'ab(?!cd)',b'abcd abce'),
        ('conditional',r'(a)?b(?(1)c|d)',b'abc bd abd'),
        ('atomic',r'(?>a|ab)c',b'abc ac'),
        ('possessive',r'a*+a',b'aaa'),
        ('ascii-word',r'\w+',b'abc_19\xff\xc3\xa9'),
        ('ascii-space',r'\s+',b'\t\r\n\v\f \x85\xa0'),
        ('ascii-fold',r'(?i)[a-z]+',b'ABC\xc4\xb0\xc5\xbf\xe2\x84\xaa'),
        ('word-boundary',r'\babc\b',b'abc_ abc\xffabc'),
        ('non-boundary',r'\B',b''),
        ('utf8-pattern','é+',b'\xc3\xa9\xa9\xc3\xa9'),
        ('escaped-byte',r'\xff+',b'a\xff\xffb'),
        ('negated-class',r'[^a]+',b'a\xff\x00\na'),
        ('multiline',r'(?m)^abc$',b'abc\nabc\n'),
        ('dollar-final-newline',r'abc$',b'abc\n'),
        ('absolute-end',r'abc\Z',b'abc\n'),
        ('empty-pattern','',b'ab'),
        ('empty-then-nonempty',r'|a',b'a'),
        ('lazy-empty',r'.*?',b'ab'),
        ('verbose',r'(?x) a \x20 b # end',b'a b ab'),
        ('context-too-short',r'A.{140}B',b'A'+b'x'*140+b'B'),
        ('invalid-group','(',b'abc'),
        ('invalid-byte-unicode',r'\u1234',b'abc'),
        ('invalid-variable-lookbehind',r'(?<=a+)b',b'ab'),
        ('empty-data','MATCH',b''),
    ]
    def rows(generator):
        result, error = [], None
        try:
            for level, values in generator:
                result.append(dict(level=level, values=[v.hex() if isinstance(v,bytes) else int(v) if isinstance(v,int) else str(v) for v in values]))
        except (ValueError,re.error):
            error = 'invalid_pattern'
        except exceptions.InvalidAddressException:
            error = 'unavailable_address'
        return dict(rows=result,error=error)

    cases = []
    for name,pattern,data in samples:
        scanner_result, scanner_error = [], None
        try:
            scanner_result = list(RegExScanner(pattern.encode('utf-8'))(data,0x1000))
        except re.error:
            scanner_error = 'invalid_pattern'
        context = contexts.Context()
        # BufferDataLayer requires at least one byte; empty-data is scanner-only.
        generated = []
        if data:
            context.layers.add_layer(BufferDataLayer(context,'physical','physical',data))
            runner = SimpleNamespace(context=context)
            for maxsize in (0,4,128,256):
                generated.append(dict(maxsize=maxsize, **rows(RegExScan._generator(runner,context,'physical',pattern,maxsize))))
        padded = bytes(32)+data+bytes(256)
        padded_context = contexts.Context()
        padded_context.layers.add_layer(BufferDataLayer(padded_context,'physical','physical',padded))
        padded_runner = SimpleNamespace(context=padded_context)
        padded_results = [dict(maxsize=n, **rows(RegExScan._generator(padded_runner,padded_context,'physical',pattern,n))) for n in (4,128,256)]
        cases.append(dict(name=name,pattern=pattern,data=data.hex(),scanner_offsets=scanner_result,scanner_error=scanner_error,generic=generated,
            padded_generic=dict(size=len(padded),writes=sparse(padded),results=padded_results)))
    # Exercise the scanner's own overlap suppression independently of layer I/O.
    for name,pattern,data in [('overlap','MATCH',b'xxxxxxMATCH-MATCH'),('cross-overlap','MATCH',b'xxxxxxMATCH'),('zero-at-chunk-end','',b'abcd')]:
        scanner = RegExScanner(pattern.encode())
        scanner.chunk_size = 8 if name != 'zero-at-chunk-end' else 4
        cases.append(dict(name=name,pattern=pattern,data=data.hex(),chunk_size=scanner.chunk_size,
            scanner_offsets=list(scanner(data,0x1000)),scanner_error=None,generic=[]))

    vmas = []
    selected = [s for s in samples if s[0] in ('literal','dotall','backreference','lookbehind','utf8-pattern','escaped-byte','context-too-short','invalid-group','lazy','ascii-word')]
    selected += [('vma-edge','XYZMATCH',b'MATCH'),('missing-page','MATCH',b'MATCH'),('no-mm','MATCH',b'MATCH'),('invalid-no-mm','(',b'MATCH')]
    for arch,layer_class in [('x86',Intel),('pae',IntelPAE),('x64',Intel32e)]:
        for name,pattern,payload in selected:
            isf,data = linux_fixture(arch,payload,'no-mm' if name=='invalid-no-mm' else name)
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context,'physical','physical',data))
            context.config['kernel.memory_layer'] = 'physical'
            context.config['kernel.page_map_offset'] = 0x8000
            context.layers.add_layer(layer_class(context,'kernel','kernel'))
            with tempfile.TemporaryDirectory(prefix='gomem-regex-oracle-') as directory:
                path = Path(directory)/'kernel.json'
                path.write_text(json.dumps(isf))
                context.symbol_space.append(IntermediateSymbolTable(context,'symbols','kernel',path.as_uri(),class_types={
                    'task_struct':extensions.task_struct,'mm_struct':extensions.mm_struct,'vm_area_struct':extensions.vm_area_struct}))
                context.module('kernel','kernel',0)
                task = context.object('kernel!task_struct',layer_name='kernel',offset=0x1000)
                runner = SimpleNamespace(context=context,config={'maxsize':4},MAXSIZE_DEFAULT=VmaRegExScan.MAXSIZE_DEFAULT,_progress_callback=lambda *_:None)
                expected = rows(VmaRegExScan._generator(runner,pattern,[task]))
            vmas.append(dict(name=name,arch=arch,pattern=pattern,configured_maxsize=4,isf=isf,size=len(data),writes=sparse(data),**expected))
    # Fail generation if the fixture stops reaching the methods it intends to
    # exercise. These are reference expectations, not native acceptance claims.
    for arch in ('x86','pae','x64'):
        by_name = {v['name']:v for v in vmas if v['arch']==arch}
        assert len(by_name['literal']['rows']) == 4
        assert by_name['literal']['rows'][0]['values'][:3] == [100,'proc',0x10002]
        assert len(bytes.fromhex(by_name['dotall']['rows'][0]['values'][-1])) == 128
        assert len(bytes.fromhex(by_name['lookbehind']['rows'][0]['values'][-1])) == 128
        assert len(by_name['missing-page']['rows']) == 1
        assert by_name['vma-edge']['rows'] == []
        assert by_name['no-mm']['rows'] == []
        assert by_name['invalid-no-mm']['error'] is None
        assert by_name['invalid-group']['error'] == 'invalid_pattern'
    windows = []
    for name,size,starts in [('full-overlap',(16<<20)+8192,[(16<<20)-2,(16<<20)+1024]),
                              ('partial-window',(16<<20)+1000,[(16<<20)-1000])]:
        data = bytearray(size)
        for start in starts:
            data[start:start+5] = b'MATCH'
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context,'physical','physical',bytes(data)))
        runner = SimpleNamespace(context=context)
        result = rows(RegExScan._generator(runner,context,'physical','MATCH',128))
        assert result['error'] is None
        windows.append(dict(name=name,pattern='MATCH',maxsize=128,size=size,writes=sparse(data),**result))
    return json.dumps(dict(commit=COMMIT,python='3.12',scope='Actual unmodified scanner and generic generator; VMA generator with real ISF task/mm/VMA and Intel process translation; no method mocks',cases=cases,vmas=vmas,windows=windows),indent=2,ensure_ascii=True)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('regex oracle differs')
    else:
        OUTPUT.write_text(result)
    doc = json.loads(result)
    print(f'{len(doc["cases"])} actual byte-scanner cases and {len(doc["vmas"])} paged VMA generators verified')


if __name__ == '__main__':
    main()
