#!/usr/bin/env python3
"""Lock actual Python-byte RegExScanner and generic/Linux VMA generator semantics.

Uses real BufferDataLayer/Intel layers and byte-backed Linux ISF objects. No
scanner, object-field, VMA traversal or process-layer method is mocked. This is
reference evidence for native implementation, not capability acceptance.
"""
import argparse
import base64
import hashlib
import json
import logging
from pathlib import Path
import re
import random
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/engine/testdata/regex-oracle.json'
SEMANTICS = ROOT / 'internal/engine/testdata/byte-regex-semantics.jsonl'


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
        'task_struct': record(64, dict(pid=field(0, base('u32')), tgid=field(4, base('u32')),
            comm=field(8, dict(kind='array', count=16, subtype=base('u8'))), mm=field(24, pointer('mm_struct')),
            tasks=field(40,dict(kind='struct',name='list_head')))),
        'list_head':record(2*width,dict(next=field(0,pointer('list_head')),prev=field(width,pointer('list_head')))),
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
    # A real init_task sentinel and list make the same byte-backed task usable
    # for full native/plugin orchestration, without substituting a task walker.
    for at,nxt,prev in [(0x5028,0x1028,0x1028),(0x1028,0x5028,0x5028)]:
        word(at,nxt);word(at+width,prev)
    banner = b'Linux version gomem-regex-oracle\n'
    data[0x6000:0x6000+len(banner)] = banner
    isf['symbols'] = dict(init_task=dict(address=0x5000),linux_banner=dict(address=0x6000,
        constant_data=base64.b64encode(banner+b'\0').decode()))
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
                sections,mappings,chunks = [],[],[]
                if task.mm:
                    process_name = task.add_process_layer()
                    process = context.layers[process_name]
                    sections = list(process._coalesce_sections(task.get_process_memory_sections()))
                    for start,length in sections:
                        mappings += [[int(offset),int(size),int(physical),int(physical_size)]
                            for offset,size,physical,physical_size,_ in process.mapping(start,length,ignore_errors=True)]
                    # Planning uses the actual scanner's fixed shape. Invalid
                    # regex cases still record the acquisition plan separately.
                    chunks = [dict(end=int(end),parts=[[int(at),int(length)] for _,at,length in parts])
                        for parts,end in process._scan_iterator(RegExScanner(b'MATCH'),sections)]
                runner = SimpleNamespace(context=context,config={'maxsize':4},MAXSIZE_DEFAULT=VmaRegExScan.MAXSIZE_DEFAULT,_progress_callback=lambda *_:None)
                expected = rows(VmaRegExScan._generator(runner,pattern,[task]))
            kernel_runner = SimpleNamespace(context=context)
            kernel_generic = rows(RegExScan._generator(kernel_runner,context,'kernel',pattern,4))
            vmas.append(dict(name=name,arch=arch,pattern=pattern,configured_maxsize=4,isf=isf,size=len(data),writes=sparse(data),sections=sections,mappings=mappings,chunks=chunks,kernel_generic=kernel_generic,**expected))
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
    plans = []
    # Drive the actual translation iterator over hardware page tables. Small
    # chunks expose packing across physically disjoint adjacent virtual runs;
    # large-page cases exercise the default 16 MiB boundary without huge JSON.
    for arch, layer_class in [('x86',Intel),('pae',IntelPAE),('x64',Intel32e)]:
        for scenario in ('adjacent-disjoint', 'contiguous', 'gap', 'empty', 'overlap-sections'):
            _, original = linux_fixture(arch,b'MATCH','literal')
            data = bytearray(original)
            table = {'x86':0x9000,'pae':0xa000,'x64':0xb000}[arch]
            width = 4 if arch == 'x86' else 8
            if scenario == 'adjacent-disjoint':
                struct.pack_into('<I' if width == 4 else '<Q',data,table+17*width,0x15003)
            if scenario == 'gap':
                struct.pack_into('<I' if width == 4 else '<Q',data,table+17*width,0)
            sections = [(0x10000,3*4096)]
            if scenario == 'empty':
                sections = [(0x30000,4096)]
            if scenario == 'overlap-sections':
                sections = [(0x10000,4096),(0x10800,4096),(0x11800,4096)]
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context,'physical','physical',bytes(data)))
            context.config['kernel.memory_layer'] = 'physical'
            context.config['kernel.page_map_offset'] = 0x8000
            layer = layer_class(context,'kernel','kernel')
            context.layers.add_layer(layer)
            sections = list(layer._coalesce_sections(sections))
            scanner = RegExScanner(b'MATCH')
            scanner.chunk_size, scanner.overlap = 4096, 512
            plans.append(dict(name=scenario,arch=arch,size=len(data),writes=sparse(data),sections=sections,
                chunk_size=scanner.chunk_size,overlap=scanner.overlap,
                mappings=[[int(a),int(b),int(c),int(d)] for start,length in sections
                    for a,b,c,d,_ in layer.mapping(start,length,ignore_errors=True)],
                chunks=[dict(end=int(end),parts=[[int(at),int(length)] for _,at,length in parts])
                    for parts,end in layer._scan_iterator(scanner,sections)]))
    for name,length in [('full-overlap',(16<<20)+8192),('partial-window',(16<<20)+1000)]:
        data = bytearray(22<<20)
        struct.pack_into('<Q',data,0x8000,0x9003)
        struct.pack_into('<Q',data,0x9000,0xa003)
        for page in range(10):
            struct.pack_into('<Q',data,0xa000+page*8,((page+1)<<21)|0x83)
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context,'physical','physical',bytes(data)))
        context.config['kernel.memory_layer'] = 'physical'
        context.config['kernel.page_map_offset'] = 0x8000
        layer = Intel32e(context,'kernel','kernel')
        context.layers.add_layer(layer)
        scanner = RegExScanner(b'MATCH')
        sections = [(0,length)]
        plans.append(dict(name=name,arch='x64',size=len(data),writes=sparse(data),sections=sections,
            chunk_size=scanner.chunk_size,overlap=scanner.overlap,
            mappings=[[int(a),int(b),int(c),int(d)] for a,b,c,d,_ in layer.mapping(0,length,ignore_errors=True)],
            chunks=[dict(end=int(end),parts=[[int(at),int(size)] for _,at,size in parts])
                for parts,end in layer._scan_iterator(scanner,sections)]))
    # Lock Python replacement decoding without storing all short byte strings.
    # Length-framed output makes this digest an unambiguous sequence oracle.
    def decoding_inputs():
        yield b''
        for first in range(256):
            yield bytes([first])
            for second in range(256):
                yield bytes([first,second])
        edges = [0,0x7f,0x80,0x8f,0x90,0x9f,0xa0,0xbf,0xc0,0xff]
        for first in [0xc0,0xc1,0xc2,0xdf,0xe0,0xe1,0xed,0xef,0xf0,0xf1,0xf4,0xf5,0xff]:
            for second in edges:
                for third in edges:
                    yield bytes([first,second,third])
                    for fourth in edges:
                        yield bytes([first,second,third,fourth])
    decoding_hash = hashlib.sha256()
    decoding_count = 0
    for data in decoding_inputs():
        decoded = data.decode('utf-8',errors='replace').encode('utf-8')
        decoding_hash.update(struct.pack('<I',len(decoded)))
        decoding_hash.update(decoded)
        decoding_count += 1
    decoding = dict(cases=decoding_count,sha256=decoding_hash.hexdigest(),
        scope='Python UTF-8 replacement decoding; empty, exhaustive single/pair bytes, selected triple/quad boundary bytes; uint32 LE length-framed UTF-8 outputs')
    semantic_patterns = [p for _,p,_ in samples] + [
        r'(a?)*\1', r'(?:|a)*b', r'(?:|a)+b', r'(a(b)?)+\2', r'(a|ab)*b',
        r'(?=(a|ab))\1c', r'(?i:(a))\1', r'(a)(?<=\1)b', r'(?<=(a)\1)b',
        r'(a)?(?(1)b|c)', r'(?(1)b|c)(a)', r'(?(99)b|c)', r'(?P<n>a)?(?(n)b|c)',
        r'(?i:a)(?-i:b)', r'(?i)a|b', r'a|(?i)b', r'(?i-m:a)', r'(?i-:a)',
        r'[\s\xff]', r'[^\W_]', r'[\b]', r'[\8]', r'\123', r'\400',
        r'[a-z]', r'(?i)[^a-z]', r'[]a]', r'[-a]', r'[a-]', r'[z-a]',
        r'a{,}', r'a{,2}', r'a{0}', r'a{2,1}', r'a{2}', r'{2}', r'a{b}',
        r'a{2}*', r'a{1,2}+', r'a{1,2}?', r'(?#comment)(?i)a',
        r'(?m:a$)', r'(?-s:a.b)', r'\A.*\Z', r'(?<=a|bc)d',
        r'(a)?\1', r'(a*)\1', r'(?P<a>a)(b)\1\2', r'(?P<a>a)(?P=a)',
        r'(?aa)a', r'a(?#c)*', r'a(?#foo\)bar)*', r'(?(+1)a|b)(a)',
        r'(a(?(1)b|c))', r'(?<=(a)(?(1)b|c))d', r'(a?){2,}\1',
        r'|(?i)a', r'(?#a)(?i)a', r'(?i)(?#a)(?m)a', r'(?x) a (?#c) *',
        r'(a?)*?', r'(?:a?)*a', r'((?:|a)*)\1', r'(a|b)\1',
        r'(?i)([a-z]+)\1', r'(a)?(?(1)(b|c)|(d|e))\2', r'(a|ab)++b',
        r'(?<=ab|cd)e', r'(?>(a|ab))b', r'(?=(a|ab))\1b',
        r'(a(b)?)+\2', r'(a|b){0,2}?\1', r'(?P<a>a)(?P<a>b)',
        r'(a\1)', r'(?a-i:a)', r'(?-i:a)', r'(?i-ii:a)',
    ]
    atoms = ['a','b','.',r'\d',r'\w',r'\s','[ab]','[^a]','(a)','(?:a|b)','(?:|a)']
    for atom in atoms:
        for quant in ['', '?', '*', '+', '*?', '++', '{1,2}', '{0,2}?']:
            semantic_patterns.extend([atom+quant, '('+atom+quant+')b', atom+quant+'a'])
    rng = random.Random(20261022)
    def grammar(depth):
        if depth == 0:
            return rng.choice(['a','b','.',r'\w',r'\xff','[ab]','[^b]',''])
        choice = rng.randrange(7)
        if choice == 0:
            return grammar(depth-1)+grammar(depth-1)
        if choice == 1:
            return '(?:'+grammar(depth-1)+'|'+grammar(depth-1)+')'
        if choice == 2:
            return '(?:'+grammar(depth-1)+')'+rng.choice(['?','{0,2}','{1,3}?','{0,2}+'])
        if choice == 3:
            return '(?>'+grammar(depth-1)+')'
        if choice == 4:
            return '(?='+grammar(depth-1)+')'+grammar(depth-1)
        if choice == 5:
            return '(?!'+grammar(depth-1)+')'+grammar(depth-1)
        return '(?i:'+grammar(depth-1)+')'
    semantic_patterns += [grammar(3) for _ in range(256)]
    semantic = []
    for pattern in semantic_patterns:
        inputs = [b'',b'a',b'ab',b'aaaab',b'a\nb',b'\xffa\xc3\xa9']
        inputs += [bytes(rng.choice(b'ab01_\n\x00\xff') for _ in range(rng.randrange(13))) for _ in range(4)]
        for data in inputs:
            for dotall in (False,True):
                try:
                    matches = [[m.start(),m.end()] for m in re.finditer(pattern.encode('utf-8'),data,re.DOTALL if dotall else 0)]
                    error = None
                except re.error:
                    matches,error = [],'invalid_pattern'
                semantic.append(dict(pattern=pattern,data=data.hex(),dotall=dotall,matches=matches,error=error))
    semantic_text = ''.join(json.dumps(case,ensure_ascii=True,separators=(',',':'))+'\n' for case in semantic)
    manifest = dict(path=SEMANTICS.name,cases=len(semantic),patterns=len(set(c['pattern'] for c in semantic)),sha256=hashlib.sha256(semantic_text.encode()).hexdigest(),scope='Python 3.12 byte finditer; complete match start/end positions')
    reference = json.dumps(dict(commit=COMMIT,python='3.12',scope='Actual unmodified scanner and generic generator; VMA generator with real ISF task/mm/VMA and Intel process translation; no method mocks',cases=cases,vmas=vmas,windows=windows,plans=plans,decoding=decoding,semantics=manifest),indent=2,ensure_ascii=True)+'\n'
    return reference,semantic_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    result,semantic = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result or SEMANTICS.read_text() != semantic:
            raise ValueError('regex oracle differs')
    else:
        OUTPUT.write_text(result)
        SEMANTICS.write_text(semantic)
    doc = json.loads(result)
    print(f'{len(doc["cases"])} actual byte-scanner cases, {len(doc["vmas"])} paged VMA generators, {len(doc["plans"])} Intel iterator plans and {doc["semantics"]["cases"]} byte-regex semantics cases verified')


if __name__ == '__main__':
    main()
