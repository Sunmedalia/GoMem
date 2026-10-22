#!/usr/bin/env python3
"""Run pinned EtwPatch with real paged process objects, PDB cache and exports."""
import argparse
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_suspended_threads_oracle import fixture as suspended_fixture

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT/'internal/engine/testdata/windows-etwpatch-oracle.json'


def fixture(width, scenario):
    kernel, pdb, data = suspended_fixture(width, 'normal')
    module = 'advapi32.dll' if scenario == 'advapi' else 'ntdll.dll'
    database = module[:-3]+'pdb'
    names = ['EventWrite', 'TraceEvent'] if scenario == 'advapi' else ['EtwEventWrite', 'EtwEventWriteFull', 'NtTraceEvent', 'ZwTraceEvent', 'NtTraceControl', 'ZwTraceControl', 'EtwpEventWriteFull']
    path = ('C:\\Windows\\'+module).encode('utf-16le')
    if scenario == 'relative-name':
        path=module.encode('utf-16le')
    elif scenario == 'mixed-case':
        path=('C:\\Windows/NTDLL.DLL').encode('utf-16le')
    elif scenario == 'suffix-only':
        path=('C:\\Windows\\prefixntdll.dll').encode('utf-16le')
    elif scenario == 'forward-only':
        path=('C:/Windows/ntdll.dll').encode('utf-16le')
    struct.pack_into('<HH',data,0x4000,len(path),len(path)+2)
    data[0x5000:0x5100]=bytes(256)
    data[0x5000:0x5000+len(path)]=path
    pdb['metadata']['windows']['pdb']['database']=database
    pdb['symbols']={name:dict(address=0x1200+i*16) for i,name in enumerate(names)}
    record=b'RSDS'+bytes([0x12])*16+(1).to_bytes(4,'little')+database.encode()+b'\0'
    data[0x101900:0x101a00]=bytes(256)
    data[0x101900:0x101900+len(record)]=record
    struct.pack_into('<I',data,0x101890,len(record))
    for i,name in enumerate(names):
        opcode=0xc3 if i%2==0 else 0xe9
        if scenario == 'all-clean':opcode=0x90
        elif scenario == 'ret-imm':opcode=0xc2
        elif scenario == 'all-ret':opcode=0xc3
        elif scenario == 'all-jmp':opcode=0xe9
        data[0x101200+i*16]=opcode
    put = lambda at,value: struct.pack_into('<Q' if width==8 else '<I',data,at,value)
    if scenario == 'no-vads':
        put(0x430,0)
    elif scenario == 'missing-symbols':
        pdb['symbols']={'unrelated':dict(address=0x1400)}
    elif scenario in ('export-only', 'mixed-source'):
        if scenario == 'export-only':
            pdb['symbols']={'unrelated':dict(address=0x1400)}
            export='EtwEventWrite'
            target=0x101a00
        else:
            pdb['symbols']={'EtwEventWrite':dict(address=0x1200)}
            export='EtwEventWriteFull'
            target=0x101a20
        encoded=export.encode()+b'\0'
        data[target:target+len(encoded)]=encoded
    elif scenario == 'rsds-directory-absent':
        debug=0x100000+0x98+(112 if width==8 else 96)+6*8
        data[debug:debug+8]=bytes(8)
    elif scenario in ('rsds-cross-page','rsds-exact-end','rsds-past-end'):
        data[0x101900:0x101900+len(record)]=bytes(len(record))
        relative={'rsds-cross-page':0x1ff0,'rsds-exact-end':0x4000-len(record),'rsds-past-end':0x4001-len(record)}[scenario]
        data[0x100000+relative:0x100000+relative+len(record)]=record
    elif scenario == 'rsds-first-guid-only':
        wrong=bytearray(record);wrong[4:20]=bytes([0x14])*16
        data[0x101800:0x101800+len(wrong)]=wrong
    elif scenario == 'wrong-guid':
        data[0x101904:0x101914]=bytes([0x14])*16
    elif scenario == 'rsds-no-mz':
        data[0x100000:0x100002]=b'ZZ'
    elif scenario == 'both-modules':
        put(0x1008,0x1200);put(0x1210,0x1000)
        data[0x1200-(12 if width==8 else 4):0x1200-(12 if width==8 else 4)+4]=b'Vadl'
        struct.pack_into('<II',data,0x1218,0x110,0x113)
        put(0x1228,0x2100);put(0x2100,0x3100);put(0x3100,0x4103)
        path2=r'C:\Windows\advapi32.dll'.encode('utf-16le')
        struct.pack_into('<HH',data,0x4100,len(path2),len(path2)+2)
        put(0x4108,0x5200);data[0x5200:0x5200+len(path2)]=path2
        data[0x110000:0x114000]=data[0x100000:0x104000]
        data[0x111a00:0x111a00+11]=b'EventWrite\0'
        data[0x111200]=0xe9
    if scenario in ('second-clean', 'second-patched', 'second-filtered', 'second-no-vad'):

        put = lambda at,value: struct.pack_into('<Q' if width==8 else '<I',data,at,value)
        put(0x18080+width,0x500);put(0x400,0x500)
        put(0x500,0x18080);put(0x500+width,0x400)
        put(0x540,0x540);put(0x540+width,0x540)
        put(0x550,0xb000)
        if width==8:
            put(0xb000,0xc003);put(0xc000,0xd003);put(0xd000,0xe003)
            for index in range(512):put(0xe000+index*8,(index<<12)|3)
            put(0xe000+0x101*8,0x1e0003)
        else:
            put(0xb000,0xe003)
            for index in range(512):put(0xe000+index*4,(index<<12)|3)
            put(0xe000+0x101*4,0x1e0003)
        data[0x1e0000:0x1e1000]=data[0x101000:0x102000]
        for i in range(len(names)):
            data[0x1e0200+i*16]=0x90 if scenario=='second-clean' else 0xc3
            if scenario in ('second-patched','second-filtered','second-no-vad'):data[0x101200+i*16]=0x90
        if scenario=='second-no-vad':put(0x530,0)
    return kernel,pdb,data


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, constants, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.automagic.symbol_cache import SqliteCache, WindowsIdentifier
    from volatility3.plugins.windows.etwpatch import EtwPatch
    old_cache, old_offline = constants.CACHE_PATH, constants.OFFLINE
    cases = []
    try:
        for width in (4, 8):
            for scenario in ('normal', 'all-clean', 'all-ret', 'all-jmp', 'ret-imm', 'advapi', 'no-vads', 'relative-name', 'pid-match', 'pid-mismatch', 'mixed-case', 'suffix-only', 'forward-only', 'missing-symbols', 'export-only', 'mixed-source', 'rsds-directory-absent', 'rsds-cross-page', 'rsds-exact-end', 'rsds-past-end', 'rsds-first-guid-only', 'wrong-guid', 'rsds-no-mz', 'both-modules', 'second-clean', 'second-patched', 'second-filtered', 'second-no-vad'):
                kernel, pdb, data = fixture(width, scenario)
                ctx = contexts.Context()
                ctx.layers.add_layer(BufferDataLayer(ctx, 'physical', 'physical', bytes(data)))
                ctx.config['memory.memory_layer'] = 'physical'
                ctx.config['memory.page_map_offset'] = 0x8000
                ctx.config['memory.kernel_virtual_offset'] = 0x10000
                ctx.layers.add_layer((Intel32e if width == 8 else Intel)(ctx, 'memory', 'memory'))
                with tempfile.TemporaryDirectory() as directory:
                    directory = Path(directory)
                    constants.CACHE_PATH, constants.OFFLINE = str(directory), True
                    kp, pp = directory/'kernel.json', directory/'pdb.json'
                    kp.write_text(json.dumps(kernel)); pp.write_text(json.dumps(pdb))
                    cachepath = str(directory/constants.IDENTIFIERS_FILENAME)
                    SqliteCache(cachepath)
                    with sqlite3.connect(cachepath) as db:
                        db.execute('INSERT INTO cache(location, identifier, operating_system, local) VALUES(?,?,?,1)',(pp.as_uri(), WindowsIdentifier.generate(pdb['metadata']['windows']['pdb']['database'], '12'*16, 1), 'windows'))
                    classes = {name:getattr(extensions,name.lstrip('_')) for name in ('_EPROCESS','_ETHREAD','_LIST_ENTRY','_MMVAD','_MMVAD_SHORT','_EX_FAST_REF','_UNICODE_STRING')}
                    classes['_RTL_BALANCED_NODE'] = extensions.MMVAD_SHORT
                    ctx.symbol_space.append(IntermediateSymbolTable(ctx, 'symbols', 'kernel', kp.as_uri(), class_types=classes))
                    ctx.module('kernel', 'memory', 0x10000)
                    config={'kernel':'kernel'}
                    if scenario.startswith('pid-'):config['pid']=[104 if scenario=='pid-match' else 108]
                    if scenario=='second-filtered':config['pid']=[108]
                    runner = SimpleNamespace(context=ctx, config=config, config_path='analysis', etw_functions=EtwPatch.etw_functions)
                    rows = [[None if isinstance(cell, interfaces.renderers.BaseAbsentValue) else int(cell) if isinstance(cell,int) else str(cell) for cell in row] for _,row in EtwPatch._generator(runner)]
                writes = [dict(offset=at, data=bytes(data[at:at+256]).hex()) for at in range(0,len(data),256) if any(data[at:at+256])]
                cases.append(dict(width=width, name=scenario, isf=kernel, pdb=pdb, size=len(data), writes=writes, expected=rows))
        return json.dumps(dict(commit=COMMIT,cases=cases),indent=2)+'\n'
    finally:
        constants.CACHE_PATH, constants.OFFLINE = old_cache, old_offline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    result=generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:
            raise ValueError('ETW patch oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual paged ETW generator cases verified")


if __name__=='__main__':
    main()
