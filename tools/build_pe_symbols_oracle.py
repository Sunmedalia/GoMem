#!/usr/bin/env python3
"""Run the locked PE-symbol command on real paged process/kernel objects."""
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
OUTPUT = ROOT/'internal/engine/testdata/windows-pe-symbols-oracle.json'

def fixture(width, scenario):
    kernel, pdb, data = suspended_fixture(width, scenario)
    def put(at, value):
        struct.pack_into('<Q' if width == 8 else '<I', data, at, value)
    b = lambda name: dict(kind='base', name=name)
    st = lambda name: dict(kind='struct', name=name)
    f = lambda off, typ: dict(offset=off, type=typ)
    kernel['user_types']['_EPROCESS']['fields']['Session'] = f(88, b('uptr'))
    kernel['user_types']['_MM_SESSION_SPACE'] = dict(kind='struct', size=16, fields=dict(SessionId=f(8,b('u32'))))
    kernel['user_types']['_KLDR_DATA_TABLE_ENTRY'] = dict(kind='struct',size=64,fields=dict(InLoadOrderLinks=f(0,st('_LIST_ENTRY')),DllBase=f(16,b('uptr')),SizeOfImage=f(24,b('u32')),BaseDllName=f(32,st('_UNICODE_STRING'))))
    kernel['symbols']['PsLoadedModuleList'] = dict(address=0x9000)
    put(0x458,0x7000); put(0x558,0x7000); struct.pack_into('<I',data,0x7008,1)
    put(0x19000,0x1a000); put(0x19000+width,0x1a000)
    put(0x1a000,0x19000); put(0x1a000+width,0x19000)
    put(0x1a010,0x100000); struct.pack_into('<I',data,0x1a018,0x4000)
    name='fixture.dll'.encode('utf-16le')
    struct.pack_into('<HH',data,0x1a020,len(name),len(name)+2);put(0x1a028,0x1b000)
    data[0x1b000:0x1b000+len(name)]=name
    if scenario == 'legacy-module-type':
        kernel['user_types']['_LDR_DATA_TABLE_ENTRY'] = kernel['user_types'].pop('_KLDR_DATA_TABLE_ENTRY')
    elif scenario == 'session-fallback':
        del kernel['user_types']['_MM_SESSION_SPACE']
        kernel['base_types']['unsigned long'] = dict(kind='int', size=4, signed=False, endian='little')
    elif scenario == 'two-sessions':
        put(0x558,0x7100); struct.pack_into('<I',data,0x7108,2)
    elif scenario == 'duplicate-module':
        data[0x1a100:0x1a140] = data[0x1a000:0x1a040]
        put(0x19000+width,0x1a100)
        put(0x1a000,0x1a100)
        put(0x1a100,0x19000); put(0x1a100+width,0x1a000)
    return kernel,pdb,data


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires locked unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, constants
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.automagic.symbol_cache import SqliteCache, WindowsIdentifier
    from volatility3.plugins.windows.pe_symbols import PESymbols
    old_cache, old_offline = constants.CACHE_PATH, constants.OFFLINE
    fixtures, cases = [], []
    scenarios = ('normal', 'no-vads', 'relative-name', 'sharp-s-name', 'short-unicode-name', 'unc-share-only',
                 'rsds-directory-absent', 'rsds-different-directory-name', 'rsds-no-mz', 'rsds-cross-page',
                 'rsds-exact-end', 'rsds-past-end', 'rsds-first-guid-only', 'rsds-candidate-priority',
                 'legacy-module-type', 'session-fallback', 'two-sessions', 'duplicate-module')
    try:
        for width in (4,8):
            for scenario in scenarios:
                kernel,pdb,data = fixture(width,scenario)
                ctx=contexts.Context()
                ctx.layers.add_layer(BufferDataLayer(ctx,'physical','physical',bytes(data)))
                ctx.config['memory.memory_layer']='physical'
                ctx.config['memory.page_map_offset']=0x8000
                ctx.config['memory.kernel_virtual_offset']=0x10000
                ctx.layers.add_layer((Intel32e if width==8 else Intel)(ctx,'memory','memory'))
                with tempfile.TemporaryDirectory() as directory:
                    directory=Path(directory)
                    constants.CACHE_PATH,constants.OFFLINE=str(directory),True
                    kp,pp=directory/'kernel.json',directory/'pdb.json'
                    kp.write_text(json.dumps(kernel));pp.write_text(json.dumps(pdb))
                    cachepath=str(directory/constants.IDENTIFIERS_FILENAME)
                    SqliteCache(cachepath)
                    identity=pdb['metadata']['windows']['pdb']
                    with sqlite3.connect(cachepath) as db:
                        db.execute('INSERT INTO cache(location,identifier,operating_system,local) VALUES(?,?,?,1)',
                                   (pp.as_uri(),WindowsIdentifier.generate(identity['database'],identity['GUID'],identity['age']),'windows'))
                    classes={name:getattr(extensions,name.lstrip('_')) for name in ('_EPROCESS','_ETHREAD','_LIST_ENTRY','_MMVAD','_MMVAD_SHORT','_EX_FAST_REF','_UNICODE_STRING')}
                    classes['_RTL_BALANCED_NODE']=extensions.MMVAD_SHORT
                    ctx.symbol_space.append(IntermediateSymbolTable(ctx,'symbols','kernel',kp.as_uri(),class_types=classes))
                    ctx.module('kernel','memory',0x10000)
                    fixture_id=len(fixtures)
                    for source_name in ('processes','kernel'):
                        queries=[dict(module='fixture.dll',symbols=['AlphaPDB','Alpha','missing','AlphaPDB'],addresses=[]),
                                 dict(module='fixture.dll',symbols=[],addresses=['0x101200','0x101201','0x101700','0x101200']),
                                 dict(module='fixture.dll',symbols=['Alpha'],addresses=['0x101200'])]
                        if scenario=='normal':
                            queries += [dict(module=name,symbols=['Alpha'],addresses=[]) for name in ('FIXTURE.DLL','TURE.DLL','absent.dll','NTOSKRNL.EXE')]
                            queries += [dict(module='fixture.dll',symbols=[],addresses=[]),
                                        dict(module='fixture.dll',symbols=['a,b','Alpha'],addresses=[])]
                        for query in queries:
                            config=dict(kernel='kernel',source=source_name,module=query['module'],symbols=query['symbols'],addresses=[int(v,0) for v in query['addresses']])
                            runner=SimpleNamespace(context=ctx,config=config,config_path='analysis',get_process_modules=PESymbols.get_process_modules,get_kernel_modules=PESymbols.get_kernel_modules)
                            rows=[[str(row[0]),str(row[1]),int(row[2])] for _,row in PESymbols._generator(runner)]
                            cases.append(dict(fixture=fixture_id,source=source_name,query=query,expected=rows,native_error='invalid DOS signature' if scenario=='rsds-no-mz' else ''))
                writes=[dict(offset=at,data=bytes(data[at:at+256]).hex()) for at in range(0,len(data),256) if any(data[at:at+256])]
                fixtures.append(dict(width=width,name=scenario,isf=kernel,pdb=pdb,size=len(data),writes=writes))
        return json.dumps(dict(commit=COMMIT,fixtures=fixtures,cases=cases),indent=2)+'\n'
    finally:
        constants.CACHE_PATH,constants.OFFLINE=old_cache,old_offline


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    result=generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:raise ValueError('PE-symbol command oracle differs')
    else:OUTPUT.write_text(result)
    data=json.loads(result)
    print(f"{len(data['fixtures'])} paged fixtures, {len(data['cases'])} actual PE-symbol command queries verified")

if __name__=='__main__':
    main()
