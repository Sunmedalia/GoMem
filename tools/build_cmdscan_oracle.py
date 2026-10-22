#!/usr/bin/env python3
"""Run complete original CmdScan generators on real conhost/process/VAD objects."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_suspended_threads_oracle import fixture

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-cmdscan-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.plugins.windows.cmdscan import CmdScan

    cases = []
    for scenario in ['normal', 'unused-slot', 'length-1024', 'reversed-small', 'invalid-handle', 'unreadable-command', 'unreadable-bucket', 'unreadable-application', 'empty-commands', 'uppercase-process', 'missing-vad-page']:
        kernel, _, data = fixture(8, 'normal')
        b = lambda name: dict(kind='base', name=name)
        field = lambda at, typ: dict(offset=at, type=typ)
        kernel['user_types']['_DBGKD_GET_VERSION64'] = dict(kind='struct', size=4, fields={'MajorVersion':field(0,b('u16')), 'MinorVersion':field(2,b('u16'))})
        kernel['user_types']['_KUSER_SHARED_DATA'] = dict(kind='struct', size=8, fields={'NtMajorVersion':field(0,b('u32')), 'NtMinorVersion':field(4,b('u32'))})
        kernel['symbols']['KdVersionBlock'] = dict(address=0x6000)
        kernel['metadata']['windows']['pe'] = dict(major=10, minor=0, revision=0, build=19041)
        struct.pack_into('<HH',data,0x16000,15,19041)
        struct.pack_into('<II',data,0x18000,10,0)
        kuser=0xfffff78000000000
        for table,shift,target in [(0x8000,39,0x1c003),(0x1c000,30,0x1d003),(0x1d000,21,0x1e003),(0x1e000,12,0x18003)]:
            struct.pack_into('<Q',data,table+((kuser>>shift)&511)*8,target)
        data[0x418:0x428]=b'conhost.exe\0'+bytes(4)
        if scenario=='uppercase-process':data[0x418:0x428]=b'CONHOST.EXE\0'+bytes(4)
        path=r'C:\Windows\System32\conhost.exe'.encode('utf-16le')
        struct.pack_into('<HH',data,0x4000,len(path),len(path)+2)
        data[0x5000:0x5000+len(path)]=path
        data[0x100000:0x104000]=bytes(0x4000)
        # Replace the low huge page with actual 4KiB mappings for PTE holes.
        struct.pack_into('<Q',data,0xa000,0xb003)
        for i in range(512):struct.pack_into('<Q',data,0xb000+i*8,i*4096|3)
        if scenario=='missing-vad-page':struct.pack_into('<Q',data,0xb000+0x102*8,0)
        hist,bucket,handle,text=0x102000,0x102400,0x102800,0x102c00
        def q(at,value):struct.pack_into('<Q',data,at,value)
        q(hist+16,bucket);q(hist+24,bucket+64);q(hist+32,bucket+160)
        if scenario=='reversed-small':q(hist+24,bucket-1)
        struct.pack_into('<H',data,hist+40,50)
        data[hist+48:hist+62]='cmd.exe'.encode('utf-16le')
        struct.pack_into('<I',data,hist+64,7);struct.pack_into('<I',data,hist+72,16)
        q(hist+80,handle);struct.pack_into('<h',data,hist+92,-1)
        struct.pack_into('<I',data,handle+48,0 if scenario=='invalid-handle' else 4)
        for i,value in [(0,'whoami'),(1,'ipconfig')]+([(4,'unused')] if scenario=='unused-slot' else []):
            at=bucket+i*32
            if len(value)<8:data[at:at+len(value)*2]=value.encode('utf-16le')
            else:q(at,text);data[text:text+len(value)*2]=value.encode('utf-16le')
            struct.pack_into('<II',data,at+16,len(value),0)
            struct.pack_into('<I',data,at+24,1024)
        if scenario=='length-1024':struct.pack_into('<I',data,bucket+16,1024)
        if scenario=='unreadable-command':q(bucket+32,0x300000)
        if scenario=='unreadable-bucket':q(hist+16,0x300000);q(hist+24,0x300000);q(hist+32,0x300080)
        if scenario=='unreadable-application':q(hist+48,0x300000);struct.pack_into('<I',data,hist+64,8)
        if scenario=='empty-commands':data[bucket:bucket+160]=bytes(160)
        ctx=contexts.Context();ctx.layers.add_layer(BufferDataLayer(ctx,'physical','physical',bytes(data)))
        ctx.config['memory.memory_layer']='physical';ctx.config['memory.page_map_offset']=0x8000;ctx.config['memory.kernel_virtual_offset']=0x10000
        ctx.layers.add_layer(Intel32e(ctx,'memory','memory'))
        rows,error=[],None
        with tempfile.TemporaryDirectory(prefix='gomem-cmdscan-') as directory:
            p=Path(directory)/'kernel.json';p.write_text(json.dumps(kernel))
            classes={n:getattr(extensions,n.lstrip('_')) for n in ['_EPROCESS','_LIST_ENTRY','_MMVAD','_MMVAD_SHORT','_EX_FAST_REF','_UNICODE_STRING']}
            classes['_RTL_BALANCED_NODE']=extensions.MMVAD_SHORT
            ctx.symbol_space.append(IntermediateSymbolTable(ctx,'symbols','kernel',p.as_uri(),class_types=classes));ctx.module('kernel','memory',0x10000)
            runner=SimpleNamespace(context=ctx,_context=ctx,config_path='plugins.CmdScan',config={'kernel':'kernel','max_history':[50],'no_registry':True},get_command_history=CmdScan.get_command_history)
            processes=PsList.list_processes(ctx,'kernel',filter_func=lambda proc:CmdScan._conhost_proc_filter(runner,proc))
            try:
                for depth,row in CmdScan._generator(runner,processes):
                    vals=[]
                    for value in row:
                        if isinstance(value,interfaces.renderers.BaseAbsentValue):value=dict(missing=type(value).__name__)
                        elif not isinstance(value,str):value=int(value)
                        vals.append(value)
                    rows.append(dict(depth=depth,values=vals))
            except Exception as exc:error=type(exc).__name__
        cases.append(dict(scenario=scenario,isf=kernel,size=len(data),writes=[dict(offset=at,data=data[at:at+256].hex()) for at in range(0,len(data),256) if any(data[at:at+256])],rows=rows,error=error))
    by_name = {c['scenario']: c for c in cases}
    assert len(by_name['normal']['rows']) == 9 and by_name['normal']['error'] is None
    assert len(by_name['unused-slot']['rows']) == 10
    assert by_name['uppercase-process']['rows'] == []
    assert by_name['missing-vad-page']['error'] == 'UnboundLocalError'
    assert all(c['error'] is None for c in cases if c['scenario'] != 'missing-vad-page')
    return json.dumps(dict(commit=COMMIT,scope=__doc__,cases=cases),indent=2)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT));p.add_argument('--check',action='store_true');args=p.parse_args()
    result=generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text()!=result:raise SystemExit('cmdscan oracle drift')
    else:OUTPUT.write_text(result)
    print('11 complete original CmdScan controls verified')


if __name__=='__main__':main()
