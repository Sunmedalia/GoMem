#!/usr/bin/env python3
"""Run actual pinned Windows Malfind over real paged process/VAD objects."""
import argparse
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
from build_suspended_threads_oracle import fixture
from baseline_matrix import ROOT, tree_digest

COMMIT='881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT=ROOT/'internal/engine/testdata/windows-malfind-oracle.json'


def generate(source):
    if tree_digest(source)!=json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0,str(source))
    from volatility3.framework import contexts,interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel,Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.plugins.windows.malware.malfind import Malfind
    results=[]
    for width in (4,8):
        for scenario in ('rwx-private-short','rwx-private-long','rwx-shared','writecopy-shared','writecopy-private','read-only','rx-clean','rx-dirty','rx-hole-first','rwx-zero','rwx-first-zero','rwx-first-hole','mz','pe-prologue','x64-prologue','x86-prologue','core','u1-private','core-shared','core-u1','u1-precedence','wow64','rx-second-dirty','rx-hole-before-dirty','guard-rwx','rwx-all-hole','rx-dirty-zero','readwrite-private','no-vads','pid-match','pid-mismatch','second-mz','second-filtered','dump-normal','dump-hole'):
            kernel,_,data=fixture(width,'normal')
            kernel['base_types']['int']=dict(kind='int',size=4,signed=True,endian='little')
            def put(at,value):struct.pack_into('<Q' if width==8 else '<I',data,at,value)
            def dword(at,value):struct.pack_into('<I',data,at,value)
            b=lambda name:dict(kind='base',name=name)
            field=lambda offset,typ:dict(offset=offset,type=typ)
            typ=lambda size,fields:dict(kind='struct',size=size,fields=fields)
            kernel['user_types']['_MMVAD_FLAGS']=typ(4,dict(Protection=field(0,dict(kind='bitfield',bit_position=0,bit_length=5,type=b('u32'))),PrivateMemory=field(0,dict(kind='bitfield',bit_position=8,bit_length=1,type=b('u32'))),CommitCharge=field(0,dict(kind='bitfield',bit_position=16,bit_length=16,type=b('u32')))))
            kernel['user_types']['_MMVAD_FLAGS_UNION']=typ(4,dict(VadFlags=field(0,dict(kind='struct',name='_MMVAD_FLAGS'))))
            for name in ('_MMVAD','_MMVAD_SHORT'):
                kernel['user_types'][name]['size']=56
                kernel['user_types'][name]['fields']['u']=field(48,dict(kind='struct',name='_MMVAD_FLAGS_UNION'))
            if scenario in ('core','core-shared','core-u1'):
                kernel['user_types']['_MMVAD']['fields']['Core']=field(0,dict(kind='struct',name='_MMVAD_SHORT'));del kernel['user_types']['_MMVAD']['fields']['u']
            if scenario in ('u1-private','u1-precedence','core-u1'):
                kernel['user_types']['_MMVAD_FLAGS1']=typ(4,dict(PrivateMemory=field(0,dict(kind='bitfield',bit_position=8,bit_length=1,type=b('u32'))),CommitCharge=field(0,dict(kind='bitfield',bit_position=16,bit_length=16,type=b('u32')))))
                kernel['user_types']['_MMVAD_FLAGS1_UNION']=typ(4,dict(VadFlags1=field(0,dict(kind='struct',name='_MMVAD_FLAGS1'))))
                for name in ('_MMVAD','_MMVAD_SHORT'):kernel['user_types'][name]['fields']['u1']=field(52,dict(kind='struct',name='_MMVAD_FLAGS1_UNION'))
                dword(0x1034,0x30000|(0 if scenario in ('u1-precedence','core-u1') else 0x100))
            kernel['symbols']['MmProtectToValue']=dict(address=0x9000)
            private=0 if scenario in ('rwx-shared','writecopy-shared','core-shared','core-u1') else 1
            protection=0x80 if scenario.startswith('writecopy') else 0x20 if scenario.startswith('rx-') else 0x02 if scenario=='read-only' else 0x40
            dword(0x1030,1|(private<<8)|(3<<16));dword(0x19004,protection)
            if scenario=='core-shared':
                kernel['user_types']['_MMVAD_SHORT']['fields']['CommitCharge']=field(52,b('u32'));dword(0x1034,3)
            if scenario=='guard-rwx': dword(0x19004,0x140)
            if scenario=='wow64':
                kernel['user_types']['_EPROCESS']['fields']['Wow64Process']=field(88,dict(kind='pointer',subtype=b('u8')));put(0x458,0x1234)
            short=scenario not in ('rwx-private-long','core','core-shared','core-u1')
            data[0x1000-(12 if width==8 else 4):0x1000-(12 if width==8 else 4)+4]=b'VadS' if short else b'Vadl'
            data[0x100000:0x104000]=bytes(0x4000)
            if scenario not in ('rwx-zero','rx-dirty-zero'):data[0x100000 if scenario not in ('rwx-first-zero','rwx-first-hole') else 0x101000]=0x90
            if scenario in ('mz','pe-prologue','x64-prologue','x86-prologue'):
                data[0x100000:0x100002]={'mz':b'MZ','pe-prologue':b'\x55\x8b','x64-prologue':b'\x55\x48','x86-prologue':b'\x55\x89'}[scenario]
            # Map small pages so dirty and missing-page observations are independent.
            if width==8:
                put(0xa000,0xb003)
                for i in range(512):put(0xb000+i*8,(i<<12)|3)
                leaf=0xb000+0x100*8
            else:
                put(0x8000,0x9003)
                for i in range(1024):put(0x9000+i*4,(i<<12)|3)
                leaf=0x9000+0x100*4
            if scenario in ('rx-dirty','rx-dirty-zero'):put(leaf,0x100043)
            if scenario in ('rx-second-dirty','rx-hole-before-dirty'):put(leaf+width,0x101043)
            if scenario in ('rx-hole-first','rwx-first-hole','rx-hole-before-dirty','dump-hole'):put(leaf,0)
            if scenario=='dump-hole':data[0x101000]=0x90
            if scenario=='rwx-all-hole':
                for index in range(4):put(leaf+index*width,0)
            if scenario=='readwrite-private':dword(0x19004,4)
            if scenario=='no-vads':put(0x430,0)
            if scenario.startswith('second-'):
                put(0x18080+width,0x500);put(0x400,0x500)
                put(0x500,0x18080);put(0x500+width,0x400)
                put(0x540,0x540);put(0x540+width,0x540);put(0x550,0x20000)
                if width==8:
                    put(0x20000,0x21003);put(0x21000,0x22003);put(0x22000,0x23003)
                    for index in range(512):put(0x23000+index*8,(index<<12)|3)
                    put(0x23000+0x100*8,0x1e0003)
                else:
                    put(0x20000,0x25003)
                    for index in range(1024):put(0x25000+index*4,(index<<12)|3)
                    put(0x25000+0x100*4,0x1e0003)
                data[0x1e0000:0x1e1000]=data[0x100000:0x101000];data[0x1e0000:0x1e0002]=b'MZ'
            ctx=contexts.Context();ctx.layers.add_layer(BufferDataLayer(ctx,'physical','physical',bytes(data)))
            ctx.config['memory.memory_layer']='physical';ctx.config['memory.page_map_offset']=0x8000;ctx.config['memory.kernel_virtual_offset']=0x10000
            ctx.layers.add_layer((Intel32e if width==8 else Intel)(ctx,'memory','memory'))
            expected=[];error=None
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'kernel.json';path.write_text(json.dumps(kernel))
                classes={name:getattr(extensions,name.lstrip('_')) for name in ('_EPROCESS','_ETHREAD','_LIST_ENTRY','_MMVAD','_MMVAD_SHORT','_EX_FAST_REF','_UNICODE_STRING')};classes['_RTL_BALANCED_NODE']=extensions.MMVAD_SHORT
                ctx.symbol_space.append(IntermediateSymbolTable(ctx,'symbols','kernel',path.as_uri(),class_types=classes));ctx.module('kernel','memory',0x10000)
                files={}
                class Capture(interfaces.plugins.FileHandlerInterface):
                    def __init__(self,name):
                        super().__init__(name)
                        self.buffer=io.BytesIO()
                    def write(self,data):
                        return self.buffer.write(data)
                    def close(self):
                        if not self.closed:
                            files[self.preferred_filename]=self.buffer.getvalue().hex()
                            super().close()
                runner=SimpleNamespace(context=ctx,config={'kernel':'kernel','dump':scenario.startswith('dump-')},config_path='analysis',list_injection_sites=Malfind.list_injection_sites,open=Capture)
                try:
                    for _,row in Malfind._generator(runner,PsList.list_processes(ctx,'kernel',filter_func=PsList.create_pid_filter([108] if scenario in ('pid-mismatch','second-filtered') else [104] if scenario=='pid-match' else []))):
                        normalized=[]
                        for cell in row:
                            if isinstance(cell,interfaces.renderers.BaseAbsentValue):value=None
                            elif isinstance(cell,int):value=int(cell)
                            elif hasattr(cell,'offset') and hasattr(cell,'length'):
                                value=dict(offset=cell.offset,length=cell.length,raw=cell.context.layers[cell.layer_name].read(cell.offset,cell.length,pad=True).hex())
                            elif hasattr(cell,'data') and hasattr(cell,'architecture'):
                                value=dict(data=cell.data.hex(),architecture=cell.architecture)
                            else:value=str(cell)
                            normalized.append(value)
                        expected.append(normalized)
                except Exception as exc:error=type(exc).__name__+': '+str(exc)
            writes=[dict(offset=at,data=bytes(data[at:at+256]).hex()) for at in range(0,len(data),256) if any(data[at:at+256])]
            results.append(dict(width=width,scenario=scenario,isf=kernel,size=len(data),writes=writes,rows=expected,error=error,files=files))
    cases=[]
    for case in results:
        if case['error'] is not None:
            raise ValueError(f"unexpected generator failure: {case['error']}")
        case['name']=case.pop('scenario')
        case['expected']=case.pop('rows')
        cases.append(case)
    return json.dumps(dict(commit=COMMIT,cases=cases),indent=2)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    result=generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:
            raise ValueError('Windows malfind oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual paged Windows malfind cases verified")


if __name__=='__main__':
    main()
