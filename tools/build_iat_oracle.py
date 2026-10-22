#!/usr/bin/env python3
"""Exercise the actual pinned IAT generator using paged process objects."""
import argparse
import importlib.metadata
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
from baseline_matrix import ROOT, tree_digest
from build_suspended_threads_oracle import fixture as suspended_fixture
COMMIT='881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def fixture(width, scenario):
    kernel, _, data=suspended_fixture(width,'normal')
    def put(at,value):
        struct.pack_into('<Q' if width==8 else '<I',data,at,value)
    def dword(at,value):
        struct.pack_into('<I',data,at,value)
    kernel['user_types']['_EPROCESS']['fields']['Peb']=dict(offset=88,type=dict(kind='pointer',subtype=dict(kind='struct',name='_PEB')))
    kernel['user_types']['_PEB']=dict(kind='struct',size=width,fields=dict(ImageBaseAddress=dict(offset=0,type=dict(kind='base',name='uptr'))))
    put(0x458,0x6000);put(0x6000,0x100000)
    directory=0x100000+0x98+(112 if width==8 else 96)+8
    struct.pack_into('<II',data,directory,0x1c00,40)
    struct.pack_into('<IIIII',data,0x101c00,0x1d00,0,0,0x1e00,0x1d80)
    put(0x101d00,0x1f00);put(0x101d00+width,(1<<(width*8-1))|12)
    put(0x101d80,0x70001234);put(0x101d80+width,0x70005678)
    data[0x101e00:0x101e0d]=b'KERNEL32.dll\0'
    data[0x101f00:0x101f08]=b'\0\0FuncA\0'
    put(0x100000+0x98+(24 if width==8 else 28),0x400000)
    if scenario=='bound': dword(0x101c04,0xffffffff)
    elif scenario=='bound-one': dword(0x101c04,1)
    elif scenario=='no-directory': data[directory:directory+8]=bytes(8)
    elif scenario=='zero-size': dword(directory+4,0)
    elif scenario=='small-size': dword(directory+4,1)
    elif scenario=='no-directory-count': dword(directory-12,1)
    elif scenario=='empty-descriptor': data[0x101c00:0x101c14]=bytes(20)
    elif scenario=='no-ilt':
        dword(0x101c00,0);put(0x101d80,0x1f00);put(0x101d80+width,(1<<(width*8-1))|12)
    elif scenario=='no-iat': dword(0x101c10,0)
    elif scenario=='empty-ilt': put(0x101d00,0)
    elif scenario=='empty-iat': put(0x101d80,0)
    elif scenario=='both-empty': put(0x101d00,0);put(0x101d80,0)
    elif scenario=='bad-ilt': dword(0x101c00,0x5000)
    elif scenario=='bad-iat': dword(0x101c10,0x5000)
    elif scenario=='overlap-ilt': put(0x101d00,0x1d00)
    elif scenario=='ordinal-zero': put(0x101d00+width,1<<(width*8-1))
    elif scenario=='bad-ordinal': put(0x101d00+width,(1<<(width*8-1))|0x10000)
    elif scenario=='name-spaces': data[0x101f02:0x101f08]=b'A B\0\0\0'
    elif scenario=='name-empty': data[0x101f02]=0
    elif scenario=='name-invalid': data[0x101f02]=0xff
    elif scenario=='dll-empty': data[0x101e00]=0
    elif scenario=='dll-invalid': data[0x101e00]=0xff
    elif scenario=='dll-path': data[0x101e00:0x101e0d]=b'C:\\bad.dll\0\0\0'
    elif scenario=='known-ordinal':
        data[0x101e00:0x101e0d]=b'ws2_32.dll\0\0\0';put(0x101d00+width,(1<<(width*8-1))|1)
    elif scenario=='duplicate': put(0x101d00+width,0x1f00)
    elif scenario=='two-libraries':
        struct.pack_into('<IIIII',data,0x101c14,0x1d00,3,0,0x1e20,0x1d80)
        data[0x101e20:0x101e2d]=b'SECOND.dll\0\0\0'
    elif scenario=='no-peb': put(0x458,0)
    elif scenario=='no-base': put(0x6000,0)
    elif scenario=='bad-mz': data[0x100000:0x100002]=b'XX'
    elif scenario=='bad-pe': data[0x100080:0x100084]=b'XX\0\0'
    elif scenario=='iat-before-directory':
        dword(0x101c10,0x1b80);data[0x101b80:0x101b80+width*3]=data[0x101d80:0x101d80+width*3]
    elif scenario=='ilt-before-directory':
        dword(0x101c00,0x1b00);data[0x101b00:0x101b00+width*3]=data[0x101d00:0x101d00+width*3]
    elif scenario=='bad-function-rva': put(0x101d00,0x8000)
    elif scenario=='bad-dll-rva': dword(0x101c0c,0x8000)
    if scenario in ('first-bad-ilt','first-bad-dll'):
        struct.pack_into('<IIIII',data,0x101c14,0x1d00,3,0,0x1e20,0x1d80)
        data[0x101e20:0x101e2d]=b'SECOND.dll\0\0\0'
        dword(0x101c00 if scenario=='first-bad-ilt' else 0x101c0c,0x5000)
    elif scenario in ('long-function','long-library'):
        address=0x102400 if scenario=='long-function' else 0x102200
        content=(b'\0\0' if scenario=='long-function' else b'')+b'A'*513+b'\0'
        data[address:address+len(content)]=content
        if scenario=='long-function': put(0x101d00,0x2400)
        else: dword(0x101c0c,0x2200)
    elif scenario=='repeated-thunks':
        dword(0x101c00,0x2200);dword(0x101c10,0x2400)
        for index in range(17):put(0x102200+index*width,0x1f00)
    elif scenario=='known-missing-ordinal':
        data[0x101e00:0x101e0d]=b'ws2_32.dll\0\0\0';put(0x101d00+width,(1<<(width*8-1))|999)
    elif scenario.startswith('second-'):
        put(0x18080+width,0x500);put(0x400,0x500)
        put(0x500,0x18080);put(0x500+width,0x400)
        put(0x540,0x540);put(0x540+width,0x540);put(0x550,0xb000);put(0x558,0x6000)
        if width==8:
            put(0xb000,0xc003);put(0xc000,0xd003);put(0xd000,0xe003)
            for index in range(512):put(0xe000+index*8,(index<<12)|3)
            put(0xe000+0x101*8,0x1e0003)
        else:
            put(0xb000,0xc003)
            for index in range(1024):put(0xc000+index*4,(index<<12)|3)
            put(0xc000+0x101*4,0x1e0003)
        data[0x1e0000:0x1e1000]=data[0x101000:0x102000]
        data[0x1e0f02:0x1e0f07]=b'FuncB'
        put(0x1e0d80,0x70009999)
    assert len(data)==2<<20, (scenario,len(data))
    return kernel,data


def generate(source):
    if importlib.metadata.version('pefile') != '2024.8.26':
        raise ValueError('requires pefile==2024.8.26')
    if tree_digest(source)!=json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires locked unmodified source')
    sys.path.insert(0,str(source))
    from volatility3.framework import contexts,interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel,Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.plugins.windows.iat import IAT
    cases=[]
    scenarios=('normal','bound','bound-one','no-directory','zero-size','small-size','no-directory-count','empty-descriptor','no-ilt','no-iat','empty-ilt','empty-iat','both-empty','bad-ilt','bad-iat','overlap-ilt','ordinal-zero','bad-ordinal','name-spaces','name-empty','name-invalid','dll-empty','dll-invalid','dll-path','known-ordinal','duplicate','two-libraries','no-peb','no-base','bad-mz','bad-pe','iat-before-directory','ilt-before-directory','bad-function-rva','bad-dll-rva','pid-match','pid-mismatch','first-bad-ilt','first-bad-dll','long-function','long-library','repeated-thunks','known-missing-ordinal','second-normal','second-filtered')
    for width in (4,8):
        for scenario in scenarios:
            kernel,data=fixture(width,scenario)
            ctx=contexts.Context();ctx.layers.add_layer(BufferDataLayer(ctx,'physical','physical',bytes(data)))
            ctx.config['memory.memory_layer']='physical';ctx.config['memory.page_map_offset']=0x8000;ctx.config['memory.kernel_virtual_offset']=0x10000
            ctx.layers.add_layer((Intel32e if width==8 else Intel)(ctx,'memory','memory'))
            expected=[];error=None
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'kernel.json';path.write_text(json.dumps(kernel))
                classes={name:getattr(extensions,name.lstrip('_')) for name in ('_EPROCESS','_ETHREAD','_LIST_ENTRY','_MMVAD','_MMVAD_SHORT','_EX_FAST_REF','_UNICODE_STRING')}
                classes['_RTL_BALANCED_NODE']=extensions.MMVAD_SHORT
                ctx.symbol_space.append(IntermediateSymbolTable(ctx,'symbols','kernel',path.as_uri(),class_types=classes));ctx.module('kernel','memory',0x10000)
                runner=SimpleNamespace(context=ctx,config={'kernel':'kernel'},config_path='analysis')
                try:
                    for _,row in IAT._generator(runner,PsList.list_processes(ctx,'kernel',filter_func=PsList.create_pid_filter([108] if scenario in ('pid-mismatch','second-filtered') else [104] if scenario=='pid-match' else []))):
                        expected.append([None if isinstance(cell,interfaces.renderers.BaseAbsentValue) else bool(cell) if isinstance(cell,bool) else int(cell) if isinstance(cell,int) else str(cell) for cell in row])
                except Exception as exc:
                    error=type(exc).__name__+': '+str(exc)
            writes=[dict(offset=at,data=bytes(data[at:at+256]).hex()) for at in range(0,len(data),256) if any(data[at:at+256])]
            cases.append(dict(width=width,name=scenario,isf=kernel,size=len(data),writes=writes,expected=expected,error=error))
    return dict(commit=COMMIT,cases=cases)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    result=json.dumps(generate(args.source),indent=2)+'\n'
    output=ROOT/'internal/engine/testdata/windows-iat-oracle.json'
    if args.check:
        if output.read_text()!=result:
            raise ValueError('IAT oracle differs')
    else:
        output.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual paged IAT generator cases verified")


if __name__=='__main__':
    main()
