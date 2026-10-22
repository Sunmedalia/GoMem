#!/usr/bin/env python3
"""Run original GUI executive names, station info and desktop enumeration."""
import argparse
import copy
import json
import random
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/wingui/testdata/names-oracle.json'
SCENARIOS = ['normal', 'zero-name-info', 'header-hole', 'table-hole', 'mask-hole',
             'length-zero', 'max-zero', 'length-over-max', 'maximum-hole',
             'length-zero-maximum-hole', 'buffer-hole', 'name-hole', 'name-tail-hole',
             'odd-name', 'odd-surrogate-tail', 'unpaired-name', 'bom-le', 'bom-be',
             'embedded-nul', 'one-character', 'one-unicode-character', 'replacement-name',
             'station-session-hole', 'station-session-256', 'desktop-null',
             'desktop-pointer-hole', 'desktop-name-hole', 'desktop-name-empty',
             'nul-name', 'bom-only', 'one-emoji', 'one-byte']


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0,str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.symbols.windows.extensions import gui, pool
    seeds=json.loads((ROOT/'pkg/wingui/testdata/object-oracle.json').read_text())
    if seeds['commit']!=COMMIT:raise ValueError('object seed baseline mismatch')
    cases=[]
    for seed in seeds['cases']:
        if seed['scenario']!='normal':continue
        layout=source/'volatility3/framework/symbols/windows/gui'/(seed['layout']+'.json')
        types=json.loads(layout.read_text())['user_types']
        off=lambda typ,field:types[typ]['fields'][field]['offset']
        for header_kind in ['offset','infomask']:
            kernel=copy.deepcopy(seeds['kernel'])
            b=lambda n:dict(kind='base',name=n)
            s=lambda n:dict(kind='struct',name=n)
            f=lambda at,ref:dict(offset=at,type=ref)
            typ=lambda size,fields:dict(kind='struct',size=size,fields=fields)
            kernel['base_types']['u16']=dict(kind='int',size=2,signed=False,endian='little')
            kernel['base_types']['unsigned char']=dict(kind='int',size=1,signed=False,endian='little')
            fields=dict(Body=f(0x30,dict(kind='array',count=16,subtype=b('u8'))),InfoMask=f(0x1a,b('u8')))
            if header_kind=='offset':fields['NameInfoOffset']=f(0x19,b('u8'))
            kernel['user_types']['_OBJECT_HEADER']=typ(0x40,fields)
            kernel['user_types']['_OBJECT_HEADER_NAME_INFO']=typ(32,dict(Name=f(8,s('_UNICODE_STRING'))))
            kernel['user_types']['_UNICODE_STRING']=typ(16,dict(Length=f(0,b('u16')),MaximumLength=f(2,b('u16')),Buffer=f(8,dict(kind='pointer',subtype=b('u16')))))
            kernel['symbols']['ObpInfoMaskToOffset']=dict(address=0x100)
            for scenario in SCENARIOS:
                data=bytearray(seed['size']);holes=[]
                for write in seed['writes']:
                    raw=bytes.fromhex(write['data']);data[write['offset']:write['offset']+len(raw)]=raw
                root,desktop=seed['root'],seed['desktop']
                def q(at,value):struct.pack_into('<Q',data,at,value)
                def h(at,value):struct.pack_into('<H',data,at,value)
                def name(at,buffer,text):
                    raw=text.encode('utf-16le')
                    header=at-0x30;info=header-32
                    data[header+0x19]=32;data[header+0x1a]=2
                    h(info+8,len(raw));h(info+10,len(raw)+2);q(info+16,buffer)
                    data[buffer:buffer+len(raw)]=raw
                data[0x1102]=32
                name(root,0x11000,'WinSta0');name(0x5000,0x11400,'Other')
                name(desktop,0x12000,'Default');name(0x9000,0x12400,'Second')
                q(root+off('tagWINDOWSTATION','rpdeskList'),0 if scenario=='desktop-null' else desktop)
                q(0x5000+off('tagWINDOWSTATION','rpdeskList'),0x9000)
                q(0x9000+off('tagDESKTOP','rpwinstaParent'),root)
                header=root-0x30;info=header-32
                if scenario=='zero-name-info':data[header+0x19]=0;data[0x1102]=0
                if scenario in ['length-zero','length-zero-maximum-hole']:h(info+8,0)
                if scenario=='max-zero':h(info+10,0)
                if scenario=='length-over-max':h(info+10,2)
                raw={'odd-name':b'A\0B', 'odd-surrogate-tail':b'X\0\0\xd8A',
                     'unpaired-name':b'X\0\0\xd8Y\0', 'bom-le':b'\xff\xfe'+ 'WinSta0'.encode('utf-16le'),
                     'bom-be':b'\xfe\xff'+'WinSta0'.encode('utf-16be'),
                     'embedded-nul':'A\0B'.encode('utf-16le'), 'one-character':b'A\0',
                     'one-unicode-character':'站'.encode('utf-16le'),
                     'replacement-name':'A\ufffdB'.encode('utf-16le'), 'nul-name':b'\0\0',
                     'bom-only':b'\xff\xfe', 'one-emoji':'😀'.encode('utf-16le'), 'one-byte':b'\xff'}.get(scenario)
                if raw is not None:
                    data[0x11000:0x11000+len(raw)]=raw;h(info+8,len(raw));h(info+10,len(raw)+2)
                if scenario=='station-session-256':struct.pack_into('<I',data,root+off('tagWINDOWSTATION','dwSessionId'),256)
                if scenario=='desktop-name-empty':h(desktop-0x30-32+8,0)
                fault={'header-hole':(header+0x19 if header_kind=='offset' else header+0x1a,1),
                       'table-hole':(0x1102,1),'mask-hole':(header+0x1a,1),
                       'maximum-hole':(info+10,2),'length-zero-maximum-hole':(info+10,2),
                       'buffer-hole':(info+16,8),'name-hole':(0x11000,1),'name-tail-hole':(0x1100c,1),
                       'station-session-hole':(root+off('tagWINDOWSTATION','dwSessionId'),4),
                       'desktop-pointer-hole':(root+off('tagWINDOWSTATION','rpdeskList'),8),
                       'desktop-name-hole':(0x12000,1)}.get(scenario)
                if fault:holes.append(fault)
                class OriginalLayer(BufferDataLayer):
                    @property
                    def address_mask(self):return (1<<64)-1
                    def read(self,at,length,pad=False):
                        for start,size in holes:
                            if at<start+size and start<at+length:raise exceptions.InvalidAddressException(self.name,max(at,start))
                        return super().read(at,length,pad)
                context=contexts.Context();context.layers.add_layer(OriginalLayer(context,'memory','memory',bytes(data)))
                with tempfile.TemporaryDirectory(prefix='gomem-gui-names-') as directory:
                    path=Path(directory)/'kernel.json';path.write_text(json.dumps(kernel))
                    context.symbol_space.append(IntermediateSymbolTable(context,'kernel','kernel',path.as_uri(),class_types={'_LIST_ENTRY':extensions.LIST_ENTRY,'_UNICODE_STRING':extensions.UNICODE_STRING,'_OBJECT_HEADER':pool.OBJECT_HEADER}))
                    context.module('kernel','memory',0x1000)
                    context.symbol_space.append(IntermediateSymbolTable(context,'gui','gui',layout.as_uri(),class_types=gui.GUIExtensions.class_types,table_mapping={'nt_symbols':'kernel'}))
                    station=context.object('gui!tagWINDOWSTATION','memory',root)
                    def result(call):
                        try:return dict(value=call())
                        except Exception as error:return dict(error=type(error).__name__)
                    def info_value():
                        text,sid=station.get_info('kernel')
                        return [str(text) if text is not None else None,int(sid) if sid is not None else None]
                    results=dict(name=result(lambda:station.get_name('kernel')),info=result(info_value),
                                 desktops=result(lambda:[dict(address=int(d.vol.offset),name=n) for d,n in station.desktops('kernel')]),
                                 desktops_one=result(lambda:[dict(address=int(d.vol.offset),name=n) for d,n in station.desktops('kernel',max_desktops=1)]),
                                 desktops_zero=result(lambda:[dict(address=int(d.vol.offset),name=n) for d,n in station.desktops('kernel',max_desktops=0)]))
                cases.append(dict(layout=seed['layout'],header_kind=header_kind,scenario=scenario,kernel=kernel,kernel_base=0x1000,size=len(data),root=root,desktop=desktop,holes=holes,results=results,
                                  writes=[dict(offset=at,data=data[at:at+256].hex()) for at in range(0,len(data),256) if any(data[at:at+256])]))
    assert len(cases)==768
    for case in cases:
        if case['scenario']=='normal':
            assert case['results']['name']==dict(value='WinSta0')
            assert case['results']['info']==dict(value=['WinSta0',1])
            assert case['results']['desktops']==dict(value=[dict(address=0x8000,name='Default')])
    rng=random.Random(0x475549)
    codec_inputs=[b'',b'X\0\0\xd8A',b'\xfe\xff\xd8\0A',b'\xff\xfe']+[rng.randbytes(i%33) for i in range(508)]
    codec=[dict(raw=raw.hex(),text=raw.decode('utf16','replace').split('\0',1)[0]) for raw in codec_inputs]
    return json.dumps(dict(commit=COMMIT,scope=__doc__,cases=cases,codec=codec),indent=2)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT));parser.add_argument('--check',action='store_true')
    args=parser.parse_args();result=generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text()!=result:raise SystemExit('GUI name oracle drift')
    else:OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original GUI name/desktop controls verified')


if __name__=='__main__':main()
