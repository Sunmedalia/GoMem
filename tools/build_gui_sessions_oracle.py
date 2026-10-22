#!/usr/bin/env python3
"""Run original Modules session-map discovery with actual process and Intel layers."""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/wingui/testdata/sessions-oracle.json'
SCENARIOS = ['normal','duplicate-session','duplicate-pid','session-null','session-unmapped',
             'session-hole','session-pointer-hole','cr3-hole','pid-hole','name-hole',
             'zero-cr3','bad-cr3','array32-cr3','array32-high-cr3','array64-cr3','filter-first','filter-second',
             'empty-filter','broken-forward','bad-backlink','forward-head-hole','empty-list',
             'session-max','tagged-cr3','first-owner-fault']


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0,str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.plugins.windows.modules import Modules
    b=lambda name:dict(kind='base',name=name)
    s=lambda name:dict(kind='struct',name=name)
    ptr=lambda name:dict(kind='pointer',subtype=s(name))
    f=lambda at,ref:dict(offset=at,type=ref)
    typ=lambda size,fields:dict(kind='struct',size=size,fields=fields)
    kernel=dict(metadata=dict(format='6.2.0'),
                base_types={name:dict(kind='int',size=size,signed=False,endian='little') for name,size in [('pointer',8),('u8',1),('u32',4),('u64',8),('unsigned long',4),('unsigned long long',8)]},
                user_types={'_LIST_ENTRY':typ(16,dict(Flink=f(0,ptr('_LIST_ENTRY')),Blink=f(8,ptr('_LIST_ENTRY')))),
                            '_KPROCESS':typ(16,dict(DirectoryTableBase=f(0,b('u64')))),
                            '_EPROCESS':typ(128,dict(ActiveProcessLinks=f(0,s('_LIST_ENTRY')),UniqueProcessId=f(16,b('u64')),Pcb=f(24,s('_KPROCESS')),Session=f(40,ptr('_MM_SESSION_SPACE')),ImageFileName=f(48,dict(kind='array',count=16,subtype=b('u8'))))),
                            '_MM_SESSION_SPACE':typ(16,dict(SessionId=f(12,b('u32'))))},
                enums={},symbols={'PsActiveProcessHead':dict(address=0x8080)})
    cases=[]
    for layout in ['typed','opaque-type','opaque-member']:
        for scenario in SCENARIOS:
            doc=copy.deepcopy(kernel)
            if layout=='opaque-type':del doc['user_types']['_MM_SESSION_SPACE']
            if layout=='opaque-member':del doc['user_types']['_MM_SESSION_SPACE']['fields']['SessionId']
            if scenario in ['array32-cr3','array32-high-cr3','array64-cr3']:
                doc['user_types']['_KPROCESS']['fields']['DirectoryTableBase']['type']=dict(kind='array',count=2 if scenario.startswith('array32') else 1,subtype=b('u32' if scenario.startswith('array32') else 'u64'))
            data=bytearray(0x80000);holes=[]
            def q(at,value):struct.pack_into('<Q',data,at,value)
            def d(at,value):struct.pack_into('<I',data,at,value)
            q(0x1000,0x2003);q(0x2000,0x3003);q(0x3000,0x83)
            processes=[0x20000+i*0x1000 for i in range(4)]
            head=0x18080
            q(head,head if scenario=='empty-list' else processes[0]);q(head+8,head if scenario=='empty-list' else processes[-1])
            for i,process in enumerate(processes):
                root=0x4000+i*0x3000
                q(process,processes[i+1] if i<3 else head);q(process+8,processes[i-1] if i else head)
                q(process+16,100 if scenario=='duplicate-pid' else 100+i)
                q(process+24,root)
                q(process+40,0x28000+i*0x1000)
                data[process+48:process+56]=b'ignored\0'
                sid=[1,2,1,3][i]
                if scenario=='duplicate-session':sid=1
                if scenario=='session-max' and i==0:sid=0xffffffff
                # Different values at offset 8 distinguish the upstream fallback.
                d(0x28008+i*0x1000,sid if sid==0xffffffff else sid+50)
                d(0x2800c+i*0x1000,sid)
                q(root,root+0x1000|3);q(root+0x1000,root+0x2000|3)
                q(root+0x2000,0x40000+i*0x1000|3)
                q(root+0x2010,0x10000+i*0x1000|3)
                for page in range(512):q(0x40000+i*0x1000+page*8,page*4096|3)
                # Process-private shadows ensure the session ID must be read
                # through the kernel layer, not the newly constructed process layer.
                q(0x40000+i*0x1000+(0x28+i)*8,0x38000+i*0x1000|3)
                d(0x38008+i*0x1000,900+i);d(0x3800c+i*0x1000,900+i)
                q(0x10000+i*0x1000,0x30000+i*0x1000|3)
                marker=f'gui-owner-{i:06d}'.encode()
                assert len(marker)==16
                data[0x30000+i*0x1000:0x30010+i*0x1000]=marker
            first=processes[0]
            if scenario=='session-null':q(first+40,0)
            if scenario=='session-unmapped':q(first+40,0x300000)
            if scenario=='array32-high-cr3':d(first+28,1)
            if scenario=='zero-cr3':q(first+24,0)
            if scenario=='bad-cr3':q(first+24,0x100000)
            if scenario=='tagged-cr3':q(first+24,0x4007)
            if scenario=='broken-forward':q(processes[1],0)
            if scenario=='bad-backlink':q(processes[1]+8,0xffffffffffffffff)
            fault={'session-hole':(0x28008 if layout!='typed' else 0x2800c,4),
                   'session-pointer-hole':(first+40,8),'cr3-hole':(first+24,8),
                   'pid-hole':(first+16,8),'name-hole':(first+48,16),
                   'forward-head-hole':(head+4,4),
                   'first-owner-fault':(first+40,8)}.get(scenario)
            if fault:holes.append(fault)
            pids=[100] if scenario=='filter-first' else [101] if scenario=='filter-second' else [] if scenario=='empty-filter' else None
            class OriginalLayer(BufferDataLayer):
                def is_valid(self,at,length=1):return super().is_valid(at,length) and not any(at<start+size and start<at+length for start,size in holes)
                def read(self,at,length,pad=False):
                    for start,size in holes:
                        if at<start+size and start<at+length:raise exceptions.InvalidAddressException(self.name,max(at,start))
                    return super().read(at,length,pad)
            context=contexts.Context();context.layers.add_layer(OriginalLayer(context,'physical','physical',bytes(data)))
            context.config['memory.memory_layer']='physical';context.config['memory.page_map_offset']=0x1000;context.config['memory.kernel_virtual_offset']=0x10000
            context.layers.add_layer(Intel32e(context,'memory','memory'))
            rows=[];error=None
            with tempfile.TemporaryDirectory(prefix='gomem-gui-sessions-') as directory:
                path=Path(directory)/'kernel.json';path.write_text(json.dumps(doc))
                context.symbol_space.append(IntermediateSymbolTable(context,'symbols','kernel',path.as_uri(),class_types={'_EPROCESS':extensions.EPROCESS,'_LIST_ENTRY':extensions.LIST_ENTRY}))
                context.module('kernel','memory',0x10000)
                try:
                    for sid,layer_name in Modules._do_get_session_layers(context,'kernel',pids):
                        layer=context.layers[layer_name]
                        # Layer names are presentation-specific. Compare the actual
                        # chosen CR3 and a process-private hardware translation.
                        row=dict(session=int(sid),cr3=int(layer.config['page_map_offset']))
                        try:row['probe']=layer.read(0x400000,16).hex()
                        except exceptions.InvalidAddressException:row['probe_error']='unavailable'
                        rows.append(row)
                except Exception as exc:error=type(exc).__name__
            cases.append(dict(layout=layout,scenario=scenario,isf=doc,size=len(data),kernel_base=0x10000,kernel_dtb=0x1000,pids=pids,holes=holes,rows=rows,error=error,
                              writes=[dict(offset=at,data=data[at:at+256].hex()) for at in range(0,len(data),256) if any(data[at:at+256])]))
    assert len(cases)==75
    for case in cases:
        if case['scenario']=='normal':
            delta=0 if case['layout']=='typed' else 50
            if case['layout']=='opaque-member':
                assert case['rows']==[] and case['error']=='AttributeError'
                continue
            assert [r['session'] for r in case['rows']]==[1+delta,2+delta,3+delta],(case['layout'],case['scenario'],case['rows'],case['error'])
            assert [r['cr3'] for r in case['rows']]==[0x4000,0x7000,0xd000]
            assert case['error'] is None
    return json.dumps(dict(commit=COMMIT,scope=__doc__,cases=cases),indent=2)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT));parser.add_argument('--check',action='store_true')
    args=parser.parse_args();result=generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text()!=result:raise SystemExit('GUI session oracle drift')
    else:OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original translated GUI session controls verified')


if __name__=='__main__':main()
