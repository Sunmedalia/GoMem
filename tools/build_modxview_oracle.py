#!/usr/bin/env python3
"""Run pinned module aggregation, flattening, validity and taint helpers."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch
from baseline_matrix import ROOT, tree_digest

COMMIT='881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT=ROOT/'internal/plugins/testdata/linux-modxview-oracle.json'


def generate(source):
    if tree_digest(source)!=json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned source')
    sys.path.insert(0,str(source))
    from volatility3.framework.symbols.linux.utilities.modules import Modules, ModuleInfo
    from volatility3.framework.symbols.linux.utilities.tainting import Tainting
    from volatility3.framework.symbols.linux.extensions import module
    from volatility3.plugins.linux.malware.modxview import Modxview
    taints=[]
    class Context: pass
    fake_context=Context()
    fake_context.modules={'kernel':SimpleNamespace(has_symbol=lambda _:False)}
    for value in [0,1,2,3,1<<10,1<<12,1<<13,1<<15,1<<16,1<<17,1<<18,1<<63,(1<<64)-1,1|1<<10|1<<12]:
        plain=Tainting.get_taints_as_plain_string.__func__(Tainting,fake_context,'kernel',value,True)
        parsed=','.join(Tainting.get_taints_parsed(fake_context,'kernel',value,True))
        taints.append(dict(value=str(value),plain=plain,parsed=parsed))
    dynamic=[]
    flags=[SimpleNamespace(module=True,c_true=ord('P'),c_false=ord('G')),SimpleNamespace(module=False,c_true=ord('F'),c_false=32),SimpleNamespace(module=True,c_true=ord('?'),c_false=ord('-')),SimpleNamespace(module=True,c_true=0x110000,c_false=32),SimpleNamespace(module=True,c_true=ord('O'),c_false=32)]
    for value in range(32):
        with patch.object(Tainting,'_get_kernel_taint_flags_list',return_value=flags):
            plain=Tainting.get_taints_as_plain_string(fake_context,'kernel',value,True)
            parsed=','.join(Tainting.get_taints_parsed(fake_context,'kernel',value,True))
        dynamic.append(dict(value=str(value),plain=plain,parsed=parsed))
    graphs=[{'Lsmod':[(1,'one',10,20)],'SysFs':[(1,'one',10,20),(2,'two',30,40)],'Scanner':[(1,'one',10,20),(2,'two',30,40),(3,'three',50,60)]},
            {'Lsmod':[(1,'one',10,20),(2,'two',10,30)],'SysFs':[(1,'one',10,20),(1,'one',10,20)],'Scanner':[]},
            {'Lsmod':[],'SysFs':[(2,'two',30,40)],'Scanner':[(3,'three',50,60),(2,'two',30,40)]}]
    aggregates=[]
    for graph in graphs:
        runs={key:[ModuleInfo(*values) for values in entries] for key,entries in graph.items()}
        kernel=SimpleNamespace(object=lambda typ,offset,absolute:SimpleNamespace(get_name=lambda:next(v[1] for values in graph.values() for v in values if v[0]==offset),taints=0))
        plugin=SimpleNamespace(context=SimpleNamespace(modules={'kernel':kernel}),config={'kernel':'kernel'})
        with patch.object(Modules,'run_modules_scanners',return_value=runs),patch.object(Tainting,'get_taints_parsed',return_value=[]):
            rows=[dict(name=v[0],offset=int(v[1]),lsmod=v[2],sysfs=v[3],scan=v[4]) for _,v in Modxview._generator(plugin)]
        flattened=[dict(offset=m.offset,base=m.start) for m in Modules.flatten_run_modules_results(runs)]
        aggregates.append(dict(sources=graph,rows=rows,flattened=flattened))
    validity=[]
    class Pointer(int):
        def is_readable(self): return self.readable
    for core,text,init,selfptr,readable in [(4096,2048,0,1,True),(1,1,4095,1,True),(4095,1,0,1,True),(4096,0,0,1,True),(0,1,4096,1,True),(20000001,1,0,1,True),(4096,20000001,0,1,True),(4096,1,0,0,True),(4096,1,0,2,True),(4096,1,0,1,False),(1,1,(1<<64)-1,1,True),(4096,1,(1<<64)-1,1,True)]:
        p=Pointer(selfptr);p.readable=readable
        obj=SimpleNamespace(_context=SimpleNamespace(layers={'test':SimpleNamespace(is_valid=lambda *_:True)}),vol=SimpleNamespace(offset=1,size=256,layer_name='test'),get_core_size=lambda:core,get_core_text_size=lambda:text,get_init_size=lambda:init,mkobj=SimpleNamespace(mod=p))
        validity.append(dict(core=core,text=text,init=init,self=selfptr,readable=readable,valid=module.is_valid(obj)))
    return json.dumps(dict(commit=COMMIT,taints=taints,dynamic=dynamic,aggregates=aggregates,validity=validity),indent=2)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT));p.add_argument('--check',action='store_true');args=p.parse_args();result=generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text()!=result:raise ValueError('module oracle differs')
    else:OUTPUT.write_text(result)
    print('14 legacy/32 dynamic taint cases, 3 aggregation graphs and 12 module validity cases verified')


if __name__=='__main__':main()
