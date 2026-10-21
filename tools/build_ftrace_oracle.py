#!/usr/bin/env python3
"""Run unmodified ftrace list/filter/parser methods over real ISF-backed objects."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from baseline_matrix import ROOT, tree_digest

COMMIT="881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT=ROOT/"internal/engine/testdata/linux-ftrace-oracle.json"


def fixture(width,layout,scenario):
    base=lambda n:dict(kind="base",name=n)
    obj=lambda n:dict(kind="struct",name=n)
    ptr=lambda n:dict(kind="pointer",subtype=obj(n))
    field=lambda o,t:dict(offset=o,type=t)
    record=lambda size,fields:dict(kind="struct",size=size,fields=fields)
    types={"ftrace_ops":record(64,dict(func=field(0,dict(kind="pointer",subtype=dict(kind="function"))),next=field(8,ptr("ftrace_ops")),flags=field(16,base("ulong")))),"ftrace_ops_hash":record(16,dict(filter_hash=field(0,ptr("ftrace_hash")))),"ftrace_hash":record(24,dict(buckets=field(0,ptr("hlist_head")),size_bits=field(8,base("ulong")))),"hlist_head":record(width,dict(first=field(0,ptr("hlist_node")))),"hlist_node":record(width*2,dict(next=field(0,ptr("hlist_node")),pprev=field(width,dict(kind="pointer",subtype=ptr("hlist_node"))))),"ftrace_func_entry":record(32,dict(hlist=field(0,obj("hlist_node")),ip=field(16,base("ulong"))))}
    if layout=="legacy": types["ftrace_ops"]["fields"]["filter_hash"]=field(24,ptr("ftrace_hash"))
    else: types["ftrace_ops"]["fields"]["func_hash"]=field(24,ptr("ftrace_ops_hash") if layout=="pointer" else obj("ftrace_ops_hash"))
    data=bytearray(0x18000)
    def put(at,value,size=width):data[at:at+size]=value.to_bytes(size,"little")
    put(0x16f00,0x17200 if scenario=="empty-ops" else 0x17000)
    for i in range(2):
        at,local,hash_at,buckets,node=0x17000+i*0x100,0x17400+i*0x100,0x17600+i*0x100,0x17800+i*0x100,0x17a00+i*0x80
        put(at,0x8500 if i==0 else 0x8501)
        if scenario=="unknown-callback":put(at,0x30000)
        elif scenario=="callback-no-symbol":put(at,0x8502)
        put(at+8,0x17100 if i==0 else 0x17200)
        put(at+16,(1|8|1<<18|1<<25) if i==0 else 0)
        if scenario=="all-flags":put(at+16,(1<<19)-1)
        if layout=="legacy":put(at+24,hash_at)
        else:
            if layout=="pointer":put(at+24,local)
            else:local=at+24
            put(local,hash_at)
        put(hash_at,buckets);put(hash_at+8,1)
        put(buckets,node if scenario not in ("empty-filters","second-bucket-only") else 0)
        put(buckets+width,0x17b00)  # A valid second bucket, deliberately ignored upstream.
        put(0x17b00+16,0x8508)
        for j in range(2 if i==0 else 1):
            entry=node+j*0x40
            put(entry,entry+0x40 if i==0 and j==0 else 0)
            put(entry+width,buckets if j==0 else entry-0x40)
            put(entry+16,0x8508 if scenario!="hook-no-symbol" else 0x8509)
    syms={"ftrace_ops_list":dict(address=0x16f00,type=ptr("ftrace_ops")),"ftrace_list_end":dict(address=0x17200,type=obj("ftrace_ops")),"_text":dict(address=0x8400),"_etext":dict(address=0x8600),"a_callback":dict(address=0x8500),"z_callback":dict(address=0x8500),"a_hook":dict(address=0x8508),"z_hook":dict(address=0x8508)}
    isf=dict(metadata={"format":"6.2.0"},base_types={n:dict(kind="int",size=s,endian="little",signed=False) for n,s in (("pointer",width),("ulong",width))},user_types=types,enums={},symbols=syms)
    return isf,bytes(data)


def generate(source):
    if tree_digest(source)!=json.loads((ROOT/"baseline.lock.json").read_text())["python_tree_sha256"]:raise ValueError("requires pinned source")
    sys.path.insert(0,str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux.utilities.modules import ModuleInfo
    from volatility3.plugins.linux.tracing.ftrace import CheckFtrace
    cases=[]
    for width in (4,8):
        for layout in ("legacy","pointer","embedded"):
            for scenario in ("normal","empty-ops","empty-filters","unknown-callback","callback-no-symbol","hook-no-symbol","second-bucket-only","all-flags"):
                isf,data=fixture(width,layout,scenario);context=contexts.Context()
                class KernelBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):return (1<<(width*8))-1
                    def is_valid(self,offset,length=1):return offset!=0 and super().is_valid(offset,length)
                context.layers.add_layer(KernelBuffer(context,"test","memory",data))
                with tempfile.TemporaryDirectory(prefix="gomem-ftrace-oracle-") as directory:
                    path=Path(directory)/"kernel.json";path.write_text(json.dumps(isf))
                    context.symbol_space.append(IntermediateSymbolTable(context,"symbols","kernel",path.as_uri()))
                    context.module("kernel","memory",0)
                    known=[ModuleInfo(0x8400,"__kernel__",0x8400,0x8600)]
                    rows=[]
                    for ops in CheckFtrace.iterate_ftrace_ops_list(context,"kernel"):
                        for r in CheckFtrace.parse_ftrace_ops(context,"kernel",known,ops):
                            rows.append(dict(ops=int(r.ftrace_ops_offset),callback=r.callback_symbol or None,address=int(r.callback_address),hooked=r.hooked_symbols or None,module=r.module_name or None,module_address=None if r.module_address is None else int(r.module_address),flags=r.flags))
                writes=[];cursor=0x16f00
                while cursor<len(data):
                    if not data[cursor]:cursor+=1;continue
                    start=cursor
                    while cursor<len(data) and data[cursor]:cursor+=1
                    writes.append([start,data[start:cursor].hex()])
                cases.append(dict(width=width,layout=layout,scenario=scenario,isf=isf,writes=writes,expected=rows))
    return json.dumps(dict(commit=COMMIT,scope="Real ISF byte-backed ftrace ops/list/filter objects and unmodified parser/module kernel lookup; explicit known kernel range; module gatherers not mocked or exercised here",cases=cases),indent=2)+"\n"


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--source",type=Path,default=ROOT/(".cache/volatility3-"+COMMIT));parser.add_argument("--check",action="store_true");args=parser.parse_args();result=generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:raise ValueError("ftrace oracle differs")
    else:OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} byte-backed ftrace cases verified")


if __name__=="__main__":main()
