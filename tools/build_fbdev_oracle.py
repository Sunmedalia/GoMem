#!/usr/bin/env python3
"""Run pinned Fbdev metadata and export methods over real byte-backed ISF objects."""
import argparse
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-fbdev-oracle.json"


def fixture(width, scenario):
    base = lambda name: dict(kind="base", name=name)
    obj = lambda name: dict(kind="struct", name=name)
    ptr = lambda name: dict(kind="pointer", subtype=obj(name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    arr = lambda count, subtype: dict(kind="array", count=count, subtype=subtype)
    types = {
        "fb_bitfield": record(12, {n: field(i*4, base("u32")) for i,n in enumerate(("offset","length","msb_right"))}),
        "fb_fix_screeninfo": record(32, dict(id=field(0,arr(16,base("u8"))),line_length=field(16,base("u32")))),
        "fb_var_screeninfo": record(64, {**{n:field(i*4,base("u32")) for i,n in enumerate(("xres_virtual","yres_virtual","bits_per_pixel","grayscale"))}, **{n:field(16+i*12,obj("fb_bitfield")) for i,n in enumerate(("red","green","blue","transp"))}}),
        "fb_info": record(128, dict(fix=field(0,obj("fb_fix_screeninfo")),var=field(32,obj("fb_var_screeninfo")),screen_base=field(96,dict(kind="pointer",subtype=base("u8"))),state=field(104,base("u32")),dev=field(112,ptr("device")))),
        "device": record(16,dict(kobj=field(0,obj("kobject")))),
        "kobject": record(16,dict(name=field(0,dict(kind="pointer",subtype=base("u8"))))),
    }
    data = bytearray(0x18000)
    def put(at,value,size=4): data[at:at+size] = value.to_bytes(size,"little")
    put(0x10000,0 if scenario=="no-devices" else 2)
    for i in range(2):
        fb,dev,name,screen = 0x11000+i*0x100,0x12000+i*0x40,0x13000+i*0x100,0x14000+i*0x100
        put(0x10010+i*width,fb,width)
        ident = b"testfb" if i==0 else b"other"
        if scenario=="empty-id": ident=b""
        if scenario=="invalid-name": ident=b"prefix\xfftail"
        if scenario=="unicode": ident="显示器".encode()
        data[fb:fb+len(ident)] = ident
        x,y,bpp,line = 2,2,32,8
        channels = [(16,8,0),(8,8,0),(0,8,0),(24,8,0)]
        if scenario=="rgb565": bpp,line,channels=16,4,[(11,5,0),(5,6,0),(0,5,0),(0,0,0)]
        elif scenario=="rgb24": bpp,line,channels=24,6,[(16,8,0),(8,8,0),(0,8,0),(0,0,0)]
        elif scenario=="padding": line=12
        elif scenario=="short-buffer": line=2
        elif scenario=="reverse": channels=[(16,8,1),(8,8,1),(0,8,1),(24,8,1)]
        elif scenario=="wide-channel": channels=[(0,16,0),(8,16,1),(0,0,0),(0,0,0)]
        put(fb+16,line)
        for j,v in enumerate((x,y,bpp,0x34325258 if scenario=="fourcc" else 1 if scenario=="grayscale" else 0)): put(fb+32+j*4,v)
        for c,values in enumerate(channels):
            for j,v in enumerate(values): put(fb+48+c*12+j*4,v)
        put(fb+96,screen,width)
        put(fb+104,i)
        put(fb+112,dev,width)
        put(dev,name,width)
        devname = "显卡".encode() if scenario=="unicode" else b"fbdev"
        data[name:name+len(devname)]=devname
        data[screen:screen+24]=bytes.fromhex("1020408011223344aabbccdd1234567898badcfe7654321012345678")
    isf=dict(metadata={"format":"6.2.0"},base_types={n:dict(kind="int",size=s,endian="little",signed=False) for n,s in (("pointer",width),("u8",1),("u32",4))},user_types=types,enums={},symbols={"num_registered_fb":dict(address=0x10000,type=base("u32")),"registered_fb":dict(address=0x10010,type=arr(2,ptr("fb_info")))})
    return isf,bytes(data)


def generate(source):
    if tree_digest(source)!=json.loads((ROOT/"baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires pinned source")
    sys.path.insert(0,str(source))
    from PIL import Image
    from volatility3.framework import contexts, renderers
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.plugins.linux.graphics.fbdev import Fbdev
    cases=[]
    for width in (4,8):
        for scenario in ("normal","no-devices","empty-id","invalid-name","unicode","rgb565","rgb24","padding","short-buffer","reverse","wide-channel","fourcc","grayscale"):
            isf,data=fixture(width,scenario)
            context=contexts.Context()
            class KernelBuffer(BufferDataLayer):
                @property
                def address_mask(self): return (1 << (width*8))-1
            context.layers.add_layer(KernelBuffer(context,"test","memory",data))
            files={}
            class Output(io.BytesIO):
                def __init__(self,name): super().__init__(); self.preferred_filename=name
                def close(self): files[self.preferred_filename]=self.getvalue();super().close()
            with tempfile.TemporaryDirectory(prefix="gomem-fbdev-oracle-") as directory:
                path=Path(directory)/"kernel.json";path.write_text(json.dumps(isf))
                context.symbol_space.append(IntermediateSymbolTable(context,"symbols","kernel",path.as_uri()))
                context.module("kernel","memory",0)
                runner=SimpleNamespace(context=context,config={"kernel":"kernel","dump":True},open=Output,parse_fb_info=Fbdev.parse_fb_info,dump_fb=Fbdev.dump_fb)
                expected=[]
                for _,v in Fbdev._generator(runner):
                    filename=v[7];payload=files[filename]
                    row=dict(address=int(v[0]),device=v[1],id=None if isinstance(v[2],renderers.NotAvailableValue) else v[2],size=int(v[3]),resolution=v[4],bpp=int(v[5]),state=v[6],filename=filename)
                    if filename.endswith(".png"):
                        img=Image.open(io.BytesIO(payload));row["rgba"]=img.tobytes().hex()
                    else: row["raw"]=payload.hex()
                    expected.append(row)
            writes=[]
            cursor=0x10000
            while cursor<len(data):
                if not data[cursor]:
                    cursor+=1
                    continue
                start=cursor
                while cursor<len(data) and data[cursor]: cursor+=1
                writes.append([start,data[start:cursor].hex()])
            cases.append(dict(width=width,scenario=scenario,isf=isf,writes=writes,expected=expected))
    return json.dumps(dict(commit=COMMIT,scope="Unmodified Fbdev generator, metadata parsing and raw/PNG export over ISF byte-backed objects; PNG decoded pixels compared independently of compression",cases=cases),indent=2)+"\n"


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ROOT/(".cache/volatility3-"+COMMIT))
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args();result=generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result: raise ValueError("fbdev oracle differs")
    else: OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} byte-backed framebuffer cases verified")


if __name__=="__main__": main()
