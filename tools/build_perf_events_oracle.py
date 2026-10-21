#!/usr/bin/env python3
"""Run pinned PerfEvents and real PsList/thread/list objects over kernel bytes."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-perf-events-oracle.json"


def fixture(width, layout, scenario):
    base = lambda name: dict(kind="base", name=name)
    obj = lambda name: dict(kind="struct", name=name)
    ptr = lambda name: dict(kind="pointer", subtype=obj(name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    array = lambda count: dict(kind="array", count=count, subtype=base("u8"))
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    types = {
        "list_head": record(width*2, dict(next=field(0,ptr("list_head")),prev=field(width,ptr("list_head")))),
        "task_struct": record(128, dict(tasks=field(0,obj("list_head")),pid=field(16,base("i32")),tgid=field(20,base("i32")),comm=field(24,array(16)),thread_group=field(40,obj("list_head")),perf_event_list=field(56,obj("list_head")),mm=field(72,ptr("mm_struct")),active_mm=field(80,ptr("mm_struct")),start_time=field(88,base("u64")),real_parent=field(120,ptr("task_struct")))),
        "mm_struct": record(16, {}),
        "perf_event": record(48, dict(owner_entry=field(0,obj("list_head")),pmu=field(24,ptr("pmu")),prog=field(32,ptr("bpf_prog")))),
        "pmu": record(16, dict(name=field(0,dict(kind="pointer",subtype=base("u8"))))),
        "bpf_prog": record(16, dict(aux=field(0,ptr("bpf_prog_aux")))),
        "bpf_prog_aux": record(544, dict(name=field(0,array(16)),ksym=field(32,obj("bpf_ksym")))),
        "bpf_ksym": record(512, dict(name=field(0,array(512)))),
    }
    data = bytearray(0x20000)
    def put(at, value, size=width):
        data[at:at+size] = value.to_bytes(size,"little")
    def circular(head, nodes):
        sequence = [head]+nodes
        for i, at in enumerate(sequence):
            put(at,sequence[(i+1)%len(sequence)])
            put(at+width,sequence[i-1])
    tasks = [0x11000,0x12000,0x12200,0x12400]
    for task,pid,tgid,name in zip(tasks,[0,20,21,30],[0,20,20,30],[b"init",b"leader",b"worker",b"other"]):
        put(task+16,pid,4)
        put(task+20,tgid,4)
        data[task+24:task+24+len(name)] = name
        put(task+88,123456789+pid,8)
        put(task+120,0x12000)
        circular(task+40,[])
        circular(task+56,[])
    circular(0x11000,[0x12000,0x12400])
    circular(0x12000+40,[0x12200+40])
    if layout == "signal":
        del types["task_struct"]["fields"]["thread_group"]
        types["task_struct"]["fields"]["signal"] = field(96,ptr("signal_struct"))
        types["task_struct"]["fields"]["thread_node"] = field(104,obj("list_head"))
        types["signal_struct"] = record(32,dict(thread_head=field(0,obj("list_head"))))
        for task in tasks:
            signal = 0x10000 if task in (0x12000,0x12200) else 0x10040 if task == 0x12400 else 0x10080
            put(task+96,signal)
        circular(0x10000,[0x12000+104,0x12200+104])
        circular(0x10040,[0x12400+104])
        circular(0x10080,[0x11000+104])
    circular(0x12000+56,[0x13000,0x13100])
    circular(0x12200+56,[0x13200])
    if scenario == "empty-events":
        circular(0x12000+56,[])
        circular(0x12200+56,[])
    if scenario == "absent-ksym":
        del types["bpf_prog_aux"]["fields"]["ksym"]
    if scenario == "short-full-array":
        types["bpf_ksym"]["fields"]["name"] = field(0,array(8))
    for i in range(3):
        event,pmu,prog,aux,name = 0x13000+i*0x100,0x14000+i*0x40,0x15000+i*0x40,0x16000+i*0x400,0x14800+i*128
        put(event+24,pmu)
        put(event+32,prog)
        put(pmu,name)
        put(prog,aux)
        event_text,short,full = b"kprobe",b"probe",b"bpf_prog_0123456789abcdef_probe"
        if scenario == "empty-names":
            event_text,short,full = b"",b"",b""
        elif scenario == "invalid":
            event_text,short,full = b"a\xfftail",b"b\xfftail",b"c\xfftail"
        elif scenario == "unicode":
            event_text,short,full = "事件".encode(),"探针".encode(),"程序_探针".encode()
        data[name:name+len(event_text)] = event_text
        data[aux:aux+len(short)] = short
        data[aux+32:aux+32+len(full)] = full
    if scenario == "null-program":
        put(0x13100+32,0)
    if scenario == "invalid-thread-mm":
        put(0x12200+72,0x17000)
    elif scenario == "invalid-leader-parent":
        put(0x12000+120,0)
    elif scenario == "negative-thread-pid":
        put(0x12200+16,0xffffffff,4)
    isf = dict(metadata={"format":"6.2.0"},base_types={name:dict(kind="int",size=size,endian="little",signed=False) for name,size in (("pointer",width),("u8",1),("u32",4),("u64",8),("i32",4))},user_types=types,enums={},symbols={"init_task":dict(address=0x11000,type=obj("task_struct"))})
    isf["base_types"]["i32"]["signed"] = True
    return isf,bytes(data)


def generate(source):
    if tree_digest(source) != json.loads((ROOT/"baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires pinned source")
    sys.path.insert(0,str(source))
    from volatility3.framework import contexts,renderers
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.tracing.perf_events import PerfEvents
    cases = []
    for width in (4,8):
        for layout in ("legacy","signal"):
            for scenario in ("normal","empty-events","empty-names","invalid","unicode","absent-ksym","short-full-array","null-program","invalid-thread-mm","invalid-leader-parent","negative-thread-pid"):
                isf,data = fixture(width,layout,scenario)
                context = contexts.Context()
                class KernelBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):
                        return (1 << (width*8))-1
                context.layers.add_layer(KernelBuffer(context,"test","memory",data))
                with tempfile.TemporaryDirectory(prefix="gomem-perf-oracle-") as directory:
                    path = Path(directory)/"kernel.json"
                    path.write_text(json.dumps(isf))
                    context.symbol_space.append(IntermediateSymbolTable(context,"symbols","kernel",path.as_uri(),class_types={"task_struct":extensions.task_struct,"list_head":extensions.list_head}))
                    context.module("kernel","memory",0)
                    runner = SimpleNamespace(context=context,config={"kernel":"kernel"},list_perf_events=PerfEvents.list_perf_events)
                    expected = [dict(pid=int(v[0]),process=v[1],event=None if isinstance(v[2],renderers.NotAvailableValue) else v[2],short=None if isinstance(v[3],renderers.NotAvailableValue) else v[3],full=None if isinstance(v[4],renderers.NotAvailableValue) else v[4],address=None if isinstance(v[5],renderers.NotAvailableValue) else int(v[5])) for _,v in PerfEvents._generator(runner)]
                writes = []
                cursor = 0x10000
                while cursor<len(data):
                    if not data[cursor]:
                        cursor += 1
                        continue
                    start = cursor
                    while cursor<len(data) and data[cursor]:
                        cursor += 1
                    writes.append([start,data[start:cursor].hex()])
                cases.append(dict(width=width,layout=layout,scenario=scenario,isf=isf,writes=writes,expected=expected,incomplete=scenario in ("invalid-thread-mm","invalid-leader-parent","negative-thread-pid")))
    return json.dumps(dict(commit=COMMIT,scope="Unmodified PerfEvents generator/listing and actual PsList/task/list extensions over ISF byte-backed objects; no method mocks",cases=cases),indent=2)+"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ROOT/(".cache/volatility3-"+COMMIT))
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:
            raise ValueError("perf-events oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} byte-backed perf-event cases verified")


if __name__ == "__main__":
    main()
