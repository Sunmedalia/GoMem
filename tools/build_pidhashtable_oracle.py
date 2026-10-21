#!/usr/bin/env python3
"""Execute locked PIDHashTable over real task/PID/index objects and bytes."""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace as NS

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-pidhashtable-oracle.json"


def fixture(width, layout, scenario):
    base = lambda name: dict(kind="base", name=name)
    obj = lambda name: dict(kind="struct", name=name)
    ptr = lambda name: dict(kind="pointer", subtype=obj(name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    array = lambda count, typ: dict(kind="array", count=count, subtype=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    types = {
        "hlist_head": record(width, dict(first=field(0, ptr("hlist_node")))),
        "hlist_node": record(width * 2, dict(next=field(0, ptr("hlist_node")), pprev=field(width, ptr("hlist_node")))),
        "pid_link": record(width * 3, dict(node=field(0, obj("hlist_node")), pid=field(width * 2, ptr("pid")))),
        "upid": record(32, dict(nr=field(0, base("u32")), ns=field(8, ptr("pid_namespace")), pid_chain=field(16, obj("hlist_node")))),
        "pid": record(96, dict(tasks=field(0, array(3, obj("hlist_head"))), numbers=field(32, array(1, obj("upid"))))),
        "task_struct": record(128, dict(pid=field(0, base("u32")), tgid=field(4, base("u32")), flags=field(8, base("u32")), parent=field(16, ptr("task_struct")), real_parent=field(24, ptr("task_struct")), pids=field(32, array(3, obj("pid_link"))), comm=field(104, array(16, base("u8"))), cred=field(120, ptr("cred")))),
        "cred": record(16, {}), "pid_namespace": record(64, {}),
        "address_space": record(16, {}),
    }
    symbols = {}
    data = bytearray(0x20000)
    def word(at, n):
        struct.pack_into("<I" if width == 4 else "<Q", data, at, n)
    def u32(at, n):
        struct.pack_into("<I", data, at, n)
    pids = [0x12000, 0x12100, 0x12200]
    tasks = [0x14000, 0x14200, 0x14400]
    for i, (pid, task) in enumerate(zip(pids, tasks)):
        word(pid, task + 32)
        u32(task, [20, 21, 10][i])
        u32(task + 4, [20, 20, 10][i])
        u32(task + 8, 0x200000 if i == 2 else 0)
        word(task + 16, tasks[0])
        word(task + 24, tasks[0])
        name = [b"leader", b"worker", b"kernel"][i]
        data[task + 104:task + 104 + len(name)] = name
    if layout == "legacy":
        symbols = dict(pidhash_shift=dict(address=0x10008, type=base("u32")), pid_hash=dict(address=0x10010, type=ptr("hlist_head")))
        u32(0x10008, 2)
        word(0x10010, 0x11000)
        # Bucket zero: thread then kernel. Bucket two: leader.
        word(0x11000, pids[1] + 48)
        word(pids[1] + 48, pids[2] + 48)
        word(pids[1] + 48 + width, 0x11000)
        word(pids[2] + 48 + width, pids[1] + 48)
        word(0x11000 + 2 * width, pids[0] + 48)
        word(pids[0] + 48 + width, 0x11000 + 2 * width)
    else:
        root, node, head, tag = ("radix_tree_root", "radix_tree_node", "rnode", 1) if layout == "radix" else ("xarray", "xa_node", "xa_head", 2)
        types["idr"] = record(32, dict(idr_base=field(0, base("u32")), idr_rt=field(8, obj(root))))
        types["pid_namespace"] = record(64, dict(idr=field(16, obj("idr"))))
        types[root] = record(16, {head: field(0, ptr(node))})
        types[node] = record(64, dict(shift=field(0, base("u32")), slots=field(16, array(4, ptr("pid")))))
        types["address_space"]["fields"] = {"page_tree" if layout == "radix" else "i_pages":field(0, obj(root))}
        symbols["init_pid_ns"] = dict(address=0x10000, type=obj("pid_namespace"))
        word(0x10018, 0x11000 | tag)
        for i, pid in enumerate(pids):
            word(0x11010 + width * i, pid)
        if layout == "direct":
            word(0x10018, pids[1])
        elif layout == "empty":
            word(0x10018, 0)
        elif layout == "links":
            types["task_struct"]["fields"]["pid_links"] = field(32, array(3, obj("hlist_node")))
            del types["task_struct"]["fields"]["pids"]
    if scenario == "empty-name":
        data[tasks[0]+104:tasks[0]+120] = bytes(16)
    elif scenario == "invalid-name":
        data[tasks[0]+104:tasks[0]+120] = b"a\xffrest" + bytes(10)
    elif scenario == "null-parent":
        word(tasks[0]+16, 0)
    elif scenario == "zero-tid":
        u32(tasks[0], 0)
    elif scenario == "no-task":
        word(pids[0], 0)
    elif scenario == "duplicate-task":
        word(pids[1], tasks[0]+32)
    elif scenario == "real-parent-zero":
        word(tasks[0]+24, 0)
    isf = dict(metadata={"format":"6.2.0"}, base_types={"pointer":dict(kind="int", size=width, endian="little", signed=False), "u32":dict(kind="int", size=4, endian="little", signed=False), "u8":dict(kind="int", size=1, endian="little", signed=False)}, user_types=types, enums={"pid_type":dict(base="u32", size=4, constants={"PIDTYPE_PID":0,"PIDTYPE_PGID":1,"PIDTYPE_SID":2})}, symbols=symbols)
    return isf, bytes(data)


def generate(source):
    if tree_digest(source) != json.loads((ROOT/"baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires pinned source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.pidhashtable import PIDHashTable
    cases = []
    for width in (4, 8):
        for layout in ("legacy", "radix", "xarray", "links", "direct", "empty"):
            for scenario in ("normal", "empty-name", "invalid-name", "null-parent", "zero-tid", "no-task", "duplicate-task", "real-parent-zero"):
                isf, data = fixture(width, layout, scenario)
                context = contexts.Context()
                class KernelBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):
                        return (1 << (width * 8)) - 1
                context.layers.add_layer(KernelBuffer(context,"test","memory",data))
                with tempfile.TemporaryDirectory(prefix="gomem-pid-oracle-") as directory:
                    path = Path(directory)/"kernel.json"
                    path.write_text(json.dumps(isf))
                    table = IntermediateSymbolTable(context,"symbols","kernel",path.as_uri(),class_types={name: cls for name, cls in {"idr":extensions.IDR,"task_struct":extensions.task_struct}.items() if name in isf["user_types"]})
                    context.symbol_space.append(table)
                    context.module("kernel","memory",0)
                    runner = NS(context=context,_context=context,config={"kernel":"kernel"})
                    for name in ("_is_valid_task","_get_pidtype_pid","_get_pidhash_array","_walk_upid","_get_upids","_pid_hash_implementation","_task_for_radix_pid_node","_pid_namespace_idr","_determine_pid_func","get_tasks"):
                        setattr(runner,name,getattr(PIDHashTable,name).__get__(runner))
                    result = {}
                    for decorate in (False,True):
                        result["decorated" if decorate else "plain"] = [dict(offset=int(v[0]),pid=int(v[1]),tid=int(v[2]),ppid=int(v[3]),comm=v[4]) for _,v in PIDHashTable._generator(runner,decorate)]
                writes = []
                cursor = 0x10000
                while cursor < len(data):
                    if data[cursor] == 0:
                        cursor += 1
                        continue
                    start = cursor
                    while cursor < len(data) and data[cursor] != 0:
                        cursor += 1
                    writes.append([start,data[start:cursor].hex()])
                cases.append(dict(width=width,layout=layout,scenario=scenario,isf=isf,writes=writes,**result))
    return json.dumps(dict(commit=COMMIT,scope="Unmodified PIDHashTable methods and PsList task fields over real ISF PID/upid/IDR/task objects; byte-backed layers, no plugin or field-method mocks",cases=cases),indent=2)+"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ROOT/(".cache/volatility3-"+COMMIT))
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:
            raise ValueError("PID hash oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} byte-backed PID hash cases verified (plain and decorated)")


if __name__ == "__main__":
    main()
