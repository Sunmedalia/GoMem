#!/usr/bin/env python3
"""Run locked EBPF/IDR extensions over real ISF objects and memory bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace as NS

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-ebpf-oracle.json"


def fixture(width, layout, metadata):
    base = lambda name: dict(kind="base", name=name)
    embedded = lambda name: dict(kind="struct", name=name)
    ptr = lambda name="void": dict(kind="pointer", subtype=dict(kind="void") if name == "void" else embedded(name))
    field = lambda off, typ: dict(offset=off, type=typ)
    array = lambda count, typ: dict(kind="array", count=count, subtype=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    enum = dict(kind="enum", name="bpf_prog_type")
    root, node, head, tag = ("xarray", "xa_node", "xa_head", 2) if layout in ("xarray", "direct", "empty", "base", "multi") else ("radix_tree_root", "radix_tree_node", "rnode", 1)
    types = {
        "idr": record(32, dict(idr_base=field(0, base("u32")), idr_rt=field(8, embedded(root)))),
        "address_space": record(16, dict(i_pages=field(0, embedded(root)))),
        root: record(16, {head: field(0, ptr(node))}),
        node: record(64, dict(shift=field(0, base("u32")), slots=field(16, array(4, ptr())))),
        "bpf_prog": record(32, dict(type=field(0, enum), tag=field(4, array(8, base("u8"))), aux=field(16, ptr("bpf_prog_aux")))),
        "bpf_prog_aux": record(32, dict(prog_type=field(0, enum), name=field(8, array(16, base("u8"))))),
    }
    data = bytearray(0x20000)
    def word(at, n):
        struct.pack_into("<I" if width == 4 else "<Q", data, at, n)
    word(0x10008, 0x11000 | tag)
    word(0x11010, 0x14000)
    word(0x11010 + width * 2, 0x14100)
    ids = [0, 2]
    if layout == "radix":
        # IDStorage selects radix using address_space's declared root type.
        types["address_space"]["fields"] = dict(page_tree=field(0, embedded(root)))
    if layout in ("legacy", "legacy-deep"):
        types["idr"] = record(32, dict(cur=field(0, base("u32")), top=field(8, ptr("idr_layer"))))
        types["idr_layer"] = record(16 + 256 * width, dict(layer=field(0, base("u32")), ary=field(16, array(256, ptr("idr_layer")))))
        data[0x11000:0x11900] = bytes(0x900)
        word(0x10000, 64)
        word(0x10008, 0x11000)
        word(0x11010 + width, 0x14000)
        word(0x11010 + width * 32, 0x14100)
        ids = [1, 32]
        if layout == "legacy-deep":
            data[0x11000:0x11900] = bytes(0x900)
            word(0x11000, 1)
            word(0x11010, 0x12000)
            word(0x12010 + width, 0x14000)
            word(0x12010 + width * 32, 0x14100)
    elif layout == "base":
        struct.pack_into("<I", data, 0x10000, 1000)
        ids = [1000, 1002]
    elif layout == "multi":
        word(0x11000, 2)
        word(0x11010, 0x12002)
        word(0x11010 + width, 0x12102)
        word(0x11010 + width * 2, 0)
        word(0x12010, 0x14000)
        word(0x12110 + width * 2, 0x14100)
        ids = [0, 6]
    elif layout == "direct":
        word(0x10008, 0x14000)
        ids = [0]
    elif layout == "empty":
        word(0x10008, 0)
        ids = []
    for i, at in enumerate((0x14000, 0x14100)):
        struct.pack_into("<I", data, at, i + 1)
        data[at + 4:at + 12] = bytes(range(8)) if i == 0 else bytes(255 - n for n in range(8))
        word(at + 16, 0x16000 + i * 256)
        struct.pack_into("<I", data, 0x16000 + i * 256, i + 1)
        text = (b"trace_one\0", b"trace_two\0")[i]
        data[0x16008 + i * 256:0x16008 + i * 256 + len(text)] = text
    if metadata == "aux-type":
        del types["bpf_prog"]["fields"]["type"]
    elif metadata == "missing-fields":
        types["bpf_prog"]["fields"] = {}
    elif metadata == "empty-name":
        data[0x16008:0x16018] = bytes(16)
    elif metadata == "unicode-name":
        data[0x16008:0x16018] = b"a\xff\xe2\x82\0" + bytes(11)
    elif metadata == "null-aux":
        word(0x14010, 0)
    isf = dict(metadata={"format": "6.2.0"}, base_types={"pointer":dict(kind="int", size=width, endian="little", signed=False), "u32":dict(kind="int", size=4, endian="little", signed=False), "u8":dict(kind="int", size=1, endian="little", signed=False)}, user_types=types, enums={"bpf_prog_type":dict(base="u32", size=4, constants={"BPF_PROG_TYPE_SOCKET_FILTER":1,"BPF_PROG_TYPE_KPROBE":2})}, symbols={"prog_idr":dict(address=0x10000, type=embedded("idr"))})
    return isf, bytes(data), ids


def generate(source):
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires locked source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.ebpf import EBPF
    cases = []
    for width in (4, 8):
        for layout in ("radix", "xarray", "legacy", "direct", "empty", "base", "multi", "legacy-deep"):
            for metadata in ("modern", "aux-type", "missing-fields", "empty-name", "unicode-name", "null-aux"):
                isf, data, ids = fixture(width, layout, metadata)
                context = contexts.Context()
                class ProcessBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):
                        return (1 << (width * 8)) - 1
                context.layers.add_layer(ProcessBuffer(context, "test", "memory", data))
                with tempfile.TemporaryDirectory(prefix="gomem-ebpf-oracle-") as directory:
                    path = Path(directory) / "kernel.json"
                    path.write_text(json.dumps(isf))
                    table = IntermediateSymbolTable(context, "symbols", "kernel", path.as_uri(), class_types={"idr":extensions.IDR,"bpf_prog":extensions.bpf_prog,"bpf_prog_aux":extensions.bpf_prog_aux})
                    context.symbol_space.append(table)
                    context.module("kernel", "memory", 0)
                    runner = NS(context=context, config={"kernel":"kernel"})
                    runner.get_ebpf_programs = lambda *args: EBPF.get_ebpf_programs(runner, *args)
                    selected = []
                    for _, row in EBPF._generator(runner):
                        address, name, tag, typ = row
                        selected.append(dict(address=int(address),name=None if isinstance(name,interfaces.renderers.BaseAbsentValue) else name,tag=None if isinstance(tag,interfaces.renderers.BaseAbsentValue) else tag,type=None if isinstance(typ,interfaces.renderers.BaseAbsentValue) else typ))
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
                cases.append(dict(width=width,layout=layout,metadata=metadata,isf=isf,size=len(data),writes=writes,native_ids=ids,selected=selected))
    return json.dumps(dict(commit=COMMIT,scope="Unmodified EBPF generator and real IDR/radix/XArray/program/aux ISF objects over byte-backed layers; no plugin or field-method mocks",cases=cases),indent=2,ensure_ascii=True)+"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ROOT/(".cache/volatility3-"+COMMIT))
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:
            raise ValueError("eBPF oracle differs")
        print(f"{len(json.loads(result)['cases'])} byte-backed pinned eBPF/IDR cases verified")
    else:
        OUTPUT.write_text(result)


if __name__=="__main__":
    main()
