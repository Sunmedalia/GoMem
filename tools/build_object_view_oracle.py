#!/usr/bin/env python3
"""Exercise unmodified upstream objects with distinct data/native byte layers."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/object/testdata/view-oracle.json"


def fixture(width, endian, scenario):
    base = lambda n: dict(kind="base", name=n)
    obj = lambda n: dict(kind="struct", name=n)
    ptr = dict(kind="pointer", subtype=obj("leaf"))
    field = lambda off, t: dict(offset=off, type=t)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    isf = dict(
        metadata={"format": "6.2.0"},
        base_types={
            "pointer": dict(kind="int", size=width, endian=endian, signed=False),
            "u32": dict(kind="int", size=4, endian=endian, signed=False),
            "i32": dict(kind="int", size=4, endian=endian, signed=True),
            "char": dict(kind="char", size=1, endian=endian, signed=False),
        },
        user_types={
            "root": record(64, dict(
                value=field(0, base("u32")),
                peer=field(8, ptr),
                embedded=field(16, obj("leaf")),
                signed=field(32, base("i32")),
                state=field(36, dict(kind="enum", name="status")),
                name=field(48, dict(kind="array", count=8, subtype=base("char"))),
            )),
            "leaf": record(16, dict(value=field(0, base("u32")), peer=field(8, ptr))),
            "file": record(32, dict(f_path=field(8, obj("path")))),
            "path": record(width, dict(dentry=field(0, dict(kind="pointer", subtype=obj("dentry"))))),
            "dentry": record(width, dict(d_inode=field(0, dict(kind="pointer", subtype=obj("inode"))))),
            "inode": record(16, dict(i_ino=field(0, base("u32")))),
            "socket": record(width, dict(sk=field(0, ptr))),
            "socket_alloc": record(48, dict(socket=field(0, obj("socket")), vfs_inode=field(32, obj("inode")))),
        },
        enums={"status": dict(base="u32", size=4, constants={"READY": 2})},
        symbols={},
    )
    physical, native = bytearray(512), bytearray(512)

    def put(data, at, value, size=width):
        data[at:at+size] = value.to_bytes(size, endian)

    put(physical, 0x40, 1, 4)
    put(physical, 0x48, 0 if scenario == "null" else 0x400 if scenario == "unmapped-target" else 0x80)
    put(physical, 0x50, 7, 4)
    put(physical, 0x58, 0x80)
    put(physical, 0x60, 0xFFFFFFFE, 4)
    put(physical, 0x64, 2, 4)
    physical[0x70:0x78] = b"root\0\0\0\0"
    for at, value in ((0x40, 99), (0x80, 2), (0xC0, 3)):
        put(native, at, value, 4)
    put(native, 0x88, 0xC0)
    # Valid but wrong data exists at the same address in the physical layer.
    put(physical, 0x80, 88, 4)
    put(physical, 0x88, 0x40)
    put(physical, 0x108, 0x100)
    put(native, 0x100, 0x160)
    put(native, 0x140, 0x80)
    put(native, 0x160, 1234, 4)
    # A wrong data-layer dereference would follow this unrelated physical inode.
    put(physical, 0x100, 0x1F0)
    if scenario == "truncated-pointer":
        physical = physical[:0x48 + width - 1]
    return isf, bytes(physical), bytes(native)


def generate(source):
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires locked unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.objects import utility
    from volatility3.framework.symbols.linux import LinuxUtilities

    cases = []
    for width in (4, 8):
        for endian in ("little", "big"):
            for scenario in ("normal", "null", "unmapped-target", "truncated-pointer"):
                isf, physical, native = fixture(width, endian, scenario)
                class FullAddressBuffer(BufferDataLayer):
                    # Keep architecture width rather than deriving a mask from
                    # this tiny synthetic buffer (which would wrap bad pointers).
                    @property
                    def address_mask(self):
                        return (1 << (width * 8)) - 1

                ctx = contexts.Context()
                for name, data in (("physical", physical), ("kernel", native)):
                    ctx.layers.add_layer(FullAddressBuffer(ctx, name, name, data))
                with tempfile.TemporaryDirectory(prefix="gomem-object-view-") as d:
                    path = Path(d) / "types.json"
                    path.write_text(json.dumps(isf))
                    ctx.symbol_space.append(IntermediateSymbolTable(ctx, "symbols", "kernel", path.as_uri()))
                    root = ctx.object("kernel!root", layer_name="physical", offset=0x40, native_layer_name="kernel")
                    module = ctx.module("kernel", "kernel", 0)
                    operations = {}

                    def capture(name, fn):
                        try:
                            operations[name] = dict(value=fn())
                        except exceptions.InvalidAddressException:
                            operations[name] = dict(error="read")

                    def describe(obj):
                        return dict(address=obj.vol.offset, layer=obj.vol.layer_name, native=obj.vol.native_layer_name, value=int(obj.value))

                    def file_socket():
                        file = ctx.object("kernel!file", layer_name="physical", offset=0x100, native_layer_name="kernel")
                        inode = file.f_path.dentry.dereference().d_inode
                        allocation = LinuxUtilities.container_of(inode, "socket_alloc", "vfs_inode", module)
                        return describe(allocation.socket.sk.dereference())

                    capture("file-socket", file_socket)
                    capture("root", lambda: describe(root))
                    capture("cast", lambda: describe(root.cast("leaf")))
                    capture("embedded", lambda: describe(root.embedded))
                    # Native pointer semantics, not just distinct numerical offsets.
                    capture("embedded-peer", lambda: describe(root.embedded.peer.dereference()))
                    capture("signed", lambda: int(root.signed))
                    capture("enum", lambda: int(root.state))
                    capture("string", lambda: utility.array_to_string(root.name))
                    try:
                        peer = int(root.peer)
                        if peer == 0:
                            # GoMem intentionally rejects null pointer targets even if
                            # upstream can construct an object at mapped address zero.
                            operations["peer"] = dict(error="null")
                            operations["peer-peer"] = dict(error="null")
                        else:
                            capture("peer", lambda: describe(root.peer.dereference()))
                            capture("peer-peer", lambda: describe(root.peer.dereference().peer.dereference()))
                    except exceptions.InvalidAddressException:
                        operations["peer"] = dict(error="read")
                        operations["peer-peer"] = dict(error="read")
                cases.append(dict(width=width, endian=endian, scenario=scenario, isf=isf, physical=physical.hex(), native=native.hex(), operations=operations))
    return json.dumps(dict(commit=COMMIT, scope="Unmodified aggregate, cast, embedded member and pointer objects over separate byte-backed physical/native layers. Null targets explicitly rejected by GoMem.", cases=cases), indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("object view oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual object data/native layer cases verified")


if __name__ == "__main__":
    main()
