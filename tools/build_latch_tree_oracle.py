#!/usr/bin/env python3
"""Exercise the locked latch-tree extension with byte-backed ISF objects."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/object/testdata/latch-tree-oracle.json"


def fixture(width, nested, sequence, node_offset, shape):
    base = lambda name: dict(kind="base", name=name)
    struct = lambda name: dict(kind="struct", name=name)
    pointer = lambda name: dict(kind="pointer", subtype=struct(name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    array = lambda count, typ: dict(kind="array", count=count, subtype=typ)
    types = {
        "seqcount": record(8, dict(sequence=field(4, base("u32")))),
        "seqcount_latch": record(16, dict(seqcount=field(8, struct("seqcount"))))
        if nested
        else record(8, dict(sequence=field(4, base("u32")))),
        "rb_root": record(width, dict(rb_node=field(0, pointer("rb_node")))),
        "rb_node": record(
            width * 3,
            dict(
                __rb_parent_color=field(0, base("word")),
                rb_right=field(width, pointer("rb_node")),
                rb_left=field(width * 2, pointer("rb_node")),
            ),
        ),
        "latch_tree_node": record(
            160,
            dict(
                node=field(node_offset, array(2, struct("rb_node"))),
                start=field(128, base("word")),
                end=field(128 + width, base("word")),
            ),
        ),
        "latch_tree_root": record(
            64,
            dict(
                seq=field(0, struct("seqcount_latch")),
                tree=field(32, array(2, struct("rb_root"))),
            ),
        ),
    }
    data = bytearray(0x5000)

    def put(at, value, size=width):
        data[at : at + size] = value.to_bytes(size, "little")

    put(0x1000 + (12 if nested else 4), sequence, 4)
    for index in range(2):
        containers = [0x2000 + index * 0x1000 + i * 0x200 for i in range(3)]
        rb = [node + node_offset + index * width * 3 for node in containers]
        if shape != "empty":
            put(0x1020 + index * width, rb[0])
        if shape != "single":
            put(rb[0] + width * 2, rb[1])
            put(rb[0] + width, rb[2])
        for i, node in enumerate(rb):
            # Use the extension's returned container coordinates. This deliberately
            # exposes its pointer-size subtraction for the second tree copy.
            selected = node - node_offset - index * width
            start = [0x120, 0x100, 0x140][i] + index * 0x1000
            put(selected + 128, start)
            put(selected + 128 + width, start + 0x10)
    isf = dict(
        metadata={"format": "6.2.0"},
        base_types={
            "pointer": dict(kind="int", size=width, signed=False, endian="little"),
            "word": dict(kind="int", size=width, signed=False, endian="little"),
            "u32": dict(kind="int", size=4, signed=False, endian="little"),
        },
        user_types=types,
        enums={},
        symbols={"root": dict(address=0x1000, type=struct("latch_tree_root"))},
    )
    return isf, bytes(data)


def generate(source):
    if (
        tree_digest(source)
        != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]
    ):
        raise ValueError("requires locked source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux.extensions import latch_tree_root

    cases = []
    for width in (4, 8):
        for nested in (False, True):
            for sequence in (0, 1, 2, 3):
                for offset in (0, 16):
                    for shape in ("normal", "empty", "single"):
                        isf, data = fixture(width, nested, sequence, offset, shape)
                        ctx = contexts.Context()
                        ctx.layers.add_layer(
                            BufferDataLayer(ctx, "test", "memory", data)
                        )
                        with tempfile.TemporaryDirectory(
                            prefix="gomem-latch-tree-"
                        ) as directory:
                            path = Path(directory) / "kernel.json"
                            path.write_text(json.dumps(isf))
                            ctx.symbol_space.append(
                                IntermediateSymbolTable(
                                    ctx,
                                    "symbols",
                                    "kernel",
                                    path.as_uri(),
                                    class_types={"latch_tree_root": latch_tree_root},
                                )
                            )
                            ctx.module("kernel", "memory", 0)
                            root = ctx.object(
                                "kernel!latch_tree_root",
                                layer_name="memory",
                                offset=0x1000,
                            )
                            expected = []
                            for inclusive in (False, True):
                                for key in (
                                    0,
                                    0xFF,
                                    0x100,
                                    0x10F,
                                    0x110,
                                    0x111,
                                    0x11F,
                                    0x120,
                                    0x130,
                                    0x131,
                                    0x140,
                                    0x150,
                                    0x151,
                                    0x1100,
                                    0x1110,
                                    0x1120,
                                    0x1130,
                                    0x1140,
                                    0x1150,
                                    0x1200,
                                ):
                                    visited = []

                                    def compare(query, node):
                                        visited.append(node.vol.offset)
                                        start, end = int(node.start), int(node.end)
                                        if query < start:
                                            return -1
                                        if query > end or (
                                            query == end and not inclusive
                                        ):
                                            return 1
                                        return 0

                                    found = root.find(key, compare)
                                    expected.append(
                                        dict(
                                            Key=key,
                                            Inclusive=inclusive,
                                            Node=found.vol.offset
                                            if found is not None
                                            else None,
                                            Visited=visited,
                                        )
                                    )
                        writes = []
                        cursor = 0x1000
                        while cursor < len(data):
                            if data[cursor] == 0:
                                cursor += 1
                                continue
                            start = cursor
                            while cursor < len(data) and data[cursor]:
                                cursor += 1
                            writes.append([start, data[start:cursor].hex()])
                        cases.append(
                            dict(
                                width=width,
                                nested=nested,
                                sequence=sequence,
                                node_offset=offset,
                                shape=shape,
                                isf=isf,
                                writes=writes,
                                expected=expected,
                            )
                        )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope="Unmodified latch_tree_root.find/_get_lt_node_from_rb_node on real ISF/byte objects; caller supplies inclusive/exclusive interval comparator; not source-specific lookup acceptance",
                cases=cases,
            ),
            indent=2,
        )
        + "\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT)
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("latch-tree oracle differs")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual latch-tree object cases verified")


if __name__ == "__main__":
    main()
