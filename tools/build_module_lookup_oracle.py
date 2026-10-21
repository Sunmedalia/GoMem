#!/usr/bin/env python3
"""Compare locked module interval lookup using actual module/ELF/list/tree objects."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_kallsyms_sources_oracle import fixture as source_fixture
from build_latch_tree_oracle import fixture as tree_fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/kallsyms/testdata/module-lookup-oracle.json"


def fixture(width, layout, scenario, sequence=0, nested=False):
    isf, original = source_fixture(width, layout, "modern", "normal")
    data = bytearray(0x30000)
    data[: len(original)] = original
    base = lambda n: dict(kind="base", name=n)
    struct = lambda n: dict(kind="struct", name=n)
    ptr = lambda n: dict(kind="pointer", subtype=struct(n))
    field = lambda off, typ: dict(offset=off, type=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (size * 8))).to_bytes(size, "little")

    isf["symbols"].update(
        module_addr_min=dict(address=0x8400), module_addr_max=dict(address=0x9000)
    )
    stride = 24 if width == 8 else 16
    valueoff = 8 if width == 8 else 4
    sizeoff = 16 if width == 8 else 8
    symbase = (
        0x18028 if layout == "legacy" else 0x18040 if layout == "embedded" else 0x18200
    )
    if scenario == "last-size":
        put(0x18400 + 2 * stride + sizeoff, 64)
    if scenario == "no-exports":
        put(0x18080, 0, 4)
    if scenario == "overlap":
        put(0x18400 + 2 * stride + valueoff, 0x8508)
        put(0x18400 + 2 * stride + sizeoff, 64)
    if scenario in ("overlap-valid", "reverse-overlap"):
        put(0x18400 + 2 * stride + valueoff, 0x8508)
        put(0x18400 + 2 * stride + sizeoff, 64)
        put(0x18400 + 3 * stride + valueoff, 0x8580)
        put(symbase + 16, 4, 4)
        if scenario == "reverse-overlap":
            first = bytes(data[0x18400 + stride : 0x18400 + 2 * stride])
            data[0x18400 + stride : 0x18400 + 2 * stride] = data[
                0x18400 + 2 * stride : 0x18400 + 3 * stride
            ]
            data[0x18400 + 2 * stride : 0x18400 + 3 * stride] = first
            data[0x18701:0x18703] = b"DT"
    if scenario in ("two-modules", "reverse-modules"):
        data[0x1C000:0x1C0A0] = data[0x18000:0x180A0]
        data[0x1C010:0x1C020] = b"second_module\0".ljust(16, b"\0")
        nodes = [0x18000, 0x1C000]
        if scenario == "reverse-modules":
            nodes.reverse()
        nodes = [0x17C00] + nodes
        for i, node in enumerate(nodes):
            put(node, nodes[(i + 1) % len(nodes)])
            put(node + width, nodes[(i - 1) % len(nodes)])
    if scenario == "empty-list":
        put(0x17C00, 0x17C00)
        put(0x17C00 + width, 0x17C00)
    if scenario == "missing-list":
        del isf["symbols"]["modules"]
    if scenario == "empty-name":
        data[0x18A00] = 0
    if scenario == "count-one":
        put(symbase + 16, 1, 4)
    if scenario == "no-strtab":
        put(symbase + 8, 0)
    if scenario == "high-values" and width == 8:
        for i in (1, 2):
            value = 0x8500 if i == 1 else 0x8580
            put(0x18400 + i * stride + valueoff, value | 0xFFFF000000000000)
    if scenario in ("tree", "tree-empty"):
        for index in range(2):
            mod = 0x1C000 + index * 0x1000
            data[mod : mod + 160] = data[0x18000:0x180A0]
            data[mod + 16 : mod + 32] = f"tree_copy_{index}\0".encode().ljust(16, b"\0")
        trees, raw = tree_fixture(
            width,
            nested,
            sequence,
            16,
            "empty" if scenario == "tree-empty" else "normal",
        )
        isf["user_types"].update(trees["user_types"])
        isf["base_types"].update(trees["base_types"])
        data[: len(raw)] = raw
        isf["user_types"]["mod_tree_root"] = record(
            96,
            dict(
                root=field(0, struct("latch_tree_root")),
                addr_min=field(64, base("word")),
                addr_max=field(72, base("word")),
            ),
        )
        isf["user_types"]["mod_tree_node"] = record(
            192,
            dict(
                mod=field(0, ptr("module")), node=field(16, struct("latch_tree_node"))
            ),
        )
        isf["user_types"]["module_memory"] = record(
            320,
            dict(
                base=field(0, ptr("void")),
                size=field(width, base("word")),
                mtn=field(128, struct("mod_tree_node")),
            ),
        )
        isf["symbols"]["mod_tree"] = dict(address=0x1000, type=struct("mod_tree_root"))
        put(0x1040, 0x8400)
        put(0x1048, 0x9000)
        for index in range(2):
            for i in range(3):
                node = 0x2000 + index * 0x1000 + i * 0x200 + index * 2 * width
                put(node - 16, 0x1C000 + index * 0x1000)
                put(node + 128, [0x8500, 0x8400, 0x8580][i])
                put(node + 128 + width, 64)
    queries = [
        0,
        0x83FF,
        0x8400,
        0x84FF,
        0x8500,
        0x8501,
        0x8507,
        0x8508,
        0x851F,
        0x8520,
        0x857F,
        0x8580,
        0x85BF,
        0x85C0,
        0x8FFF,
        0x9000,
        0x9001,
    ]
    if width == 8:
        queries += [0xFFFF000000008500]
    return isf, bytes(data), queries


def generate(source):
    if (
        tree_digest(source)
        != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]
    ):
        raise ValueError("requires locked source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions, renderers
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.plugins.linux.kallsyms import Kallsyms as Plugin

    cases = []
    for width in (4, 8):
        for layout in ("legacy", "pointer", "embedded", "typetab"):
            variants = [
                (s, 0, False)
                for s in (
                    "normal",
                    "last-size",
                    "no-exports",
                    "overlap",
                    "empty-name",
                    "count-one",
                    "no-strtab",
                    "high-values",
                    "overlap-valid",
                    "reverse-overlap",
                    "two-modules",
                    "reverse-modules",
                    "empty-list",
                    "missing-list",
                )
            ]
            variants += [
                (shape, seq, nested)
                for shape in ("tree", "tree-empty")
                for seq in range(4)
                for nested in (False, True)
            ]
            for scenario, sequence, nested in variants:
                isf, data, queries = fixture(width, layout, scenario, sequence, nested)
                ctx = contexts.Context()
                ctx.config["test.kernel_virtual_offset"] = 0

                class Layer(BufferDataLayer):
                    _entry_format = "<Q" if width == 8 else "<I"

                    def read(self, offset, length, pad=False):
                        return super().read(offset, length, pad)

                    @property
                    def address_mask(self):
                        return (1 << min(width * 8, 48)) - 1

                    @property
                    def bits_per_register(self):
                        return width * 8

                layer = Layer(ctx, "test", "memory", data)
                ctx.layers.add_layer(layer)
                with tempfile.TemporaryDirectory(prefix="gomem-module-lookup-") as d:
                    path = Path(d) / "kernel.json"
                    path.write_text(json.dumps(isf))
                    ctx.symbol_space.append(
                        IntermediateSymbolTable(
                            ctx,
                            "symbols",
                            "kernel",
                            path.as_uri(),
                            class_types={
                                n: getattr(extensions, n)
                                for n in (
                                    "module",
                                    "kernel_symbol",
                                    "list_head",
                                    "latch_tree_root",
                                )
                                if n in isf["user_types"]
                            },
                        )
                    )
                    ctx.module("kernel", "memory", 0)
                    expected = []
                    for explicit in (False, True):
                        kas = Kallsyms(ctx, "memory", "kernel")
                        module = (
                            ctx.object(
                                "kernel!module", layer_name="memory", offset=0x18000
                            )
                            if explicit
                            else None
                        )
                        for query in queries:
                            result, error = None, None
                            tree_object = None
                            if not explicit and scenario in ("tree", "tree-empty"):
                                selected = kas._get_module_by_address(
                                    query & layer.address_mask
                                )
                                if selected is not None:
                                    tree_object = selected.vol.offset
                            try:
                                symbol = kas.module_lookup_address(
                                    query & layer.address_mask, module
                                )
                                if symbol is not None:
                                    size = Plugin._get_symbol_size(None, symbol)
                                    result = dict(
                                        Name=symbol.name,
                                        Type=symbol.type,
                                        Address=symbol.address,
                                        Size=None
                                        if isinstance(size, renderers.NotAvailableValue)
                                        else size,
                                        Exported=symbol.exported,
                                        Module=symbol.module_name,
                                        Subsystem=symbol.subsystem,
                                    )
                            except (
                                exceptions.InvalidAddressException,
                                exceptions.SymbolError,
                                IndexError,
                                TypeError,
                            ) as cause:
                                error = dict(
                                    Class=type(cause).__name__, Message=str(cause)
                                )
                            expected.append(
                                dict(
                                    Query=query,
                                    Explicit=explicit,
                                    Result=result,
                                    Error=error,
                                    TreeObject=tree_object,
                                )
                            )
                writes = []
                at = 0
                while at < len(data):
                    if not data[at]:
                        at += 1
                        continue
                    start = at
                    while at < len(data) and data[at]:
                        at += 1
                    writes.append([start, data[start:at].hex()])
                cases.append(
                    dict(
                        width=width,
                        layout=layout,
                        scenario=scenario,
                        sequence=sequence,
                        nested=nested,
                        isf=isf,
                        writes=writes,
                        expected=expected,
                    )
                )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope="Unmodified module_lookup_address and actual module/ELF/list/latch tree objects; symbol-address global gate and pinned boundary expression retained; no method mocks",
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
            raise ValueError("module lookup oracle differs")
    else:
        OUTPUT.write_text(result)
    print(
        f"{len(json.loads(result)['cases'])} actual module address lookup cases verified"
    )


if __name__ == "__main__":
    main()
