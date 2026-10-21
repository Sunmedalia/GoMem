#!/usr/bin/env python3
"""Run locked BPF address lookup and real legacy extension primitives."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_kallsyms_core_oracle import fixture as core_fixture
from build_latch_tree_oracle import fixture as tree_fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/kallsyms/testdata/bpf-lookup-oracle.json"


def fixture(width, nested, sequence, layout, scenario):
    isf, raw = core_fixture(width, "absolute", "normal")
    trees, tree_data = tree_fixture(
        width, nested, sequence, 16, "empty" if scenario == "empty-tree" else "normal"
    )
    data = bytearray(0x50000)
    data[: len(raw)] = raw
    data[: len(tree_data)] = tree_data
    isf["user_types"].update(trees["user_types"])
    isf["base_types"].update(trees["base_types"])
    isf["base_types"]["unsigned int"] = dict(
        kind="int", size=4, signed=False, endian="little"
    )
    struct = lambda n: dict(kind="struct", name=n)
    ptr = lambda n: dict(
        kind="pointer", subtype=dict(kind="void") if n == "void" else struct(n)
    )
    base = lambda n: dict(kind="base", name=n)
    field = lambda off, typ: dict(offset=off, type=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    fields = dict(name=field(32, dict(kind="array", count=16, subtype=base("u8"))))
    isf["base_types"]["u8"] = dict(kind="int", size=1, signed=False, endian="little")
    typ, member = (
        ("bpf_ksym", "tnode") if layout == "modern" else ("bpf_prog_aux", "ksym_tnode")
    )
    fields[member] = field(64, struct("latch_tree_node"))
    if scenario == "header-big-endian":
        isf["base_types"]["unsigned int"]["endian"] = "big"
    if layout == "modern":
        fields.update(start=field(0, ptr("void")), end=field(width, ptr("void")))
    else:
        fields["prog"] = field(0, ptr("bpf_prog"))
        isf["user_types"]["bpf_prog"] = record(
            32, dict(aux=field(0, ptr("bpf_prog_aux")), bpf_func=field(8, ptr("void")))
        )
        if layout == "pack":
            fields["use_bpf_prog_pack"] = field(24, base("u32"))
        if scenario not in ("header-absent", "header-big-endian"):
            isf["user_types"]["bpf_binary_header"] = record(
                4, dict(pages=field(0, base("u32")))
            )
    if scenario == "missing-name":
        del fields["name"]
    isf["user_types"][typ] = record(256, fields)
    if scenario != "missing-root":
        isf["symbols"]["bpf_tree"] = dict(
            address=0x1000, type=struct("latch_tree_root")
        )

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (size * 8))).to_bytes(size, "little")

    queries = [0, 0xFFFFFFFF]
    for index in range(2):
        for i in range(3):
            node = 0x2000 + index * 0x1000 + i * 0x200 + index * width * 2
            obj = node - 64
            if layout == "modern":
                start = [0x8800, 0x8700, 0x8900][i] + index * 0x1000
                end = start if scenario == "zero-size" else start + 0x40
                high = 0xFFFF000000000000 if width == 8 else 0
                put(obj, start | high)
                put(obj + width, end | high)
            else:
                prog = 0x21000 + index * 0x1000 + i * 0x100
                aux = (
                    0x28000 + index * 0x1000 + i * 0x100
                    if scenario == "aux-redirect"
                    else obj
                )
                put(obj, prog)
                put(prog, aux)
                start = [0x30000, 0x2E000, 0x32000][i] + index * 0x10000
                start += 64 if layout == "pack" else 0
                put(prog + 8, start + 7)
                put(start, 0 if scenario == "zero-size" else 1, 4)
                if scenario == "header-big-endian":
                    data[start : start + 4] = (1).to_bytes(4, "big")
                end = start if scenario == "zero-size" else start + 4096
                if layout == "pack":
                    put(aux + 24, 1, 4)
                name = (
                    f"redirect_{index}_{i}"
                    if scenario == "aux-redirect"
                    else f"bpf_{index}_{i}"
                ).encode()
                data[aux + 32 : aux + 48] = (name + b"\0").ljust(16, b"\0")
            name_at = obj + 32 if layout == "modern" else aux + 32
            if layout == "modern":
                data[name_at : name_at + 16] = (
                    f"ksym_{index}_{i}".encode() + b"\0"
                ).ljust(16, b"\0")
            if scenario == "empty-name":
                data[name_at : name_at + 16] = bytes(16)
            elif scenario == "unicode-name":
                data[name_at : name_at + 16] = b"a\xff\xe2\x82\0" + bytes(11)
            queries += [start - 1, start, start + 1, end, end + 1]
    if width == 8:
        queries += [queries[3] | 0xFFFF000000000000]
    return isf, bytes(data), queries


def generate(source):
    if (
        tree_digest(source)
        != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]
    ):
        raise ValueError("requires locked source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, renderers, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.plugins.linux.kallsyms import Kallsyms as Plugin

    cases = []
    for width in (4, 8):
        for nested in (False, True):
            for sequence in (0, 1, 2, 3):
                for layout in ("modern", "legacy", "pack"):
                    for scenario in (
                        "normal",
                        "empty-tree",
                        "missing-root",
                        "zero-size",
                        "empty-name",
                        "unicode-name",
                        "missing-name",
                        "aux-redirect",
                        "header-absent",
                        "header-big-endian",
                    ):
                        isf, data, queries = fixture(
                            width, nested, sequence, layout, scenario
                        )
                        ctx = contexts.Context()

                        class KernelBuffer(BufferDataLayer):
                            _entry_format = "<Q" if width == 8 else "<I"

                            def read(self, offset, length, pad=False):
                                return super().read(offset, length, pad)

                            @property
                            def bits_per_register(self):
                                return width * 8

                            @property
                            def address_mask(self):
                                return (1 << min(width * 8, 48)) - 1

                            @property
                            def page_size(self):
                                return 4096

                            @property
                            def page_mask(self):
                                return ~4095

                        ctx.config["test.kernel_virtual_offset"] = 0
                        layer = KernelBuffer(ctx, "test", "memory", data)
                        ctx.layers.add_layer(layer)
                        with tempfile.TemporaryDirectory(
                            prefix="gomem-bpf-lookup-"
                        ) as directory:
                            path = Path(directory) / "kernel.json"
                            path.write_text(json.dumps(isf))
                            ctx.symbol_space.append(
                                IntermediateSymbolTable(
                                    ctx,
                                    "symbols",
                                    "kernel",
                                    path.as_uri(),
                                    class_types={
                                        name: cls
                                        for name, cls in {
                                            "latch_tree_root": extensions.latch_tree_root,
                                            "bpf_prog": extensions.bpf_prog,
                                            "bpf_prog_aux": extensions.bpf_prog_aux,
                                        }.items()
                                        if name in isf["user_types"]
                                    },
                                )
                            )
                            ctx.module("kernel", "memory", 0)
                            kas = Kallsyms(ctx, "memory", "kernel")
                            expected = []
                            for query in queries:
                                result, error, primitive = None, None, None
                                normalized = query & layer.address_mask
                                try:
                                    value = kas.bpf_lookup_address(normalized)
                                    if value is not None:
                                        size = Plugin._get_symbol_size(None, value)
                                        result = dict(
                                            Name=value.name,
                                            Type=value.type,
                                            Address=value.address,
                                            Size=None
                                            if isinstance(
                                                size, renderers.NotAvailableValue
                                            )
                                            else size,
                                            Exported=value.exported,
                                        )
                                except (
                                    AttributeError,
                                    exceptions.InvalidAddressException,
                                ) as cause:
                                    error = dict(
                                        Class=type(cause).__name__, Message=str(cause)
                                    )
                                if layout != "modern":
                                    prog = kas._find_bpf_prog(normalized)
                                    if prog is not None:
                                        start, end = prog.get_address_region()
                                        name = prog.get_name()
                                        primitive = dict(
                                            Object=int(prog),
                                            Aux=int(prog.aux),
                                            RegionStart=int(start),
                                            RegionEnd=int(end),
                                            Name=name,
                                        )
                                expected.append(
                                    dict(
                                        Query=query,
                                        Result=result,
                                        Error=error,
                                        Primitive=primitive,
                                    )
                                )
                        writes = []
                        cursor = 0
                        while cursor < len(data):
                            if not data[cursor]:
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
                                layout=layout,
                                scenario=scenario,
                                isf=isf,
                                writes=writes,
                                expected=expected,
                            )
                        )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope="Unmodified bpf_lookup_address and actual latch/BPF ISF extensions; legacy full-method AttributeError retained, separately records unmodified search/region/name primitive outputs; no method mocks",
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
            raise ValueError("BPF lookup oracle differs")
    else:
        OUTPUT.write_text(result)
    print(
        f"{len(json.loads(result)['cases'])} actual BPF address lookup cases verified"
    )


if __name__ == "__main__":
    main()
