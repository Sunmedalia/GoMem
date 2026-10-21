#!/usr/bin/env python3
"""Run unmodified fixed ftrace address lookup over actual resident list objects."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_kallsyms_sources_oracle import fixture as sources_fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/kallsyms/testdata/ftrace-lookup-oracle.json"


def fixture(width, scenario):
    isf, original = sources_fixture(width, "typetab", "modern", "normal")
    data = bytearray(0x30000)
    data[: len(original)] = original
    types = isf["user_types"]

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (8 * size))).to_bytes(size, "little")

    def text(at, value, count=None):
        raw = value + b"\0"
        if count:
            raw = raw.ljust(count, b"\0")
        data[at : at + len(raw)] = raw

    def linked(head, nodes):
        entries = [head] + nodes
        for i, node in enumerate(entries):
            put(node, entries[(i + 1) % len(entries)])
            put(node + width, entries[(i - 1) % len(entries)])

    map_offset, func_offset, ops_offset = (
        (64, 48, 32) if scenario == "list-offsets" else (0, 0, 0)
    )
    for typ, offset, size in (
        ("ftrace_mod_map", map_offset, 96),
        ("ftrace_mod_func", func_offset, 80),
        ("ftrace_ops", ops_offset, 64),
    ):
        types[typ]["fields"]["list"]["offset"] = offset
        types[typ]["size"] = size
    put(0x1A118, 64, 4)
    put(0x1B010, 0x1C000)
    put(0x1B018, 0x8608)
    put(0x1B020, 16, 4)
    text(0x1C000, b"second_function")
    put(0x1B110, 0x1B400)
    text(0x1B410, b"second_module", 16)
    put(0x1B210, 0x1C200)
    put(0x1B218, 0x8640)
    put(0x1B220, 48, 4)
    text(0x1C200, b"module_two_function")
    put(0x1B310, 0x8700)
    put(0x1B318, 128, 4)
    maps = [0x19C00]
    funcs = [0x19D00]
    ops = [0x1A100]
    if scenario in ("overlap", "reverse-functions"):
        funcs += [0x1B000]
        put(0x1A110, 0x8600)
    if scenario == "reverse-functions":
        funcs.reverse()
    if scenario in ("two-maps", "reverse-maps"):
        maps += [0x1B100]
        if scenario == "reverse-maps":
            put(0x1B218, 0x8600)
            maps.reverse()
    if scenario in ("two-trampolines", "reverse-trampolines"):
        ops += [0x1B300]
        if scenario == "reverse-trampolines":
            ops.reverse()
    if scenario == "empty":
        maps, funcs, ops = [], [], []
    if scenario == "zero-size":
        put(0x19D20, 0, 4)
        put(0x1A118, 0, 4)
    if scenario == "empty-name":
        text(0x19F00, b"", 16)
    if scenario == "unicode-name":
        text(0x19F00, b"f\xff\xe2\x82")
        text(0x18010, b"m\xff", 16)
    if scenario == "high-trampoline-scalar":
        types["ftrace_ops"]["fields"]["trampoline"]["type"] = {
            "kind": "base", "name": "u64" if width == 8 else "u32"
        }
    if scenario in ("high-trampoline", "high-trampoline-scalar") and width == 8:
        put(0x19D18, 0xFFFF000000008600)
        put(0x1A110, 0xFFFF000000008700)
    if scenario == "zero-address-function":
        put(0x19D18, 0)
    if scenario == "zero-address-trampoline":
        put(0x1A110, 0)
    if scenario == "bad-function-name":
        put(0x19D10, 0x40000)
    if scenario == "bad-module-name":
        put(0x19C10, 0x40000)
    linked(0x17C20, [at + map_offset for at in maps])
    linked(0x19C20, [at + func_offset for at in funcs])
    linked(0x1B120, [0x1B200 + func_offset])
    linked(0x17C40, [at + ops_offset for at in ops])
    if scenario == "no-maps":
        del types["ftrace_mod_map"]
    if scenario == "no-functions":
        del types["ftrace_mod_func"]
    if scenario == "no-ops":
        del types["ftrace_ops"]
    if scenario == "no-trampoline-symbol":
        del isf["symbols"]["ftrace_ops_trampoline_list"]
    if scenario == "missing-maps-symbol":
        del isf["symbols"]["ftrace_mod_maps"]
    queries = [
        0,
        1,
        15,
        16,
        31,
        32,
        47,
        48,
        0x85FF,
        0x8600,
        0x8601,
        0x8608,
        0x8618,
        0x862F,
        0x8630,
        0x8640,
        0x866F,
        0x8670,
        0x86FF,
        0x8700,
        0x8701,
        0x873F,
        0x8740,
        0x877F,
        0x8780,
        0x8800,
    ]
    if width == 8:
        queries += [0xFFFF000000008600, 0xFFFF000000008700]
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
        for scenario in (
            "normal",
            "overlap",
            "reverse-functions",
            "two-maps",
            "reverse-maps",
            "two-trampolines",
            "reverse-trampolines",
            "empty",
            "zero-size",
            "empty-name",
            "unicode-name",
            "high-trampoline",
            "high-trampoline-scalar",
            "zero-address-function",
            "zero-address-trampoline",
            "bad-function-name",
            "bad-module-name",
            "no-maps",
            "no-functions",
            "no-ops",
            "no-trampoline-symbol",
            "missing-maps-symbol",
            "list-offsets",
        ):
            isf, data, queries = fixture(width, scenario)
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

            ctx.config["test.kernel_virtual_offset"] = 0
            layer = KernelBuffer(ctx, "test", "memory", data)
            ctx.layers.add_layer(layer)
            with tempfile.TemporaryDirectory(
                prefix="gomem-ftrace-lookup-"
            ) as directory:
                path = Path(directory) / "kernel.json"
                path.write_text(json.dumps(isf))
                ctx.symbol_space.append(
                    IntermediateSymbolTable(
                        ctx,
                        "symbols",
                        "kernel",
                        path.as_uri(),
                        class_types={"list_head": extensions.list_head},
                    )
                )
                ctx.module("kernel", "memory", 0)
                kas = Kallsyms(ctx, "memory", "kernel")
                expected = []
                for query in queries:
                    value, error = None, None
                    try:
                        symbol = kas.ftrace_lookup_address(query & layer.address_mask)
                        if symbol is not None:
                            size = Plugin._get_symbol_size(None, symbol)
                            value = dict(
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
                    ) as cause:
                        error = dict(Class=type(cause).__name__, Message=str(cause))
                    expected.append(dict(Query=query, Result=value, Error=error))
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
                scope="Unmodified ftrace_lookup_address and module/trampoline generators over real ISF/list/pointer objects; source ordering, overlap and acquisition gates; no source/method mocks",
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
            raise ValueError("ftrace lookup oracle differs")
    else:
        OUTPUT.write_text(result)
    print(
        f"{len(json.loads(result)['cases'])} actual ftrace address lookup cases verified"
    )


if __name__ == "__main__":
    main()
