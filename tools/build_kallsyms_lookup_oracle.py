#!/usr/bin/env python3
"""Exercise locked core address lookup, marker positioning and cursor/cache order."""

import argparse
import json
from pathlib import Path
import sys
import tempfile
from baseline_matrix import ROOT, tree_digest
from build_kallsyms_core_oracle import fixture as core_fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/kallsyms/testdata/lookup-oracle.json"


def fixture(width, layout, scenario):
    if scenario not in ("marker-boundary", "corrupt-marker"):
        return core_fixture(width, layout, scenario)
    isf, raw = core_fixture(width, layout, "normal")
    data = bytearray(raw)

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (size * 8))).to_bytes(size, "little")

    count = 260 if scenario == "marker-boundary" else 3
    put(0x16000, count, 4 if layout == "relative" else width)
    key = "kallsyms_offsets" if layout == "relative" else "kallsyms_addresses"
    isf["symbols"][key]["address"] = 0x14000
    for i in range(count):
        address = 0x8400 + i * 4
        put(
            0x14000 + i * (4 if layout == "relative" else width),
            -(address - 0x8400) - 1 if layout == "relative" else address,
            4 if layout == "relative" else width,
        )
        data[0x17000 + i * 2 : 0x17002 + i * 2] = b"\x01\x00"
    put(
        0x16A00,
        1 if scenario == "corrupt-marker" else 0,
        4 if layout == "relative" else width,
    )
    put(
        0x16A00 + (4 if layout == "relative" else width),
        512,
        4 if layout == "relative" else width,
    )
    isf["symbols"]["_etext"]["address"] = 0x9000
    isf["symbols"]["_end"]["address"] = 0x9200
    return isf, bytes(data)


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
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.plugins.linux.kallsyms import Kallsyms as Plugin

    cases = []
    scenarios = (
        "normal",
        "aliases",
        "special-types",
        "empty-name",
        "empty-token",
        "init-end",
        "absolute-percpu",
        "empty",
        "big-last",
        "big-first",
        "negative-size",
        "zero-size",
        "no-end",
        "marker-boundary",
        "corrupt-marker",
    )
    for width in (4, 8):
        for layout in ("absolute", "relative"):
            for scenario in scenarios:
                for order in ("forward", "reverse", "after-stream"):
                    isf, data = fixture(width, layout, scenario)
                    context = contexts.Context()

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

                    context.config["test.kernel_virtual_offset"] = 0
                    context.layers.add_layer(
                        KernelBuffer(context, "test", "memory", data)
                    )
                    with tempfile.TemporaryDirectory(
                        prefix="gomem-kallsyms-lookup-"
                    ) as directory:
                        path = Path(directory) / "kernel.json"
                        path.write_text(json.dumps(isf))
                        context.symbol_space.append(
                            IntermediateSymbolTable(
                                context, "symbols", "kernel", path.as_uri()
                            )
                        )
                        context.module("kernel", "memory", 0)
                        kas = Kallsyms(context, "memory", "kernel")
                        if order == "after-stream":
                            list(kas.get_core_symbols())
                        queries = [
                            0,
                            0x83FF,
                            0x8400,
                            0x8401,
                            0x841F,
                            0x8420,
                            0x8421,
                            0x8440,
                            0x8500,
                            0x85FF,
                            0x8600,
                            0x8700,
                            0x87FF,
                            0x8800,
                        ]
                        if scenario == "marker-boundary":
                            # Over 128 distinct misses force the real lru_cache eviction.
                            queries = [0x8400 + i * 4 for i in range(260)] + [
                                0x8400,
                                0x8401,
                                0x8400 + 255 * 4 + 1,
                                0x8400 + 256 * 4,
                                0x9000,
                            ]
                        if order == "reverse":
                            queries.reverse()
                        if width == 8:
                            queries.append(0xFFFF000000008421)
                        expected = []
                        for address in queries:
                            error = None
                            result = None
                            try:
                                symbol = kas.core_lookup_address(address)
                                if symbol is not None:
                                    size = Plugin._get_symbol_size(None, symbol)
                                    result = dict(
                                        Name=symbol.name,
                                        Type=symbol.type or "",
                                        Address=symbol.address,
                                        Size=None
                                        if isinstance(size, renderers.NotAvailableValue)
                                        else size,
                                        Exported=symbol.exported,
                                    )
                            except (
                                exceptions.InvalidAddressException,
                                IndexError,
                                TypeError,
                            ) as cause:
                                error = type(cause).__name__
                            expected.append(
                                dict(Query=address, Result=result, Error=error)
                            )
                        config = kas._kas_config
                        cfg = dict(
                            Count=config.num_syms_address,
                            Names=config.names_address,
                            TokenTable=config.token_table_address,
                            TokenIndex=config.token_index_address,
                            Markers=config.markers_address or 0,
                            MarkerSize=config.markers_type_size,
                            Addresses=config.addresses_address or 0,
                            Offsets=config.offsets_address or 0,
                            RelativeBase=config.relative_base_address or 0,
                            TextStart=config._stext or 0,
                            HasText=config._stext is not None,
                            InitStart=config._sinittext or 0,
                            InitEnd=config._einittext or 0,
                            TextEnd=config._etext or 0,
                            End=config._end or 0,
                            HasInit=bool(config._sinittext and config._einittext),
                            HasEnd=config._end is not None,
                            Width=width,
                            CountSize=config.num_syms_type_size,
                            Endian="little",
                            AddressMask=(1 << min(width * 8, 48)) - 1,
                        )
                    writes = []
                    cursor = 0x14000
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
                            layout=layout,
                            scenario=scenario,
                            order=order,
                            config=cfg,
                            isf=isf,
                            writes=writes,
                            expected=expected,
                        )
                    )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope="Unmodified core_lookup_address, _get_symbol_pos, _get_symbol_offset and _expand_symbol over actual byte-backed ISF; ordered queries, real 128-entry LRU eviction and stream cursor interactions; core only",
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
            raise ValueError("lookup oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} ordered core lookup cases verified")


if __name__ == "__main__":
    main()
