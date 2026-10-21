#!/usr/bin/env python3
"""Compare resident core symbol decoding to the locked, unmodified Kallsyms API."""

import argparse
import json
from pathlib import Path
import sys
import tempfile
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/kallsyms/testdata/core-oracle.json"


def fixture(width, layout, scenario):
    data = bytearray(0x18000)

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (size * 8))).to_bytes(size, "little")

    addresses = [0x8400, 0x8420, 0x8440]
    names = [b"Tentry", b"tworker", b"Ddata"]
    if scenario == "aliases":
        addresses[1] = addresses[0]
    if scenario == "special-types":
        names = [b"uunique", b"vweak", b"wweakfunc"]
    if scenario == "empty-name":
        names[1] = b"T"
    if scenario == "empty-token":
        names[1] = b""
    if scenario == "init-end":
        addresses[-1] = 0x8700
    if scenario == "absolute-percpu" and layout == "relative":
        addresses[:2] = [0x100, 0x200]
    count = 0 if scenario == "empty" else len(addresses)
    count_size = 4 if layout == "relative" else width
    put(0x16000, count, count_size)
    for i, addr in enumerate(addresses):
        if layout == "relative":
            value = addr if addr < 0x8400 else -(addr - 0x8400) - 1
            put(0x16100 + i * 4, value, 4)
        else:
            put(0x16100 + i * width, addr | (0xFFFF000000000000 if width == 8 else 0))
    put(0x16200, 0x8400)
    cursor, token_cursor = 0x17000, 0x17400
    for i, name in enumerate(names):
        put(0x16800 + i * 2, token_cursor - 0x17400, 2)
        data[token_cursor : token_cursor + len(name) + 1] = name + b"\0"
        token_cursor += len(name) + 1
        tokens = bytes([i])
        if (scenario == "big-last" and i == len(names) - 1) or (
            scenario == "big-first" and i == 0
        ):
            tokens = bytes([i]) * 128
        header = (
            bytes([len(tokens)])
            if len(tokens) < 128
            else bytes([0x80 | (len(tokens) & 0x7F), len(tokens) >> 7])
        )
        data[cursor : cursor + len(header) + len(tokens)] = header + tokens
        cursor += len(header) + len(tokens)
    syms = {
        "kallsyms_num_syms": {
            "address": 0x16000,
            "type": {"kind": "base", "name": "u32" if count_size == 4 else "u64"},
        },
        "kallsyms_names": {"address": 0x17000},
        "kallsyms_markers": {"address": 0x16A00},
        "kallsyms_token_table": {"address": 0x17400},
        "kallsyms_token_index": {"address": 0x16800},
        "_stext": {"address": 0x8400},
        "_etext": {"address": 0x8600},
        "_end": {"address": 0x8800},
        "_sinittext": {"address": 0x8700},
        "_einittext": {"address": 0x8800},
    }
    if layout == "relative":
        syms.update(
            kallsyms_offsets={"address": 0x16100},
            kallsyms_relative_base={"address": 0x16200},
        )
    else:
        syms["kallsyms_addresses"] = {"address": 0x16100}
    if scenario == "negative-size":
        syms["_end"]["address"] = 0x8430
    elif scenario == "zero-size":
        syms["_end"]["address"] = 0x8440
    elif scenario == "no-end":
        del syms["_end"]
    isf = {
        "metadata": {"format": "6.2.0"},
        "base_types": {
            n: {"kind": "int", "size": s, "signed": False, "endian": "little"}
            for n, s in (("pointer", width), ("u32", 4), ("u64", 8))
        },
        "user_types": {
            "kernel_symbol": {"kind": "struct", "size": width * 2, "fields": {}}
        },
        "enums": {},
        "symbols": syms,
    }
    return isf, bytes(data)


def generate(source):
    if (
        tree_digest(source)
        != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]
    ):
        raise ValueError("requires locked source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, renderers
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.plugins.linux.kallsyms import Kallsyms as Plugin

    cases = []
    for width in (4, 8):
        for layout in ("absolute", "relative"):
            for scenario in (
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
            ):
                isf, data = fixture(width, layout, scenario)
                context = contexts.Context()

                class KernelBuffer(BufferDataLayer):
                    # Match the layer API keyword used by _KallsymsIO; the
                    # upstream buffer alone names this argument address.
                    def read(self, offset, length, pad=False):
                        return super().read(offset, length, pad)

                    _entry_format = "<Q" if width == 8 else "<I"

                    @property
                    def bits_per_register(self):
                        return width * 8

                    @property
                    def address_mask(self):
                        return (1 << min(width * 8, 48)) - 1

                context.config["test.kernel_virtual_offset"] = 0
                context.layers.add_layer(KernelBuffer(context, "test", "memory", data))
                with tempfile.TemporaryDirectory(
                    prefix="gomem-kallsyms-core-"
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
                    config = kas._kas_config
                    expected = []
                    for symbol in kas.get_core_symbols():
                        size = Plugin._get_symbol_size(None, symbol)
                        expected.append(
                            dict(
                                Name=symbol.name,
                                Type=symbol.type or "",
                                Address=symbol.address,
                                Size=None
                                if isinstance(size, renderers.NotAvailableValue)
                                else size,
                                Exported=symbol.exported,
                            )
                        )
                    cfg = dict(
                        Count=config.num_syms_address,
                        Markers=config.markers_address,
                        MarkerSize=config.markers_type_size,
                        TextStart=config._stext,
                        HasText=config._stext is not None,
                        Names=config.names_address,
                        TokenTable=config.token_table_address,
                        TokenIndex=config.token_index_address,
                        Addresses=config.addresses_address or 0,
                        Offsets=config.offsets_address or 0,
                        RelativeBase=config.relative_base_address or 0,
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
                cursor = 0x16000
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
                scope="Actual unmodified KASConfig.new_from_isf and Kallsyms.get_core_symbols over real ISF and byte-backed memory; no parser method mocks; core only",
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
            raise ValueError("kallsyms core oracle differs")
    else:
        OUTPUT.parent.mkdir(exist_ok=True)
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual core-symbol cases verified")


if __name__ == "__main__":
    main()
