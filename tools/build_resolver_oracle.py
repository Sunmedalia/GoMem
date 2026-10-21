#!/usr/bin/env python3
"""Run unmodified full resident symbol lookup with overlapping sources and warm queries."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_module_lookup_oracle import fixture as module_fixture
from build_bpf_lookup_oracle import fixture as bpf_fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/kallsyms/testdata/resolver-oracle.json"


def fixture(width, layout, sequence, scenario):
    module_scenario = (
        "last-size" if width == 4 and scenario == "module-first" else "normal"
    )
    isf, raw, _ = module_fixture(width, "typetab", module_scenario)
    bpf, programs, _ = bpf_fixture(
        width,
        sequence == 1,
        sequence,
        layout,
        "empty-tree" if scenario == "ftrace-after-bpf" else "normal",
    )
    data = bytearray(0x50000)
    data[: len(raw)] = raw
    data[:0x5000] = programs[:0x5000]
    data[0x21000:] = programs[0x21000:]
    kernel_symbol = isf["user_types"]["kernel_symbol"]
    isf["user_types"].pop("bpf_ksym", None)
    isf["user_types"].update(bpf["user_types"])
    isf["user_types"]["kernel_symbol"] = kernel_symbol
    # The BPF fixture's core kernel_symbol is only a bootstrap placeholder.
    # Keep the actual module fixture's kernel_symbol for module metadata.
    isf["base_types"].update(bpf["base_types"])
    isf["symbols"]["bpf_tree"] = bpf["symbols"]["bpf_tree"]

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (size * 8))).to_bytes(size, "little")

    if scenario in (
        "module-first",
        "bpf-first",
        "ftrace-after-bpf",
        "no-bpf-root",
        "unsupported-bpf",
    ):
        isf["symbols"]["_etext"]["address"] = 0x8480
        isf["symbols"]["_sinittext"]["address"] = 0x8780
    if scenario == "module-first":
        put(0x19D18, 0x8500)
        for index in range(2):
            if layout == "modern":
                node = 0x2000 + index * 0x1000 + 0x200 + index * width * 2
                put(node - 64, 0x8500)
                put(node - 64 + width, 0x8540)
            else:
                put(0x21100 + index * 0x1000 + 8, 0x8507)
                put(0x8500 if layout == "pack" else 0x8000, 1, 4)
    target = (
        (0x8800 + sequence * 0x1000)
        if layout == "modern"
        else (0x30000 + sequence * 0x10000 + (64 if layout == "pack" else 0))
    )
    if scenario in ("bpf-first", "ftrace-after-bpf"):
        put(0x19D18, target)
    if scenario == "no-bpf-root":
        del isf["symbols"]["bpf_tree"]
    if scenario == "unsupported-bpf":
        del isf["symbols"]["bpf_tree"]
        isf["user_types"].pop("bpf_ksym", None)
        del isf["user_types"]["latch_tree_root"]
    if scenario == "missing-module-globals":
        del isf["symbols"]["module_addr_min"]
        del isf["symbols"]["module_addr_max"]
    if scenario == "missing-ftrace-root":
        del isf["symbols"]["ftrace_mod_maps"]
    queries = [
        0,
        0x83FF,
        0x8400,
        0x8401,
        0x8420,
        0x8440,
        0x847F,
        0x8480,
        0x84FF,
        0x8500,
        0x8501,
        0x851F,
        0x8520,
        0x8580,
        0x85FF,
        0x8600,
        0x862F,
        0x8630,
        0x8700,
        0x873F,
        0x8740,
        0x8780,
        0x87FF,
        0x8800,
        0x8840,
        0x8900,
        0x9000,
        0x9800,
        target - 1,
        target,
        target + 1,
        target + 48,
        target + 4096,
        target + 4097,
    ]
    if width == 8:
        queries += [target | 0xFFFF000000000000]
    return isf, bytes(data), queries + list(reversed(queries))


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
        for layout in ("modern", "legacy", "pack"):
            for sequence in (0, 1):
                for scenario in (
                    "normal",
                    "module-first",
                    "bpf-first",
                    "ftrace-after-bpf",
                    "no-bpf-root",
                    "unsupported-bpf",
                    "missing-module-globals",
                    "missing-ftrace-root",
                ):
                    isf, data, queries = fixture(width, layout, sequence, scenario)
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
                        def page_size(self):
                            return 4096

                        @property
                        def page_mask(self):
                            return ~4095

                        @property
                        def bits_per_register(self):
                            return width * 8

                    layer = Layer(ctx, "test", "memory", data)
                    ctx.layers.add_layer(layer)
                    with tempfile.TemporaryDirectory(prefix="gomem-resolver-") as d:
                        path = Path(d) / "kernel.json"
                        path.write_text(json.dumps(isf))
                        types = {
                            n: getattr(extensions, n)
                            for n in (
                                "module",
                                "kernel_symbol",
                                "list_head",
                                "latch_tree_root",
                                "bpf_prog",
                                "bpf_prog_aux",
                            )
                            if n in isf["user_types"]
                        }
                        ctx.symbol_space.append(
                            IntermediateSymbolTable(
                                ctx,
                                "symbols",
                                "kernel",
                                path.as_uri(),
                                class_types=types,
                            )
                        )
                        ctx.module("kernel", "memory", 0)
                        kas = Kallsyms(ctx, "memory", "kernel")
                        expected = []
                        for query in queries:
                            result, error, primitive = None, None, None
                            try:
                                value = kas.lookup_address(query)
                                if value is not None:
                                    size = Plugin._get_symbol_size(None, value)
                                    result = dict(
                                        Name=value.name,
                                        Type=value.type,
                                        Address=value.address,
                                        Size=None
                                        if isinstance(size, renderers.NotAvailableValue)
                                        else size,
                                        Exported=value.exported,
                                        Module=value.module_name,
                                        Subsystem=value.subsystem,
                                    )
                            except (
                                exceptions.VolatilityException,
                                AttributeError,
                                TypeError,
                                IndexError,
                            ) as cause:
                                error = dict(
                                    Class=type(cause).__name__, Message=str(cause)
                                )
                            if (
                                error
                                and error["Class"] == "AttributeError"
                                and "get_addr_region" in error["Message"]
                            ):
                                prog = kas._find_bpf_prog(query & layer.address_mask)
                                if prog is None:
                                    raise ValueError("legacy failure without program")
                                start, end = prog.get_address_region()
                                primitive = dict(
                                    Name=prog.get_name(),
                                    Type="t",
                                    Address=int(start) & layer.address_mask,
                                    Size=int(end - start) if end > start else None,
                                    Exported=False,
                                    Module="bpf",
                                    Subsystem="bpf",
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
                            sequence=sequence,
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
                scope="Unmodified Kallsyms.lookup_address with overlapping core/module/BPF/ftrace sources; ordered warm transcript; fixed legacy AttributeError retained alongside actual search/region/name primitives; no method mocks",
                cases=cases,
            ),
            indent=2,
        )
        + "\n"
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT)
    )
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("resolver oracle differs")
    else:
        OUTPUT.write_text(result)
    print(
        f"{len(json.loads(result)['cases'])} actual full symbol resolver cases verified"
    )


if __name__ == "__main__":
    main()
