#!/usr/bin/env python3
"""Exercise pinned tracepoint array/parser methods and their unchanged result expression."""

import argparse
import ast
import json
from pathlib import Path
import sys
import tempfile
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-tracepoints-oracle.json"


def fixture(width, layout, scenario):
    base = lambda n: dict(kind="base", name=n)
    obj = lambda n: dict(kind="struct", name=n)
    ptr = lambda n: dict(kind="pointer", subtype=obj(n))
    field = lambda o, t: dict(offset=o, type=t)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    array = lambda n, t: dict(kind="array", count=n, subtype=t)
    types = {
        "tracepoint": record(
            32,
            dict(
                name=field(0, dict(kind="pointer", subtype=base("char"))),
                funcs=field(16, ptr("tracepoint_func")),
            ),
        ),
        "tracepoint_func": record(
            24,
            dict(
                func=field(0, dict(kind="pointer", subtype=base("void"))),
                data=field(8, dict(kind="pointer", subtype=base("void"))),
                prio=field(16, base("int")),
            ),
        ),
    }
    if scenario == "no-prio":
        del types["tracepoint_func"]["fields"]["prio"]
    if scenario == "short-stride":
        types["tracepoint_func"]["size"] = 16
        del types["tracepoint_func"]["fields"]["prio"]
    if scenario == "no-data":
        del types["tracepoint_func"]["fields"]["data"]
    data = bytearray(0x18000)

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (size * 8))).to_bytes(size, "little")

    stride = types["tracepoint_func"]["size"]
    start = 0x16F00
    addresses = [0x17000, 0x17100]
    if scenario == "negative-prel":
        start = 0x17F00
    count = 0 if scenario == "empty-array" else 2
    for i, at in enumerate(addresses):
        slot = start + i * (4 if layout == "prel32" else width)
        put(
            slot,
            at - slot if layout == "prel32" else at,
            4 if layout == "prel32" else width,
        )
        name, probes = 0x17400 + i * 0x200, 0x17200 + i * 0x100
        put(at, name)
        put(at + 16, 0 if scenario == "no-probes" else probes)
        text = b"sched_switch" if i == 0 else b"process_exec"
        if scenario == "empty-name":
            text = b""
        elif scenario == "invalid-name":
            text = b"prefix\xffsuffix"
        elif scenario == "unicode":
            text = "事件_调度".encode()
        elif scenario == "split-utf8":
            text = b"a" * 31 + "事件".encode()
        elif scenario == "unterminated":
            text = b"x" * 512
        data[name : name + len(text)] = text
        for j in range(2 if i == 0 else 1):
            entry = probes + j * stride
            callback = 0x8500 if j == 0 else 0x8501
            if scenario == "unknown-owner":
                callback = 0x16000
            elif scenario == "no-symbol":
                callback = 0x8502
            put(entry, callback)
            put(entry + 8, 0x17800 + i * 64 + j * 8)
            if "prio" in types["tracepoint_func"]["fields"]:
                put(entry + 16, -7 if j == 1 else 0 if i == 1 else 9, 4)
    syms = {
        "__start___tracepoints_ptrs": dict(
            address=start,
            type=array(0, base("int") if layout == "prel32" else ptr("tracepoint")),
        ),
        "__stop___tracepoints_ptrs": dict(
            address=start + count * (4 if layout == "prel32" else width)
        ),
        "_text": dict(address=0x8400),
        "_etext": dict(address=0x8600),
        "a_entry": dict(address=0x8500),
        "z_entry": dict(address=0x8500),
    }
    if scenario == "trailing-bytes":
        syms["__stop___tracepoints_ptrs"]["address"] += 1
    isf = dict(
        metadata={"format": "6.2.0"},
        base_types={
            n: dict(kind="int", size=s, endian="little", signed=n == "int")
            for n, s in (("pointer", width), ("char", 1), ("int", 4), ("void", 0))
        },
        user_types=types,
        enums={},
        symbols=syms,
    )
    return isf, bytes(data)


def generate(source):
    if (
        tree_digest(source)
        != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]
    ):
        raise ValueError("requires pinned source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, renderers
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.renderers import format_hints
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux.utilities.modules import ModuleInfo
    from volatility3.plugins.linux.tracing.tracepoints import CheckTracepoints

    # Execute the exact rendering expression, including its priority-zero quirk,
    # without replacing any gatherer/parser methods or fabricating parser results.
    parsed = ast.parse(
        (
            source / "volatility3/framework/plugins/linux/tracing/tracepoints.py"
        ).read_text()
    )
    expression = next(
        n.value
        for n in ast.walk(parsed)
        if isinstance(n, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "formatted_results" for t in n.targets
        )
    )
    formatting = compile(
        ast.Expression(expression), "pinned-tracepoints-result-expression", "eval"
    )
    cases = []
    for width in (4, 8):
        for layout in ("absolute", "prel32"):
            for scenario in (
                "normal",
                "empty-array",
                "no-probes",
                "no-prio",
                "short-stride",
                "no-data",
                "empty-name",
                "invalid-name",
                "unicode",
                "split-utf8",
                "unterminated",
                "unknown-owner",
                "no-symbol",
                "negative-prel",
                "trailing-bytes",
            ):
                isf, data = fixture(width, layout, scenario)
                context = contexts.Context()

                class KernelBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):
                        return (1 << (width * 8)) - 1

                    def is_valid(self, offset, length=1):
                        return offset != 0 and super().is_valid(offset, length)

                context.layers.add_layer(KernelBuffer(context, "test", "memory", data))
                with tempfile.TemporaryDirectory(
                    prefix="gomem-tracepoints-oracle-"
                ) as directory:
                    path = Path(directory) / "kernel.json"
                    path.write_text(json.dumps(isf))
                    context.symbol_space.append(
                        IntermediateSymbolTable(
                            context, "symbols", "kernel", path.as_uri()
                        )
                    )
                    context.module("kernel", "memory", 0)
                    known = [ModuleInfo(0x8400, "__kernel__", 0x8400, 0x8600)]
                    rows = []
                    for tp in CheckTracepoints.iterate_tracepoints_array(
                        context, "kernel"
                    ):
                        for r in CheckTracepoints.parse_tracepoint(
                            context, "kernel", known, tp
                        ):
                            values = eval(
                                formatting,
                                {
                                    "format_hints": format_hints,
                                    "renderers": renderers,
                                    "tracepoint_parsed": r,
                                },
                            )
                            nullable = lambda v: (
                                None
                                if isinstance(v, renderers.NotAvailableValue)
                                else v
                            )
                            rows.append(
                                dict(
                                    name=values[0],
                                    tracepoint=int(values[1]),
                                    probe=nullable(values[2]),
                                    address=int(values[3]),
                                    priority=None
                                    if nullable(values[4]) is None
                                    else int(values[4]),
                                    module=nullable(values[5]),
                                    module_address=None
                                    if nullable(values[6]) is None
                                    else int(values[6]),
                                    raw_priority=None
                                    if r.probe_priority is None
                                    else int(r.probe_priority),
                                )
                            )
                writes = []
                cursor = 0x16F00
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
                        isf=isf,
                        writes=writes,
                        expected=rows,
                    )
                )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope="Unmodified tracepoint array/probe/parser methods, real ISF objects and kernel symbol lookup, exact AST result expression; explicit kernel range; no module gatherer mocks or gatherer acceptance",
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
            raise ValueError("tracepoints oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} byte-backed tracepoint cases verified")


if __name__ == "__main__":
    main()
