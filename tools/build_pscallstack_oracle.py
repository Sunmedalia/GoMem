#!/usr/bin/env python3
"""Run pinned task listing and stack scanning on actual paged task/resolver objects."""

import argparse
import base64
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_resolver_oracle import fixture as resolver_fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-pscallstack-oracle.json"


def fixture(width, threads, scenario):
    mode = {
        "module-priority": "module-first",
        "bpf-priority": "bpf-first",
        "ftrace-priority": "ftrace-after-bpf",
        "missing-ftrace-root": "missing-ftrace-root",
    }.get(scenario, "normal")
    isf, original, _ = resolver_fixture(width, "modern", 0, mode)
    data = bytearray(0x80000)
    data[: len(original)] = original
    banner = b"Linux version 6.1.0-gomem (deterministic synthetic callstack fixture) #1 SMP\0"
    data[0x8000 : 0x8000 + len(banner)] = banner
    isf["symbols"]["linux_banner"] = dict(
        address=0x8000, constant_data=base64.b64encode(banner).decode()
    )
    base = lambda n: dict(kind="base", name=n)
    struct = lambda n: dict(kind="struct", name=n)
    ptr = lambda n: dict(kind="pointer", subtype=struct(n))
    field = lambda off, typ: dict(offset=off, type=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)

    def put(at, v, size=width):
        data[at : at + size] = (v % (1 << (size * 8))).to_bytes(size, "little")

    def linked(nodes):
        for i, at in enumerate(nodes):
            put(at, nodes[(i + 1) % len(nodes)])
            put(at + width, nodes[(i - 1) % len(nodes)])

    types = isf["user_types"]
    fields = dict(
        tasks=field(0, struct("list_head")),
        pid=field(16, base("int")),
        tgid=field(20, base("int")),
        comm=field(24, dict(kind="array", count=16, subtype=base("char"))),
        flags=field(40, base("u32")),
        mm=field(48, ptr("mm_struct")),
        active_mm=field(56, ptr("mm_struct")),
        stack=field(80, ptr("void")),
        thread=field(88, struct("thread_struct")),
        files=field(96, ptr("void")),
        start_time=field(104, base("u64")),
    )
    if threads == "signal":
        fields.update(
            signal=field(64, ptr("signal_struct")),
            thread_node=field(112, struct("list_head")),
        )
        types["signal_struct"] = record(
            width * 2, dict(thread_head=field(0, struct("list_head")))
        )
    else:
        fields["thread_group"] = field(64, struct("list_head"))
    types["task_struct"] = record(128, fields)
    types["thread_struct"] = record(
        width, dict(sp=field(0, base("u64" if width == 8 else "u32")))
    )
    types["mm_struct"] = record(width, dict(pgd=field(0, ptr("void"))))
    isf["symbols"]["init_task"] = dict(address=0x2FC00, type=struct("task_struct"))
    linked([0x2FC00, 0x30000, 0x30800])
    put(0x31000, 0x70000)
    for i, at in enumerate([0x30000, 0x30400, 0x30800]):
        put(at + 16, 100 + i, 4)
        put(at + 20, 100 if i < 2 else 102, 4)
        data[at + 24 : at + 40] = [b"leader", b"thread", b"other"][i].ljust(16, b"\0")
        put(at + 40, 0x200000, 4)
        put(at + 104, i + 1, 8)
        stack = 0x40000 + i * 0x4000
        sp = stack + 0x4000 - 8 * width
        if scenario == "misaligned":
            sp -= 1
        if scenario == "invalid-sp" and i == 0:
            sp = stack + 0x4000
        if scenario == "user-space":
            put(at + 40, 0, 4)
            put(at + 48, 0x31000)
            put(at + 56, 0x31000)
        if scenario == "no-mm" and i == 0:
            put(at + 40, 0, 4)
        if scenario == "read-hole" and i == 0:
            sp = stack + 0x2FF0
        put(at + 80, stack)
        put(at + 88, sp)
        values = [0, 0x8400, 0x8500, 0x8800, 0x8600, 0xDEAD, 0, 0x8401]
        if scenario == "zero-stack":
            values = [0] * 8
        for j, v in enumerate(values):
            put(sp + j * width, v)
    if threads == "signal":
        for at in [0x30000, 0x30400]:
            put(at + 64, 0x32000)
        put(0x30800 + 64, 0x32100)
        linked([0x32000, 0x30000 + 112, 0x30400 + 112])
        linked([0x32100, 0x30800 + 112])
    else:
        linked([0x30000 + 64, 0x30400 + 64])
        linked([0x30800 + 64])
    # Real identity page tables, also used by task.add_process_layer.
    if width == 8:
        put(0x70000, 0x71003, 8)
        put(0x71000, 0x72003, 8)
        put(0x72000, 0x73003, 8)
    else:
        put(0x70000, 0x73003, 4)
    for page in range(0x80):
        put(0x73000 + page * width, page * 4096 | 3)
    if scenario == "read-hole":
        put(0x73000 + 0x43 * width, 0)
    if scenario == "user-space":
        # Distinct process stack pages: a kernel-layer fallback must fail comparison.
        put(0x31000, 0x74000)
        data[0x50000:0x5C000] = data[0x40000:0x4C000]
        data[0x40000:0x4C000] = bytes(0xC000)
        if width == 8:
            put(0x74000, 0x75003, 8)
            put(0x75000, 0x76003, 8)
            put(0x76000, 0x77003, 8)
        else:
            put(0x74000, 0x77003, 4)
        for page in range(0x80):
            physical = page + 0x10 if 0x40 <= page < 0x4C else page
            put(0x77000 + page * width, physical * 4096 | 3)
    return isf, bytes(data)


def generate(source):
    if (
        tree_digest(source)
        != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]
    ):
        raise ValueError("requires locked unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions, renderers
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.pscallstack import PsCallStack
    from volatility3.plugins.linux.pslist import PsList
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.framework.objects import utility
    from types import SimpleNamespace

    cases = []
    for width in (4, 8):
        for threads in ("legacy", "signal"):
            for scenario in (
                "normal",
                "module-priority",
                "bpf-priority",
                "ftrace-priority",
                "misaligned",
                "invalid-sp",
                "zero-stack",
                "user-space",
                "no-mm",
                "read-hole",
                "missing-ftrace-root",
            ):
                isf, data = fixture(width, threads, scenario)
                ctx = contexts.Context()
                ctx.layers.add_layer(BufferDataLayer(ctx, "physical", "physical", data))
                ctx.config["memory.memory_layer"] = "physical"
                ctx.config["memory.page_map_offset"] = 0x70000
                ctx.config["memory.kernel_virtual_offset"] = 0
                ctx.layers.add_layer(
                    (Intel32e if width == 8 else Intel)(ctx, "memory", "memory")
                )
                with tempfile.TemporaryDirectory(prefix="gomem-callstack-") as d:
                    path = Path(d) / "kernel.json"
                    path.write_text(json.dumps(isf))
                    types = {
                        n: getattr(extensions, n)
                        for n in (
                            "task_struct",
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
                            ctx, "symbols", "kernel", path.as_uri(), class_types=types
                        )
                    )
                    ctx.module("kernel", "memory", 0)
                    profiles = []
                    for unresolved, pids in (
                        (False, None),
                        (True, None),
                        (True, [100]),
                        (True, [101]),
                    ):
                        runner = SimpleNamespace(
                            context=ctx,
                            config={
                                "kernel": "kernel",
                                "unresolved": unresolved,
                                "pid": pids,
                            },
                            get_task_callstack=PsCallStack.get_task_callstack,
                        )
                        rows = []
                        error = None
                        try:
                            for _, v in PsCallStack._generator(runner):
                                rows.append(
                                    dict(
                                        TID=int(v[0]),
                                        Comm=v[1],
                                        Position=int(v[2]),
                                        Address=int(v[3]),
                                        Value=int(v[4]),
                                        Name=None
                                        if isinstance(v[5], renderers.NotAvailableValue)
                                        else v[5],
                                        Type=None
                                        if isinstance(v[6], renderers.NotAvailableValue)
                                        else v[6],
                                        Module=None
                                        if isinstance(v[7], renderers.NotAvailableValue)
                                        else v[7],
                                    )
                                )
                        except (
                            exceptions.VolatilityException,
                            AttributeError,
                            TypeError,
                            IndexError,
                        ) as cause:
                            error = dict(Class=type(cause).__name__, Message=str(cause))
                        tasks = []
                        kas = Kallsyms(ctx, "memory", "kernel")
                        for task in PsList.list_tasks(
                            ctx,
                            "kernel",
                            PsList.create_pid_filter(pids),
                            include_threads=True,
                        ):
                            task_rows = []
                            task_error = None
                            try:
                                for entry in PsCallStack.get_task_callstack(
                                    ctx, "kernel", task, kas, unresolved
                                ):
                                    task_rows.append(
                                        dict(
                                            TID=int(task.pid),
                                            Comm=utility.array_to_string(task.comm),
                                            Position=entry.position,
                                            Address=int(entry.address),
                                            Value=int(entry.value),
                                            Name=None
                                            if isinstance(
                                                entry.name, renderers.NotAvailableValue
                                            )
                                            else entry.name,
                                            Type=None
                                            if isinstance(
                                                entry.type, renderers.NotAvailableValue
                                            )
                                            else entry.type,
                                            Module=None
                                            if isinstance(
                                                entry.module,
                                                renderers.NotAvailableValue,
                                            )
                                            else entry.module,
                                        )
                                    )
                            except (
                                exceptions.VolatilityException,
                                AttributeError,
                                TypeError,
                                IndexError,
                            ) as cause:
                                task_error = dict(
                                    Class=type(cause).__name__, Message=str(cause)
                                )
                            tasks.append(
                                dict(
                                    tid=int(task.pid), rows=task_rows, error=task_error
                                )
                            )
                        profiles.append(
                            dict(
                                unresolved=unresolved,
                                pids=pids,
                                rows=rows,
                                error=error,
                                tasks=tasks,
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
                        threads=threads,
                        scenario=scenario,
                        isf=isf,
                        writes=writes,
                        profiles=profiles,
                    )
                )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope="Unmodified PsCallStack._generator/get_task_callstack, PsList.list_tasks and actual task extensions plus Kallsyms on Intel-paged byte-backed objects; no method mocks",
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
    a = p.parse_args()
    result = generate(a.source)
    if a.check:
        if OUTPUT.read_text() != result:
            raise ValueError("pscallstack oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual paged callstack cases verified")


if __name__ == "__main__":
    main()
