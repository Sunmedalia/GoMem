#!/usr/bin/env python3
"""Run all locked kallsyms sources against actual byte-backed Linux objects."""

import argparse
import json
from pathlib import Path
import sys
import tempfile
from baseline_matrix import ROOT, tree_digest
from build_kallsyms_core_oracle import fixture as core_fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-kallsyms-oracle.json"


def fixture(width, module_layout, bpf_layout, scenario):
    isf, original = core_fixture(width, "absolute", "normal")
    data = bytearray(original) + bytearray(0x20000 - len(original))
    base = lambda n: dict(kind="base", name=n)
    struct = lambda n: dict(kind="struct", name=n)
    ptr = lambda n: dict(kind="pointer", subtype=struct(n))
    field = lambda off, typ: dict(offset=off, type=typ)
    record = lambda size, fields: dict(kind="struct", size=size, fields=fields)
    array = lambda n: dict(kind="array", count=n, subtype=base("char"))
    types = isf["user_types"]
    isf["base_types"].update(
        char=dict(kind="char", size=1, signed=True, endian="little"),
        int=dict(kind="int", size=4, signed=True, endian="little"),
    )
    types["list_head"] = record(
        width * 2,
        dict(next=field(0, ptr("list_head")), prev=field(width, ptr("list_head"))),
    )

    def put(at, value, size=width):
        data[at : at + size] = (value % (1 << (size * 8))).to_bytes(size, "little")

    def linked(head, nodes):
        for i, node in enumerate([head] + nodes):
            allnodes = [head] + nodes
            put(node, allnodes[(i + 1) % len(allnodes)])
            put(node + width, allnodes[(i - 1) % len(allnodes)])

    def text(at, value):
        data[at : at + len(value) + 1] = value + b"\0"

    fields = dict(
        list=field(0, struct("list_head")),
        name=field(16, array(16)),
        num_syms=field(128, base("u32")),
        syms=field(136, ptr("kernel_symbol")),
    )
    symfields = dict(
        symtab=field(0, ptr("void")),
        strtab=field(8, ptr("char")),
        num_symtab=field(16, base("u32")),
    )
    if module_layout == "legacy":
        fields.update(
            {name: field(f["offset"] + 40, f["type"]) for name, f in symfields.items()}
        )
        symbase = 0x18028
    else:
        if module_layout == "typetab":
            symfields["typetab"] = field(24, ptr("char"))
        types["mod_kallsyms"] = record(32, symfields)
        fields["kallsyms"] = field(
            64,
            struct("mod_kallsyms")
            if module_layout == "embedded"
            else ptr("mod_kallsyms"),
        )
        if module_layout == "embedded":
            symbase = 0x18040
        else:
            put(0x18040, 0x18200)
            symbase = 0x18200
    types["module"] = record(160, fields)
    # Legacy and PREL32 exported symbols both use the real extension helpers.
    relative = scenario == "prel32-exports"
    if relative:
        types["kernel_symbol"] = record(
            12,
            dict(value_offset=field(0, base("int")), name_offset=field(4, base("int"))),
        )
    else:
        types["kernel_symbol"] = record(
            width * 2, dict(value=field(0, ptr("void")), name=field(width, ptr("char")))
        )
    types["void"] = record(1, {})
    types["char"] = record(1, {})
    text(0x18010, b"active")
    linked(0x17C00, [] if scenario == "empty" else [0x18000])
    put(symbase, 0x18400)
    put(symbase + 8, 0x18800)
    put(symbase + 16, 3, 4)
    if module_layout == "typetab":
        put(symbase + 24, 0x18700)
    for i, (name, address, kind, size) in enumerate(
        [(b"", 0, b"?", 0), (b"entry", 0x8500, b"T", 32), (b"data", 0x8580, b"D", 0)]
    ):
        at = 0x18400 + i * (24 if width == 8 else 16)
        put(at, i * 512, 4)
        text(0x18800 + i * 512, name)
        if width == 8:
            put(at + 8, address)
            put(at + 16, size)
            data[at + 4] = kind[0]
        else:
            put(at + 4, address)
            put(at + 8, size)
            data[at + 12] = kind[0]
        data[0x18700 + i] = kind[0]
    put(0x18080, 0 if scenario == "no-exports" else 1, 4)
    put(0x18088, 0x19400)
    text(0x19800, b"entry")
    if relative:
        put(0x19400, 0x8500 - 0x19400, 4)
        put(0x19404, 0x19800 - 0x19400, 4)
    else:
        put(0x19400, 0x8500)
        put(0x19400 + width, 0x19800)
    types["ftrace_mod_map"] = record(
        64,
        dict(
            list=field(0, struct("list_head")),
            mod=field(16, ptr("module")),
            funcs=field(32, struct("list_head")),
        ),
    )
    types["ftrace_mod_func"] = record(
        48,
        dict(
            list=field(0, struct("list_head")),
            name=field(16, ptr("char")),
            ip=field(24, ptr("void")),
            size=field(32, base("u32")),
        ),
    )
    types["ftrace_ops"] = record(
        48,
        dict(
            list=field(0, struct("list_head")),
            trampoline=field(16, ptr("void")),
            trampoline_size=field(24, base("u32")),
        ),
    )
    linked(0x17C20, [] if scenario == "empty" else [0x19C00])
    put(0x19C10, 0x18000)
    linked(0x19C20, [0x19D00])
    put(0x19D10, 0x19F00)
    text(0x19F00, b"ftrace_entry")
    put(0x19D18, 0x8600)
    put(0x19D20, 48, 4)
    linked(0x17C40, [] if scenario == "empty" else [0x1A100])
    put(0x1A110, 0x8700)
    put(0x1A118, 0, 4)
    if bpf_layout == "modern":
        types["bpf_ksym"] = record(
            64,
            dict(
                lnode=field(0, struct("list_head")),
                start=field(16, ptr("void")),
                end=field(24, ptr("void")),
                name=field(32, array(16)),
            ),
        )
        put(0x1A210, 0x8800)
        put(0x1A218, 0x8840)
        text(0x1A220, b"bpf_entry")
    else:
        fields = dict(
            ksym_lnode=field(0, struct("list_head")),
            prog=field(16, ptr("bpf_prog")),
            name=field(32, array(16)),
        )
        if bpf_layout == "pack":
            fields["use_bpf_prog_pack"] = field(24, base("u32"))
            put(0x1A218, 1, 4)
        types["bpf_prog_aux"] = record(64, fields)
        types["bpf_prog"] = record(
            32, dict(aux=field(0, ptr("bpf_prog_aux")), bpf_func=field(8, ptr("void")))
        )
        types["bpf_binary_header"] = record(4, dict(pages=field(0, base("u32"))))
        put(0x1A210, 0x1A400)
        text(0x1A220, b"bpf_entry")
        put(0x1A400, 0x1A200)
        put(0x1A408, 0x1B047 if bpf_layout == "pack" else 0x1B007)
        put(0x1B040 if bpf_layout == "pack" else 0x1B000, 2, 4)
    if scenario == "aux-redirect" and bpf_layout != "modern":
        put(0x1A400, 0x1A500)
        text(0x1A520, b"other_bpf")
        if bpf_layout == "pack":
            put(0x1A518, 1, 4)
    linked(0x17C60, [] if scenario == "empty" else [0x1A200])
    isf["symbols"].update(
        modules=dict(address=0x17C00),
        ftrace_mod_maps=dict(address=0x17C20),
        ftrace_ops_trampoline_list=dict(address=0x17C40),
        bpf_kallsyms=dict(address=0x17C60),
    )
    for name in (
        "modules",
        "ftrace_mod_maps",
        "ftrace_ops_trampoline_list",
        "bpf_kallsyms",
    ):
        isf["symbols"][name]["type"] = struct("list_head")
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
    from volatility3.framework.symbols.linux import extensions
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.plugins.linux.kallsyms import Kallsyms as Plugin

    cases = []
    for width in (4, 8):
        for layout in ("legacy", "pointer", "embedded", "typetab"):
            for bpf in ("modern", "legacy", "pack"):
                for scenario in (
                    "normal",
                    "empty",
                    "no-exports",
                    "prel32-exports",
                    "aux-redirect",
                ):
                    isf, data = fixture(width, layout, bpf, scenario)
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

                        @property
                        def page_size(self):
                            return 4096

                        @property
                        def page_mask(self):
                            return ~4095

                    context.config["test.kernel_virtual_offset"] = 0
                    context.layers.add_layer(
                        KernelBuffer(context, "test", "memory", data)
                    )
                    with tempfile.TemporaryDirectory(
                        prefix="gomem-kallsyms-sources-"
                    ) as directory:
                        path = Path(directory) / "kernel.json"
                        path.write_text(json.dumps(isf))
                        context.symbol_space.append(
                            IntermediateSymbolTable(
                                context,
                                "symbols",
                                "kernel",
                                path.as_uri(),
                                class_types={
                                    name: getattr(extensions, name)
                                    for name in (
                                        "list_head",
                                        "module",
                                        "kernel_symbol",
                                        "bpf_prog",
                                        "bpf_prog_aux",
                                    )
                                    if name in isf["user_types"]
                                },
                            )
                        )
                        context.module("kernel", "memory", 0)
                        kas = Kallsyms(context, "memory", "kernel")
                        expected = []
                        reference_error = None
                        try:
                            for symbol in kas.get_all_symbols():
                                size = Plugin._get_symbol_size(None, symbol)
                                expected.append(
                                    dict(
                                        Name=symbol.name,
                                        Type=symbol.type or None,
                                        Address=symbol.address,
                                        Size=None
                                        if isinstance(size, renderers.NotAvailableValue)
                                        else size,
                                        Exported=symbol.exported,
                                        Module=symbol.module_name,
                                        Subsystem=symbol.subsystem,
                                        Description=symbol.type_description,
                                    )
                                )
                        except TypeError as error:
                            if (
                                scenario != "prel32-exports"
                                or "pointer_to_string takes a Pointer" not in str(error)
                            ):
                                raise
                            reference_error = str(error)
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
                            bpf=bpf,
                            scenario=scenario,
                            isf=isf,
                            writes=writes,
                            expected=expected,
                            reference_error=reference_error,
                        )
                    )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope="Unmodified Kallsyms.get_all_symbols and actual Linux module, kernel_symbol, ftrace and BPF extensions; real byte-backed ISF objects; no method mocks",
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
            raise ValueError("kallsyms source oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual kallsyms source cases verified")


if __name__ == "__main__":
    main()
