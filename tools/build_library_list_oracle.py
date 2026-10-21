#!/usr/bin/env python3
"""Run locked ELF/link-map extensions over actual byte-backed framework objects.

Only the task/VMA boundary is mocked. ELF headers, dynamic entries, pointers,
link-map traversal, name reads and LibraryList deduplication execute upstream.
"""
import argparse
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace as NS

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/plugins/testdata/linux-library-list-oracle.json"


def fixture(width, dynamic, scenario):
    data = bytearray(0x10000)
    base = 0x1000
    data[base:base + 7] = b"\x7fELF" + bytes([1 if width == 4 else 2, 1, 1])
    def word(at, n):
        struct.pack_into("<I" if width == 4 else "<Q", data, at, n)
    struct.pack_into("<H", data, base + 16, 3 if dynamic else 2)
    phoff, phsize = (52, 32) if width == 4 else (64, 56)
    word(base + (28 if width == 4 else 32), phoff)
    struct.pack_into("<H", data, base + (44 if width == 4 else 56), 2)
    struct.pack_into("<I", data, base + phoff, 1)
    struct.pack_into("<I", data, base + phoff + phsize, 2)
    word(base + phoff + phsize + (8 if width == 4 else 16), 0x1000 if dynamic else 0x2000)
    word(0x2000, 3)
    word(0x2000 + width, 0x3000)
    word(0x3000 + width, 0x4000)
    for at, load, name, nxt in [(0x4000, 0, 0x6000, 0x4100), (0x4100, 0x700000, 0x6100, 0x4200), (0x4200, 0x800000, 0x6200, 0x4300), (0x4300, 0x700000, 0x6300, 0)]:
        word(at, load)
        word(at + width, name)
        word(at + width * 3, nxt)
    for at, text in [(0x6100, b"/lib/libone.so\0"), (0x6200, b"/\xe2\x82\0"), (0x6300, b"/duplicate.so\0")]:
        data[at:at + len(text)] = text
    if scenario == "empty-first":
        data[0x6100:0x6200] = bytes(256)
    elif scenario == "name-hole":
        word(0x4100 + width, 0xfff0)
    elif scenario == "cycle":
        word(0x4300 + width * 3, 0x4000)
    elif scenario == "zero-name":
        word(0x4100 + width, 0)
    elif scenario == "duplicate-dynamic":
        word(0x2000 + width * 2, 3)
        word(0x2000 + width * 3, 0x3000)
    elif scenario == "no-pltgot":
        word(0x2000, 21)  # DT_DEBUG is not a substitute for DT_PLTGOT.
    elif scenario == "compat-high-half":
        struct.pack_into("<I", data, 0x3008, 1)
    return bytes(data)


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols import intermed, native
    from volatility3.framework.symbols.linux.extensions import elf
    from volatility3.plugins.linux.library_list import LibraryList
    cases = []
    for width in (4, 8):
        for dynamic in (False, True):
            for scenario in ("standard", "empty-first", "name-hole", "cycle", "zero-name", "duplicate-dynamic", "no-pltgot", "compat-high-half"):
                if scenario == "compat-high-half" and width != 4:
                    continue
                data = fixture(width, dynamic, scenario)
                context = contexts.Context()
                kernel_width = 8 if scenario == "compat-high-half" else width
                class ProcessBuffer(BufferDataLayer):
                    @property
                    def address_mask(self):
                        # BufferDataLayer normally masks pointers to its short
                        # buffer extent. Real Intel process layers retain their
                        # architecture width even when the acquisition is short.
                        return (1 << (kernel_width * 8)) - 1
                layer = ProcessBuffer(context, "test", "memory", data)
                context.layers.add_layer(layer)
                ctypes = native.native_types.copy()
                kernel_width = 8 if scenario == "compat-high-half" else width
                ctypes["pointer"] = (native.native_types["pointer"][0], (kernel_width, "little", False))
                context.symbol_space.append(native.NativeTable("kernel", ctypes))
                context.module("kernel", "memory", 0)
                table = intermed.IntermediateSymbolTable.create(context, "test", "linux", "elf", class_types=elf.class_types)
                obj = context.object(table + "!Elf", layer_name="memory", offset=0x1000)
                links = list(obj.get_link_maps("kernel"))
                # Exercise actual LibraryList filtering and process-wide load
                # dedup over two VMA starts that expose the same ELF chain.
                runner = NS(context=context, config={"kernel": "kernel"}, config_path="plugin")
                runner._get_libdl_libraries = lambda layer, start: LibraryList._get_libdl_libraries(runner, layer, start)
                task = NS(mm=NS(get_vma_iter=lambda: iter([NS(vm_start=0x1000), NS(vm_start=0x1000)])))
                maps = list(LibraryList._get_libdl_maps(runner, task, "memory"))
                rows = [{"link_map": int(link.vol.offset), "load_address": int(link.l_addr), "path": link.get_name()} for link in maps if link.get_name()]
                writes = []
                cursor = 0
                while cursor < len(data):
                    if data[cursor] == 0:
                        cursor += 1
                        continue
                    start = cursor
                    while cursor < len(data) and data[cursor] != 0:
                        cursor += 1
                    writes.append([start, data[start:cursor].hex()])
                cases.append(dict(width=width, kernel_width=kernel_width, dynamic=dynamic, scenario=scenario, size=len(data), writes=writes, link_maps=[int(link.vol.offset) for link in links], rows=rows))
    return json.dumps(dict(commit=COMMIT, scope="Actual pinned ELF objects and LibraryList traversal/dedup over byte-backed framework layers; task/VMA boundaries mocked", cases=cases), ensure_ascii=True, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("library-list oracle differs")
        print(f"{len(json.loads(result)['cases'])} byte-backed pinned ELF/library-list cases verified")
    else:
        OUTPUT.write_text(result)


if __name__ == "__main__":
    main()
