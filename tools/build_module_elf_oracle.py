#!/usr/bin/env python3
"""Evaluate locked ModuleExtract encoding, including its section-index quirks.

The actual full extractor and parse_sections run unchanged over deterministic
byte-backed ELF symbols and section reads. Only kernel object/layer boundaries
and allocation limits are mocked. No Python dependency enters the Go runtime.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/elfimage/testdata/module-elf-oracle.json"


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("reference source differs from lock")
    sys.path.insert(0, str(source))
    from volatility3.framework.symbols.linux.utilities.modules import ModuleExtract, Modules
    from volatility3.framework import symbols
    cases = []
    for bits in (32, 64):
        for scenario in ("address-order", "insertion-order", "duplicate-address", "unicode-name", "rela-section", "last-data", "string-tail", "section-symbols", "original-shstrtab"):
            sections = [(".text", 0x1000), (".data", 0x1010), (".strtab", 0x1020), (".symtab", 0x1040)]
            if scenario == "insertion-order":
                sections = [sections[i] for i in (2, 3, 1, 0)]
            elif scenario == "duplicate-address":
                sections.insert(0, (".discarded", 0x1010))
            elif scenario == "unicode-name":
                sections[1] = (".dátá", 0x1010)
            elif scenario == "rela-section":
                sections[1] = (".rela.text", 0x1010)
            elif scenario == "original-shstrtab":
                sections[1] = (".shstrtab", 0x1010)
            elif scenario == "last-data":
                sections.append((".bss", 0x1060))
            memory = bytearray(0x20000)
            for i in range(0x1000, 0x1060):
                memory[i] = i & 255
            string_data = b"\0foo\0bar\0\0unused"
            if scenario == "string-tail":
                string_data = b"x" * (8 * 256)
            memory[0x1800:0x1800 + len(string_data)] = string_data
            values = (0, 0x1000, 0x100f, 0x1010, 0x1020, 0x9000, 0, 0x103f)
            raw_symbols = b""
            for i, value in enumerate(values):
                name = 0 if i == 0 or scenario == "section-symbols" else i
                raw_symbols += struct.pack("<IIIBBH", name, value, i + 1, 0xee, 2, 0xfff1) if bits == 32 else struct.pack("<IBBHQQ", name, 0xee, 2, 0xfff1, value, i + 1)
            memory[0x2000:0x2000 + len(raw_symbols)] = raw_symbols
            def get_type(name):
                size = {"Elf32_Ehdr": 52, "Elf64_Ehdr": 64, "Elf32_Shdr": 40, "Elf64_Shdr": 64, "Elf32_Sym": 16, "Elf64_Sym": 24}[name]
                return SimpleNamespace(size=size, vol=SimpleNamespace(size=size))
            def kernel_object(**kwargs):
                if kwargs["object_type"] != "array":
                    raise ValueError(kwargs)
                result = []
                for i in range(kwargs["count"]):
                    at = kwargs["offset"] + i * get_type("Elf%d_Sym" % bits).size
                    if bits == 32:
                        name, value, size, info, other, index = struct.unpack_from("<IIIBBH", memory, at)
                    else:
                        name, info, other, index, value, size = struct.unpack_from("<IBBHQQ", memory, at)
                    result.append(SimpleNamespace(st_name=name, st_value=value, st_size=size, st_info=info, st_other=other, st_shndx=index))
                return result
            kernel = SimpleNamespace(layer_name="memory", symbol_table_name="kernel", get_type=get_type, object=kernel_object)
            layer = SimpleNamespace(address_mask=(1 << bits) - 1, read=lambda at, size, pad: bytes(memory[at:at + size]))
            context = SimpleNamespace(modules={"kernel": kernel}, layers={"memory": layer})
            module = SimpleNamespace(sect_attrs=SimpleNamespace(nsections=len(sections)), get_sections=lambda: [SimpleNamespace(address=at, get_name=lambda name=name: name) for name, at in sections], section_symtab=0x2000, section_strtab=0x1800, num_symtab=len(values))
            with patch.object(symbols, "symbol_table_is_64bit", return_value=bits == 64), patch.object(Modules, "get_modules_memory_boundaries", return_value=(0x1000, 0x1100)):
                output = ModuleExtract.extract_module(context, "kernel", module)
                parsed, _, _ = ModuleExtract._parse_sections(context, "kernel", module)
            parsed_data = {address: data for name, address, _, data in parsed if name != ".symtab"}
            cases.append(dict(name=scenario, bits=bits, sections=[dict(name=name, address=at, data=parsed_data.get(at, b"").hex()) for name, at in sections], symbols=raw_symbols.hex(), sha256=hashlib.sha256(output).hexdigest(), size=len(output)))
    return json.dumps(dict(commit=COMMIT, scope="Actual pinned ModuleExtract byte encoding over mocked kernel boundaries; real parsing is separately corpus-tested", cases=cases), ensure_ascii=True, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / ".cache" / ("volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("module ELF oracle differs")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} pinned module ELF cases verified")


if __name__ == "__main__":
    main()
