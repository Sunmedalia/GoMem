#!/usr/bin/env python3
"""Evaluate pinned module parameter decoding over deterministic sparse memory.

The production _get_param_val and _get_param_handlers run unchanged. Only the
kernel object/read boundary is supplied by a byte-backed development fixture;
no Volatility dependency enters the Go runtime.
"""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/plugins/testdata/linux-module-params-oracle.json"
HANDLERS = ["param_get_invbool", "param_get_bool", "param_get_int", "param_get_ulong",
            "param_get_ullong", "param_get_long", "param_get_uint", "param_get_ushort",
            "param_get_short", "param_get_byte", "param_get_string", "param_array_get",
            "param_get_charp"]


class Fixture:
    def __init__(self, width, endian, layout, char_signed=True):
        self.width, self.endian, self.layout = width, endian, layout
        self.char_signed = char_signed
        self.memory = bytearray(65536)
        self.writes = []
        self.symbols = {name: 0x8000 + 16 * i for i, name in enumerate(HANDLERS)}
        self.symbol_overrides = {}
        self.write(0x80, 0x100, width)
        self.write(0x88, 1, 4)
        self.write(0x100, 0x6000, width)
        self.raw(0x6000, b"test\0")

    def raw(self, at, data):
        self.memory[at:at + len(data)] = data
        self.writes.append({"address": at, "hex": data.hex()})

    def write(self, at, value, size):
        self.raw(at, (value % (1 << (8 * size))).to_bytes(size, self.endian))

    def uint(self, at, size):
        return int.from_bytes(self.memory[at:at + size], self.endian)

    def param(self, at, getter, arg):
        function = self.symbols.get(getter, getter if isinstance(getter, int) else 0)
        if self.layout == "get":
            self.write(at + 8, function, self.width)
        else:
            self.write(at + 8, at + 0x1000, self.width)
            self.write(at + 0x1008, function, self.width)
        self.write(at + 16, arg, self.width)

    def array(self, at, count, elements, num=0, step=32):
        self.write(at, count, 4)
        self.write(at + 8, num, self.width)
        self.write(at + 16, step, 4)
        self.write(at + 24, elements, self.width)

    def pointer(self, value):
        fixture = self
        class Pointer(int):
            @property
            def maxlen(self):
                return fixture.uint(self, 4)
            def dereference(self):
                return fixture.uint(self, 4)
        return Pointer(value)

    def object_param(self, at):
        fixture = self
        class Param:
            arg = fixture.uint(at + 16, fixture.width)
            def __getattr__(self, name):
                if name == "get" and fixture.layout == "get":
                    return fixture.uint(at + 8, fixture.width)
                if name == "ops" and fixture.layout == "ops":
                    ops = fixture.uint(at + 8, fixture.width)
                    return SimpleNamespace(get=fixture.uint(ops + 8, fixture.width))
                if name == "arr":
                    array = fixture.uint(at + 16, fixture.width)
                    return SimpleNamespace(
                        num=fixture.pointer(fixture.uint(array + 8, fixture.width)),
                        elemsize=fixture.uint(array + 16, 4),
                        elem=fixture.uint(array + 24, fixture.width),
                        member=lambda key: fixture.uint(array, 4) if key == "max" else None)
                raise AttributeError(name)
            def member(self, name):
                if name != "str":
                    raise ValueError(name)
                return fixture.pointer(fixture.uint(at + 16, fixture.width))
        return Param()

    def kernel_object(self, object_type, offset, **_):
        if object_type == "kernel_param":
            return self.object_param(offset)
        sizes = {"int": (4, True), "long unsigned int": (self.width, False),
                 "long long unsigned int": (8, False), "long int": (self.width, True),
                 "unsigned int": (4, False), "short unsigned int": (2, False),
                 "short int": (2, True), "char": (1, self.char_signed)}
        size, signed = sizes[object_type]
        return int.from_bytes(self.memory[offset:offset + size], self.endian, signed=signed)

    def evaluate(self, modules, utility):
        kernel = SimpleNamespace(
            object=self.kernel_object,
            get_absolute_symbol_address=lambda name: self.symbols[name],
            get_symbols_by_absolute_location=lambda _: [])
        context = SimpleNamespace(modules={"kernel": kernel})
        integers, getters = modules._get_param_handlers(context, "kernel")
        def pointer_string(pointer, count):
            return utility.bytes_to_decoded_string(bytes(self.memory[pointer:pointer + count]), "utf-8", "replace")
        with patch.object(utility, "pointer_to_string", side_effect=pointer_string):
            return modules._get_param_val(context, "kernel", integers, getters,
                                          SimpleNamespace(vol=SimpleNamespace(offset=0x80)),
                                          self.object_param(0x100))


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned source")
    sys.path.insert(0, str(source))
    from volatility3.framework.symbols.linux.utilities.modules import Modules
    from volatility3.framework.objects import utility
    cases = []
    for width in (4, 8):
        for endian in ("little", "big"):
            for layout in ("get", "ops"):
                scenarios = [
                    ("int-min", "param_get_int", -(1 << 31), 4),
                    ("int-negative", "param_get_int", -1, 4),
                    ("short-negative", "param_get_short", -123, 2),
                    ("long-min", "param_get_long", -(1 << (width * 8 - 1)), width),
                    ("ulong-max", "param_get_ulong", (1 << (width * 8)) - 1, width),
                    ("ullong-max", "param_get_ullong", (1 << 64) - 1, 8),
                    ("uint-max", "param_get_uint", (1 << 32) - 1, 4),
                    ("ushort-max", "param_get_ushort", 65535, 2),
                    ("byte-signed", "param_get_byte", 255, 1),
                    ("byte-unsigned", "param_get_byte", 255, 1),
                    ("bool-zero", "param_get_bool", 0, 4),
                    ("bool-nonzero", "param_get_bool", 2, 4),
                    ("invbool-zero", "param_get_invbool", 0, 4),
                    ("invbool-nonzero", "param_get_invbool", -1, 4),
                    ("unknown", 0xdead, 0, 4), ("null", 0, 0, 4),
                    ("charp", "param_get_charp", 0, 4),
                    ("charp-invalid-utf8", "param_get_charp", 0, 4),
                    ("charp-empty", "param_get_charp", 0, 4),
                    ("charp-limit", "param_get_charp", 0, 4),
                    ("charp-replacement", "param_get_charp", 0, 4),
                    ("kparam-string-address", "param_get_string", 0, 4),
                    ("kparam-string-maxlen", "param_get_string", 0, 4),
                    ("array-empty", "param_array_get", 0, 4),
                    ("array-max", "param_array_get", 0, 4),
                    ("array-num", "param_array_get", 0, 4),
                    ("array-nested", "param_array_get", 0, 4),
                    ("alias-bool-uint", "param_get_bool", -1, 4),
                ]
                for name, getter, number, size in scenarios:
                    f = Fixture(width, endian, layout, name != "byte-unsigned")
                    if name == "alias-bool-uint":
                        f.symbols["param_get_uint"] = f.symbols["param_get_bool"]
                        f.symbol_overrides["param_get_uint"] = f.symbols["param_get_bool"]
                    arg = 0x5000
                    if name.startswith("charp"):
                        raw = {"charp": "取证\0tail".encode(), "charp-invalid-utf8": b"abc\xffdef\0", "charp-empty": b"\0", "charp-limit": b"A" * 256 + b"B", "charp-replacement": "prefix\ufffdafter".encode()}[name]
                        f.raw(arg, raw)
                    elif name.startswith("kparam-string-"):
                        f.write(arg, 4096 if name == "kparam-string-maxlen" else 16, 4)
                        f.write(arg + 8, 0x5100, width)
                        f.raw(0x5100, b"must-not-chase\0")
                    elif name.startswith("array-"):
                        arg = 0x800
                        f.array(arg, 0 if name == "array-empty" else 2, 0x300,
                                num=0x900 if name == "array-num" else 0)
                        f.write(0x900, 3, 4)
                        f.param(0x300, "param_get_int", 0x5200)
                        f.write(0x5200, -1, 4)
                        f.param(0x320, 0xdead, 0)
                        f.param(0x340, "param_get_charp", 0x5300)
                        f.raw(0x5300, b"ok\0")
                        if name == "array-nested":
                            f.param(0x300, "param_get_bool", 0x5200)
                            f.param(0x320, "param_array_get", 0xa00)
                            f.array(0xa00, 1, 0x400)
                            f.param(0x400, "param_get_int", 0x5400)
                            f.write(0x5400, 7, 4)
                    else:
                        f.write(arg, number, size)
                    f.param(0x100, getter, arg)
                    result = f.evaluate(Modules, utility)
                    cases.append(dict(name=name, width=width, endian=endian, layout=layout,
                                      char_signed=f.char_signed, symbol_overrides=f.symbol_overrides,
                                      writes=f.writes, expected=str(result),
                                      expected_kind="missing" if result is None else "string" if isinstance(result, str) else "integer"))
    return json.dumps(dict(commit=COMMIT, scope="Pinned decoder decisions over synthetic byte-backed objects; not real-kernel acceptance",
                           handler_symbols={name: 0x8000 + 16 * i for i, name in enumerate(HANDLERS)}, cases=cases),
                      ensure_ascii=True, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / ".cache" / ("volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("module parameter oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} pinned module parameter cases verified")


if __name__ == "__main__":
    main()
