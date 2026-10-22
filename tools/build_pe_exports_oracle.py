#!/usr/bin/env python3
"""Compare mapped PE exports with real pefile and pinned ExportSymbolFinder."""
import argparse
import base64
import json
import hashlib
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/pe/testdata/exports-oracle.json"


def fixture(is64, scenario):
    data = bytearray(0x4000)
    def word(at, value):
        struct.pack_into("<H", data, at, value)
    def dword(at, value):
        struct.pack_into("<I", data, at, value)
    data[:2] = b"MZ"
    dword(60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    word(0x84, 0x8664 if is64 else 0x14c)
    word(0x86, 1)
    optional = 240 if is64 else 224
    word(0x94, optional)
    word(0x98, 0x20b if is64 else 0x10b)
    dword(0x98 + 32, 0x1000)
    dword(0x98 + 36, 0x200)
    dword(0x98 + 56, 0x4000)
    dword(0x98 + 60, 0x400)
    directories = 0x98 + (112 if is64 else 96)
    dword(directories - 4, 16)
    dword(directories, 0x1600)
    dword(directories + 4, 0x200)
    section = 0x98 + optional
    data[section:section + 5] = b".text"
    dword(section + 8, 0x2000)
    dword(section + 12, 0x1000)
    dword(section + 16, 0x2000)
    dword(section + 20, 0x1000)
    for off, value in ((12, 0x1680), (16, 5), (20, 4), (24, 3), (28, 0x1640), (32, 0x1650), (36, 0x1660)):
        dword(0x1600 + off, value)
    for i, value in enumerate((0x1200, 0x1300, 0x1700, 0)):
        dword(0x1640 + i * 4, value)
    for i, (name, rva, ordinal) in enumerate(((b"Alpha", 0x1a00, 0), (b"Alias", 0x1a20, 0), (b"Forward", 0x1a40, 2))):
        dword(0x1650 + i * 4, rva)
        word(0x1660 + i * 2, ordinal)
        data[rva:rva + len(name) + 1] = name + b"\0"
    data[0x1680:0x1680 + 12] = b"fixture.dll\0"
    data[0x1700:0x1700 + 13] = b"OTHER.Target\0"
    if scenario == "ordinal-only":
        dword(0x1600 + 24, 0)
    elif scenario == "duplicate-address":
        dword(0x1640 + 4, 0x1200)
    elif scenario == "zero-named-target":
        dword(0x1640, 0)
    elif scenario == "empty":
        dword(0x1600 + 20, 0)
        dword(0x1600 + 24, 0)
    elif scenario == "no-directory":
        dword(directories, 0)
        dword(directories + 4, 0)
    elif scenario == "no-directories":
        dword(directories - 4, 0)
        dword(directories, 0)
        dword(directories + 4, 0)
    elif scenario == "ordinal-forwarder":
        dword(0x1640 + 4, 0x1700)
    elif scenario == "ordinal-base-overflow":
        dword(0x1600 + 16, 0xffffffff)
    return bytes(data)


def generate(source):
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires locked unmodified source")
    sys.path.insert(0, str(source))
    import pefile
    from volatility3.plugins.windows.pe_symbols import ExportSymbolFinder
    cases = []
    for is64 in (False, True):
        for scenario in ("normal", "ordinal-only", "duplicate-address", "zero-named-target", "empty", "no-directory", "no-directories", "ordinal-forwarder", "ordinal-base-overflow"):
            data = fixture(is64, scenario)
            base = 0x7ff812340000 if is64 else 0x400000
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            entries = directory.symbols if directory else []
            finder = ExportSymbolFinder("memory", "fixture.dll", base, entries)
            rows = []
            encode = lambda value: base64.b64encode(value).decode() if value is not None else None
            for e in entries:
                rows.append(dict(ordinal=e.ordinal, rva=e.address, address=base + e.address, named=e.name is not None, name=encode(e.name), forwarder=encode(e.forwarder)))
            lookups = []
            for rva in (0, 0x1200, 0x1201, 0x1300, 0x1700, 0x3000):
                lookups.append(dict(address=base+rva, name=finder.get_name_for_address(base+rva)))
            cases.append(dict(is64=is64, scenario=scenario, base=base, data=encode(data), rows=rows, lookups=lookups))
    return json.dumps(dict(commit=COMMIT, pefile=pefile.__version__, cases=cases), indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--mapped-pe", type=Path)
    parser.add_argument("--mapped-base", type=lambda v: int(v, 0))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = generate(args.source)
    if args.mapped_pe:
        if args.mapped_base is None or args.output is None or args.check:
            parser.error("--mapped-pe requires --mapped-base and --output, without --check")
        import pefile
        from volatility3.plugins.windows.pe_symbols import ExportSymbolFinder
        raw = args.mapped_pe.read_bytes()
        pe = pefile.PE(data=raw, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        entries = exports.symbols if exports else []
        encode = lambda value: base64.b64encode(value).decode() if value is not None else None
        finder = ExportSymbolFinder("memory", "kernel", args.mapped_base, entries)
        rows = [dict(ordinal=e.ordinal, rva=e.address, address=args.mapped_base+e.address,
                     named=e.name is not None, name=encode(e.name), forwarder=encode(e.forwarder)) for e in entries]
        lookups = [dict(address=args.mapped_base+e.address, name=finder.get_name_for_address(args.mapped_base+e.address)) for e in entries]
        reference = dict(commit=COMMIT, pefile=pefile.__version__, image_sha256=hashlib.sha256(raw).hexdigest(),
                         base=args.mapped_base, rows=rows, lookups=lookups)
        args.output.write_text(json.dumps(reference, indent=2) + "\n")
        print(f"{len(rows)} real mapped PE exports recorded; full symbol/plugin acceptance remains pending")
        return
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("PE export oracle differs")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} pefile and pinned ExportSymbolFinder cases verified")


if __name__ == "__main__":
    main()
