#!/usr/bin/env python3
"""Run unmodified PDB-first module resolution over real layers and an ISF cache."""
import argparse
import base64
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest
from build_pe_exports_oracle import fixture

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/pesymbols/testdata/resolver-oracle.json"


def generate(source):
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires locked unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, constants
    from volatility3.framework.automagic.symbol_cache import SqliteCache, WindowsIdentifier
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.plugins.windows.pe_symbols import PESymbols
    original_cache, original_offline = constants.CACHE_PATH, constants.OFFLINE
    cases = []
    try:
        with tempfile.TemporaryDirectory() as directory:
            constants.CACHE_PATH, constants.OFFLINE = directory, True
            dbpath = str(Path(directory) / constants.IDENTIFIERS_FILENAME)
            SqliteCache(dbpath)
            modules, tables, raw_images = [], [], []
            ctx = contexts.Context()
            class PagedBuffer(BufferDataLayer):
                page_size = 4096
            for i, values in enumerate((dict(AlphaPDB=0x1200, Zulu=0x1200, Private=0x1300), dict(Alpha=0x1600, Later=0x1300))):
                guid = bytes([0x12 + i]) * 16
                isf = dict(metadata=dict(format="6.2.0", windows=dict(pdb=dict(database="fixture.pdb", GUID=guid.hex().upper(), age=1, machine_type=0x14c))),
                           base_types=dict(pointer=dict(kind="int", size=4, endian="little", signed=False)), user_types={}, enums={},
                           symbols={name:dict(address=at) for name, at in values.items()})
                path = Path(directory) / f"pdb-{i}.json"
                path.write_text(json.dumps(isf))
                with sqlite3.connect(dbpath) as database:
                    database.execute("INSERT INTO cache(location, identifier, operating_system, local) VALUES(?,?,?,1)",
                                     (path.as_uri(), WindowsIdentifier.generate("fixture.pdb", guid.hex().upper(), 1), "windows"))
                data = bytearray(fixture(False, "normal"))
                data[0x1900:0x1900+36] = b"RSDS" + guid + (1).to_bytes(4, "little") + b"fixture.pdb\0"
                base = 0x1000
                layer_name = f"module{i}"
                layer = PagedBuffer(ctx, layer_name, layer_name, bytes(base) + data)
                ctx.layers.add_layer(layer)
                modules.append((layer_name, base, len(data)))
                tables.append(isf)
                raw_images.append(base64.b64encode(data).decode())
            requests = [
                dict(names=["Alpha"]), dict(names=["Alpha", "Forward", "absent", "Alpha"]),
                dict(addresses=[0x2200]), dict(addresses=[0x2201, 0x2700]),
                dict(names=["Private", "Private"], addresses=[0x2200]),
                dict(names=["absent"], addresses=[0x2200]),
                dict(names=["Alpha", "Private", "Later", "Forward"]),
                dict(addresses=[0x2300,0x2300,0x2600,0x2700]),
                dict(names=["missing"], addresses=[0x9000]),
            ]
            for instances in (modules, list(reversed(modules))):
                for request in requests:
                    expected, missing = PESymbols._resolve_symbols_through_methods(
                        ctx, "resolve", instances, {"fixture.dll": request}, "fixture.dll")
                    cases.append(dict(order=[modules.index(m) for m in instances], request=request,
                                      expected=expected, missing=missing))
            return json.dumps(dict(commit=COMMIT, base=0x1000, images=raw_images, tables=tables, cases=cases), indent=2) + "\n"
    finally:
        constants.CACHE_PATH, constants.OFFLINE = original_cache, original_offline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("module symbol oracle differs")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} real PDB/ISF-cache and export module-resolution cases verified")


if __name__ == "__main__":
    main()
