#!/usr/bin/env python3
"""Exercise locked Windows Intel swap translation on actual byte-backed layers."""
import argparse
import base64
import json
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/memory/testdata/windows-swap-oracle.json"


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers import intel, physical

    cases = []
    modes = [("x64", intel.WindowsIntel32e, [39, 30, 21, 12], 8, 32),
             ("pae", intel.WindowsIntelPAE, [30, 21, 12], 8, 32),
             ("x86", intel.WindowsIntel, [22, 12], 4, 12)]
    for arch, cls, shifts, width, high_bit in modes:
        for level, shift in enumerate(shifts):
            for number in [0, 1, 15]:
                for displacement in [0, 0x123]:
                    data = bytearray(0x10000)
                    writes = []
                    for depth in range(level + 1):
                        value = ((depth + 2) << 12) | 3
                        if depth == level:
                            value = (2 << high_bit) | 128 | (number << 1)
                        offset = (depth + 1) << 12
                        struct.pack_into("<I" if width == 4 else "<Q", data, offset, value)
                        writes.append(dict(offset=offset, value=value))
                    ctx = contexts.Context()
                    ctx.layers.add_layer(physical.BufferDataLayer(ctx, "ram", "ram", bytes(data)))
                    pagefile = bytes(index % 251 for index in range(0x4000))
                    ctx.layers.add_layer(physical.BufferDataLayer(ctx, "file", "file", pagefile))
                    ctx.config["virtual.memory_layer"] = "ram"
                    ctx.config["virtual.page_map_offset"] = 0x1000
                    ctx.config["virtual.swap_layers"] = True
                    ctx.config[f"virtual.swap_layers.swap_layers{number}"] = "file"
                    layer = cls(ctx, "virtual", "virtual")
                    ctx.layers.add_layer(layer)
                    translated, size, selected = layer._translate(displacement)
                    if translated != 2 << shift or size != 1 << shift or selected != "file":
                        raise ValueError("unexpected actual Windows swap translation")
                    case = dict(arch=arch, level=level, number=number, address=displacement,
                                entry=writes[-1]["value"], width=width, writes=writes,
                                reference_offset=translated, page_size=size,
                                corrected_offset=translated + displacement)
                    if shift == 12:
                        case["reference_bytes"] = base64.b64encode(layer.read(displacement, 8)).decode()
                        case["corrected_bytes"] = base64.b64encode(pagefile[translated + displacement:translated + displacement + 8]).decode()
                    cases.append(case)
    return dict(schema="gomem.windows-swap-oracle/v1", baseline_commit=COMMIT,
                divergence="Pinned _translate_swap omits within-page displacement; native byte reads add it explicitly.", cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    value = json.dumps(result, indent=2) + "\n"
    if args.check:
        if OUTPUT.read_text() != value:
            raise SystemExit("Windows swap oracle differs; regenerate")
    else:
        OUTPUT.parent.mkdir(exist_ok=True)
        OUTPUT.write_text(value)
    print(f"{len(result['cases'])} actual Windows swap translations verified")


if __name__ == "__main__":
    main()
