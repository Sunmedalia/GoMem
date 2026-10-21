#!/usr/bin/env python3
"""Run real resident core lookup on an existing pinned --core reference config."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference", type=Path, required=True, help="Existing --core output prefix"
    )
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT)
    )
    args = parser.parse_args()
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(args.source) != lock["python_tree_sha256"]:
        raise ValueError("requires locked source")
    manifest_path = args.reference.with_suffix(".manifest.json")
    config_path = args.reference.with_suffix(".config.json")
    reference_path = args.reference.with_suffix(".json")
    manifest = json.loads(manifest_path.read_text())
    if (
        manifest["baseline"]["commit"] != COMMIT
        or manifest["plugin"] != "linux.kallsyms"
        or manifest["parameters"] != ["--core"]
    ):
        raise ValueError("requires pinned core reference")
    image_hash = digest(args.image)
    if (
        image_hash != manifest["image_sha256"]
        or digest(reference_path) != manifest["output_sha256"]
        or digest(config_path) != manifest["config_sha256"]
    ):
        raise ValueError("input digest mismatch")
    cfg = json.loads(config_path.read_text())
    if (
        cfg["kernel.layer_name.class"]
        != "volatility3.framework.layers.intel.LinuxIntel32e"
    ):
        raise ValueError("corpus helper supports saved LinuxIntel32e contexts only")
    sys.path.insert(0, str(args.source))
    from volatility3.framework import contexts, renderers
    from volatility3.framework.layers.physical import FileLayer
    from volatility3.framework.layers.intel import LinuxIntel32e
    from volatility3.framework.symbols.linux.extensions import (
        network,
    )  # register official extension
    from volatility3.framework.symbols.linux import LinuxKernelIntermedSymbols
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.plugins.linux.kallsyms import Kallsyms as Plugin

    ctx = contexts.Context()
    ctx.config["physical.location"] = args.image.resolve().as_uri()
    ctx.layers.add_layer(FileLayer(ctx, "physical", "physical"))
    ctx.config["virtual.memory_layer"] = "physical"
    for field in ("page_map_offset", "kernel_virtual_offset"):
        ctx.config["virtual." + field] = cfg["kernel.layer_name." + field]
    ctx.layers.add_layer(LinuxIntel32e(ctx, "virtual", "virtual"))
    # Set the mask before construction: the ISF delegate can cache symbols
    # while Linux extension types are initialized.
    ctx.config["symbols.symbol_mask"] = cfg["kernel.symbol_table_name.symbol_mask"]
    ctx.symbol_space.append(
        LinuxKernelIntermedSymbols(
            ctx,
            "symbols",
            "symbols",
            cfg["kernel.symbol_table_name.isf_url"],
            symbol_mask=cfg["kernel.symbol_table_name.symbol_mask"],
        )
    )
    ctx.module("symbols", "virtual", cfg["kernel.offset"])
    kas = Kallsyms(ctx, "virtual", "symbols")
    reference = json.loads(reference_path.read_text())
    queries = [0]
    for row in reference[::97]:
        queries += [row["Addr"], row["Addr"] + 1, row["Addr"] - 1]
    for field in ("_stext", "_etext", "_sinittext", "_einittext"):
        address = getattr(kas._kas_config, field)
        if address:
            queries += [address - 1, address, address + 1]
    queries += [queries[2] | 0xFFFF000000000000]
    results = []
    for query in queries:
        query &= (1 << 64) - 1
        symbol = kas.core_lookup_address(query)
        result = None
        if symbol is not None:
            size = Plugin._get_symbol_size(None, symbol)
            result = dict(
                Name=symbol.name,
                Type=symbol.type or "",
                Address=symbol.address,
                Size=None if isinstance(size, renderers.NotAvailableValue) else size,
                Exported=symbol.exported,
            )
        results.append(dict(Query=query, Result=result))
    output = dict(
        commit=COMMIT,
        image_sha256=image_hash,
        source_reference_manifest_sha256=digest(manifest_path),
        queries=results,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(json.dumps(output, indent=2) + "\n")
    print(f"{len(results)} real core lookup queries; SHA-256 {digest(args.output)}")


if __name__ == "__main__":
    main()
