#!/usr/bin/env python3
"""Independently compile/load native rule artifacts with pinned Python YARA-X."""
import argparse
import base64
import importlib.metadata
import json
from pathlib import Path
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--compiled", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import yara_x
    if importlib.metadata.version("yara-x") != "1.9.0":
        raise ValueError("requires yara-x 1.9.0")
    source = ROOT / (".cache/volatility3-" + COMMIT)
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires pinned Volatility")
    sys.path.insert(0, str(source))
    from volatility3.plugins.yarascan import YaraScanner
    if args.config:
        config = json.loads(args.config.read_text())
        compiler = yara_x.Compiler()
        compiler.enable_includes(False)
        for name, value in config.get("globals", {}).items():
            compiler.define_global(name, value)
        for item in config["sources"]:
            compiler.new_namespace(item["namespace"] or "default")
            compiler.add_source(base64.b64decode(item["text"]).decode())
        rules = compiler.build()
        with args.compiled.open("xb") as out:
            rules.serialize_into(out)
    else:
        with args.compiled.open("rb") as src:
            rules = yara_x.Rules.deserialize_from(src)
    data = args.data.read_bytes()
    matches = [dict(offset=offset, rule=rule, pattern=pattern, bytes=base64.b64encode(value).decode())
               for offset, rule, pattern, value in YaraScanner(rules)(data, 0)]
    args.output.write_text(json.dumps(matches, indent=2) + "\n")


if __name__ == "__main__":
    main()
