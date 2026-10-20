#!/usr/bin/env python3
"""Run only the locked Volatility reference, with an isolated local cache.

Use a development venv: python tools/reference.py --source ... --image ...
--symbols DIR --plugin linux.pslist --output reference.json [-- --pid 1]
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

from baseline_matrix import ROOT, tree_digest


def digest(path):
    with path.open("rb") as src:
        return hashlib.file_digest(src, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--image", type=pathlib.Path, required=True)
    parser.add_argument("--symbols", type=pathlib.Path, required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("parameters", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(args.source) != lock["python_tree_sha256"]:
        raise ValueError("reference source does not match baseline.lock.json")
    config = args.output.with_suffix(".config.json")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    cache = ROOT / ".cache/reference-cache"
    cache.mkdir(parents=True, exist_ok=True)
    if config.exists() or args.output.with_suffix(".manifest.json").exists():
        raise ValueError("reference config/manifest already exists; choose a new output filename")
    parameters = args.parameters[1:] if args.parameters[:1] == ["--"] else args.parameters
    command = [sys.executable, str(args.source / "vol.py"), "--offline", "-q", "--cache-path", str(cache),
               "-s", str(args.symbols.resolve()), "-f", str(args.image.resolve()), "--save-config", str(config.resolve()),
               "-r", "json", args.plugin, *parameters]
    image_hash = digest(args.image)
    with args.output.open("x") as out:
        try:
            subprocess.run(command, stdout=out, check=True)
        except BaseException:
            out.close()
            args.output.unlink()
            raise
    meta = {"baseline": lock, "image_sha256": image_hash, "plugin": args.plugin, "parameters": parameters,
            "output_sha256": digest(args.output), "config_sha256": digest(config), "python": sys.version}
    args.output.with_suffix(".manifest.json").write_text(json.dumps(meta, indent=2) + "\n")


if __name__ == "__main__":
    main()
