#!/usr/bin/env python3
"""Development-only PDB conversion using the content-verified fixed baseline."""
import argparse
import hashlib
import json
import pathlib
import sys

from baseline_matrix import ROOT, tree_digest


def digest(path):
    with path.open("rb") as src:
        return hashlib.file_digest(src, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--pdb", required=True, type=pathlib.Path)
    parser.add_argument("--database")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(args.source) != lock["python_tree_sha256"]:
        raise ValueError("PDB reference source does not match baseline.lock.json")
    sidecar = args.output.with_suffix(".manifest.json")
    if args.output.exists() or sidecar.exists():
        raise ValueError("reference output/manifest already exists")
    sys.path.insert(0, str(args.source.resolve()))
    from volatility3.framework.contexts import Context
    from volatility3.framework.symbols.windows.pdbconv import PdbReader
    table = PdbReader(Context(), args.pdb.resolve().as_uri(), database_name=args.database or args.pdb.name).get_json()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as out:
        json.dump(table, out, indent=2)
        out.write("\n")
    sidecar.write_text(json.dumps({"baseline": lock, "pdb_sha256": digest(args.pdb), "output_sha256": digest(args.output),
                                   "database": args.database or args.pdb.name, "python": sys.version}, indent=2) + "\n")


if __name__ == "__main__":
    main()
