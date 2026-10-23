#!/usr/bin/env python3
"""Read an FTP control through the actual locked Volatility ResourceAccessor."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(args.source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(args.source))
    from volatility3.framework import constants
    from volatility3.framework.layers.resources import ResourceAccessor
    with tempfile.TemporaryDirectory() as cache:
        constants.CACHE_PATH = cache
        with ResourceAccessor().open(args.url) as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(0)
            digest = hashlib.sha256()
            while data := stream.read(65536):
                digest.update(data)
            reads = []
            for offset in [0, 1, size // 2, max(0, size - 16)]:
                stream.seek(offset)
                reads.append(dict(offset=offset, data=base64.b64encode(stream.read(16)).decode()))
    print(json.dumps(dict(schema="gomem.ftp-reference/v1", baseline_commit=lock["commit"], size=size, sha256=digest.hexdigest(), reads=reads), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Remote replies may echo secrets; never print the exception message/URL.
        print("FTP reference failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
