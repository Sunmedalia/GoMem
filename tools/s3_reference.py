#!/usr/bin/env python3
"""Exercise the unmodified locked S3 handler with real s3fs over a test endpoint."""
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
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(args.source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    import fsspec.config
    import s3fs
    if s3fs.__version__ != "2026.9.0":
        raise ValueError("requires s3fs 2026.9.0")
    # Provider configuration selects the wire endpoint; no parser/client methods are mocked.
    fsspec.config.conf["s3"] = dict(anon=True, client_kwargs=dict(endpoint_url=args.endpoint, region_name="us-east-1"), config_kwargs=dict(s3=dict(addressing_style="path")))
    sys.path.insert(0, str(args.source))
    from volatility3.framework import constants
    from volatility3.framework.layers import cloudstorage
    from volatility3.framework.layers.resources import ResourceAccessor
    if not cloudstorage.HAS_S3FS:
        raise ValueError("S3 handler unavailable")
    with tempfile.TemporaryDirectory() as directory:
        constants.CACHE_PATH = directory
        with ResourceAccessor().open(args.url) as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(0)
            digest = hashlib.sha256()
            while data := stream.read(65536):
                digest.update(data)
            reads = []
            for offset in [0, 1, size // 2, size - 16]:
                stream.seek(offset)
                reads.append(dict(offset=offset, data=base64.b64encode(stream.read(16)).decode()))
    print(json.dumps(dict(schema="gomem.s3-reference/v1", baseline_commit=lock["commit"], s3fs=s3fs.__version__, sha256=digest.hexdigest(), size=size, reads=reads), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("S3 reference failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
