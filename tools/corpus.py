#!/usr/bin/env python3
"""Download named official assets with pinned checksums. Images stay local."""
import argparse
import gzip
import hashlib
import json
import pathlib
import shutil
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("asset", help="Exact name in docs/corpus.json")
    parser.add_argument("--directory", type=pathlib.Path, default=ROOT / ".cache/corpus")
    parser.add_argument("--decompress", action="store_true", help="Decompress verified gzip, with an 8 GiB bound")
    args = parser.parse_args()
    assets = json.loads((ROOT / "docs/corpus.json").read_text())["official_assets"]
    asset = next((a for a in assets if a["name"] == args.asset), None)
    if asset is None:
        parser.error("unknown asset")
    args.directory.mkdir(parents=True, exist_ok=True)
    target = args.directory / asset["name"]
    if not target.exists():
        temp = target.with_suffix(target.suffix + ".partial")
        try:
            with urllib.request.urlopen(asset["url"], timeout=60) as src, temp.open("xb") as dst:
                total = 0
                while chunk := src.read(4 << 20):
                    total += len(chunk)
                    if total > asset["size"]:
                        raise ValueError("asset exceeds recorded size")
                    dst.write(chunk)
            temp.rename(target)
        finally:
            temp.unlink(missing_ok=True)
    with target.open("rb") as src:
        digest = hashlib.file_digest(src, "sha256").hexdigest()
    if digest != asset["sha256"] or target.stat().st_size != asset["size"]:
        raise ValueError("official asset checksum/size mismatch")
    print(f"verified {target}: {digest}", flush=True)
    if args.decompress:
        if target.suffix != ".gz":
            parser.error("--decompress only handles gzip; select zip symbol members explicitly")
        output = target.with_suffix("")
        with gzip.open(target, "rb") as src, output.open("xb") as dst:
            total = 0
            while chunk := src.read(4 << 20):
                total += len(chunk)
                if total > 8 << 30:
                    raise ValueError("decompressed image exceeds 8 GiB bound")
                dst.write(chunk)
        print(output)


if __name__ == "__main__":
    main()
