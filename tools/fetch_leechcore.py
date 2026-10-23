#!/usr/bin/env python3
"""Fetch the checksum-pinned optional native library source for development tests."""
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    lock = json.loads((ROOT / "leechcore.lock.json").read_text())
    cache = ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    archive = cache / "leechcore-reference.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen("https://codeload.github.com/ufrisk/LeechCore/tar.gz/" + lock["commit"], timeout=60) as src, archive.open("wb") as dst:
            total = 0
            while data := src.read(1 << 20):
                total += len(data)
                if total > 32 << 20:
                    raise ValueError("LeechCore archive exceeds budget")
                dst.write(data)
    with archive.open("rb") as src:
        if hashlib.file_digest(src, "sha256").hexdigest() != lock["archive_sha256"]:
            raise ValueError("LeechCore archive checksum mismatch")
    with tarfile.open(archive) as tar:
        if sum(member.size for member in tar) > 128 << 20:
            raise ValueError("LeechCore source exceeds budget")
        tar.extractall(cache, filter="data")
    print(cache / ("LeechCore-" + lock["commit"]))


if __name__ == "__main__":
    main()
