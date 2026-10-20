#!/usr/bin/env python3
"""Fetch the exact development reference; no Python is used by GoMem itself."""
import hashlib
import json
import pathlib
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
lock = json.loads((ROOT / "baseline.lock.json").read_text())
cache = ROOT / ".cache"
cache.mkdir(exist_ok=True)
archive = cache / "volatility3.tar.gz"
if not archive.exists():
    url = f"https://codeload.github.com/volatilityfoundation/volatility3/tar.gz/{lock['commit']}"
    with urllib.request.urlopen(url, timeout=60) as src, archive.open("wb") as dst:
        total = 0
        while chunk := src.read(1 << 20):
            total += len(chunk)
            if total > 32 << 20:
                raise ValueError("baseline archive exceeds limit")
            dst.write(chunk)
with archive.open("rb") as src:
    if hashlib.file_digest(src, "sha256").hexdigest() != lock["archive_sha256"]:
        raise ValueError("baseline archive checksum mismatch")
with tarfile.open(archive) as tar:
    if sum(member.size for member in tar) > 128 << 20:
        raise ValueError("baseline source exceeds limit")
    tar.extractall(cache, filter="data")
print(cache / ("volatility3-" + lock["commit"]))
