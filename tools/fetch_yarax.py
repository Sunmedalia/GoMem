#!/usr/bin/env python3
"""Fetch checksum-pinned YARA-X source for optional native validation."""
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    lock = json.loads((ROOT / "yarax.lock.json").read_text())
    cache = ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    archive = cache / "yarax-reference.tar.gz"
    if not archive.exists():
        temporary = archive.with_suffix(".download")
        try:
            with urllib.request.urlopen("https://codeload.github.com/VirusTotal/yara-x/tar.gz/" + lock["commit"], timeout=60) as src, temporary.open("wb") as dst:
                total = 0
                while data := src.read(1 << 20):
                    total += len(data)
                    if total > 64 << 20:
                        raise ValueError("YARA-X archive exceeds budget")
                    dst.write(data)
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    with archive.open("rb") as src:
        if hashlib.file_digest(src, "sha256").hexdigest() != lock["archive_sha256"]:
            raise ValueError("YARA-X archive checksum mismatch")
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if sum(member.size for member in members) > 256 << 20 or len(members) > 20000:
            raise ValueError("YARA-X source exceeds budget")
        tar.extractall(cache, filter="data")
    print(cache / ("yara-x-" + lock["commit"]))


if __name__ == "__main__":
    main()
