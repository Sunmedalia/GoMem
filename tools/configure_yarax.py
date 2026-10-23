#!/usr/bin/env python3
"""Configure the pinned C API with the Python 1.9.0 production module set.

Only the capi dependency feature list changes. Keep the downloaded source
untouched and build the explicitly configured copy for serialized-rule parity.
"""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def main():
    lock = json.loads((ROOT / "yarax.lock.json").read_text())
    source = ROOT / ".cache" / ("yara-x-" + lock["commit"])
    destination = ROOT / ".cache" / ("yara-x-native-" + lock["commit"])
    manifest = source / "capi/Cargo.toml"
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != lock["capi_manifest_sha256"]:
        raise ValueError("unexpected C API manifest; fetch pinned source first")
    text = manifest.read_text()
    old = 'yara-x = { workspace = true,  default-features = true, features = ["parallel-compilation"] }'
    features = ["parallel-compilation", "constant-folding", "exact-atoms", "fast-regexp"] + lock["production_modules"]
    new = 'yara-x = { workspace = true, default-features = false, features = ' + json.dumps(features) + ' }'
    if text.count(old) != 1:
        raise ValueError("pinned dependency declaration changed")
    shutil.copytree(source, destination, dirs_exist_ok=True)
    (destination / "capi/Cargo.toml").write_text(text.replace(old, new))
    print(destination)


if __name__ == "__main__":
    main()
