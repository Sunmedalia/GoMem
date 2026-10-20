#!/usr/bin/env python3
"""Build a hash-locked, development-only AVML encoder/decoder reference.

The Rust wrapper calls unmodified Microsoft AVML source. GoMem does not execute
this helper at runtime. Images and converted bytes stay in local files.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMIT = "d212dd1204b6ad089438fc27ae8530371c095501"
SOURCES = {
    "image.rs": ("src/image.rs", "bd706b93b42608ee7e463c370cc1fef988e9af2c49cc66a7b1c0f940b6f06ec1"),
    "snappy.rs": ("src/io/snappy.rs", "20c908af0d9a8795a860789d914099f6f5ad2f6810f9589e638ac030b472e2b9"),
    "counter.rs": ("src/io/counter.rs", "9d27c1a0b49357f8b60fd7c6fffc97f6ff10ab3c7f10836af4fb0d7d2b9dd982"),
}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name, (remote, expected) in SOURCES.items():
        path = directory / name
        if not path.exists():
            url = f"https://raw.githubusercontent.com/microsoft/avml/{COMMIT}/{remote}"
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(2 << 20)
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"AVML reference source drift: {name}")
            with path.open("xb") as output:
                output.write(data)
        if digest(path) != expected:
            raise ValueError(f"AVML reference source drift: {name}")
    for name in ("main.rs", "Cargo.toml", "Cargo.lock"):
        source = ROOT / "tools/avml-reference" / name
        target = directory / name
        if target.exists() and digest(target) != digest(source):
            raise ValueError(f"reference build file differs: {target}; use a new directory")
        if not target.exists():
            shutil.copyfile(source, target)
    subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path", str(directory / "Cargo.toml")], check=True)
    binary = directory / "target/release" / ("gomem-avml-reference.exe" if os.name == "nt" else "gomem-avml-reference")
    return binary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("prepare", "encode", "decode"))
    parser.add_argument("--directory", type=pathlib.Path, default=ROOT / ".cache/avml-reference")
    parser.add_argument("--input", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    binary = prepare(args.directory.resolve())
    if args.operation == "prepare":
        print(binary)
        return
    if args.input is None or args.output is None:
        parser.error("encode/decode require --input and --output")
    manifest = args.output.with_name(args.output.name + ".source.json")
    if args.output.exists() or manifest.exists():
        raise ValueError("reference output/manifest already exists; choose a new filename")
    input_hash = digest(args.input)
    subprocess.run([str(binary), args.operation, str(args.input), str(args.output)], check=True)
    if digest(args.input) != input_hash:
        raise ValueError("reference input changed during conversion")
    record = {"schema": "gomem.avml-reference/v1", "operation": args.operation, "avml_commit": COMMIT,
              "sources": {name: expected for name, (_, expected) in SOURCES.items()},
              "cargo_lock_sha256": digest(args.directory / "Cargo.lock"), "binary_sha256": digest(binary),
              "input_sha256": input_hash, "output_sha256": digest(args.output),
              "input_size": str(args.input.stat().st_size), "output_size": str(args.output.stat().st_size)}
    with manifest.open("x") as out:
        out.write(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
