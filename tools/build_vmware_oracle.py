#!/usr/bin/env python3
"""Build byte-backed VMware controls and invoke the actual pinned layer."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/memory/testdata/vmware-oracle.json"
MAGICS = [0xBED2BED0, 0xBAD1BAD1, 0xBED2BED2, 0xBED3BED3]


def pair(magic, width=4, extras=False, extended=62, regions=None, missing=False, duplicate=False, terminated=True, memory_pages=3):
    regions = regions if regions is not None else [(2, 0, 2), (8, 2, 1)]
    version = magic & 15
    tag_bytes = bytearray()
    def tag(name, value, index=None):
        name = name.encode()
        tag_bytes.extend(bytes([width | (64 if index is not None else 0), len(name)]) + name)
        if index is not None:
            tag_bytes.extend(struct.pack("<I", index))
        tag_bytes.extend(struct.pack("<I" if width == 4 else "<Q", value))
    if extras:
        for size in [0, 1, 2, 16]:
            name = b"unused"
            tag_bytes.extend(bytes([size, len(name)]) + name + bytes(size))
        name = b"indexed"
        tag_bytes.extend(bytes([0xC4, len(name)]) + name + struct.pack("<IIII", 1, 2, 3, 99))
        payload = b"extended-state" * 5100
        name = b"state"
        tag_bytes.extend(bytes([extended, len(name)]) + name)
        descriptor = "<IIH" if version == 0 else "<QQH"
        tag_bytes.extend(struct.pack(descriptor, len(payload), len(payload), 0) + payload)
    tag("regionsCount", len(regions))
    if duplicate:
        tag("regionsCount", len(regions))
    for i, (physical, stored, pages) in enumerate(regions):
        tag("regionPPN", physical, i)
        tag("regionPageNum", stored, i)
        if not missing or i != len(regions) - 1:
            tag("regionSize", pages, i)
    if terminated:
        tag_bytes.extend(b"\x00\x00")
    metadata = struct.pack("<III", magic, 0, 2) + struct.pack("<64sQQ", b"cpu", 172, 0) + struct.pack("<64sQQ", b"memory", 172, 0) + tag_bytes
    memory = b"".join(bytes([65 + i]) * 4096 for i in range(memory_pages))
    expected = []
    for physical, stored, pages in regions:
        expected.append(dict(address=hex(physical * 4096), offset=stored * 4096, size=pages * 4096,
                             sha256=hashlib.sha256(memory[stored * 4096:(stored + pages) * 4096]).hexdigest()))
    return memory, metadata, expected


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.vmware import VmwareLayer

    cases = []
    controls = []
    for magic in MAGICS:
        version = magic & 15
        for width in [4, 8]:
            controls.append((f"v{version}-u{width * 8}", magic, dict(width=width), False))
        for extended in [62, 63]:
            controls.append((f"v{version}-extended-{extended}", magic, dict(extras=True, extended=extended), False))
    controls.extend([
        ("unordered", MAGICS[2], dict(regions=[(8, 0, 1), (2, 1, 2)]), False),
        ("high-address", MAGICS[2], dict(width=8, regions=[(0x100000000000, 0, 1)]), False),
        ("zero-frame", MAGICS[2], dict(regions=[(0, 0, 3)]), False),
        ("missing-region-tag", MAGICS[2], dict(missing=True), True),
        ("duplicate-count", MAGICS[2], dict(duplicate=True), True),
        ("physical-overlap", MAGICS[2], dict(regions=[(2, 0, 2), (3, 2, 1)]), True),
        ("truncated-memory", MAGICS[2], dict(memory_pages=2), True),
        ("missing-terminator", MAGICS[2], dict(terminated=False), True),
        ("zero-regions", MAGICS[2], dict(regions=[]), True),
        ("overflow-frame", MAGICS[2], dict(width=8, regions=[(2**64 - 2, 0, 1)]), True),
    ])
    for name, magic, options, native_error in controls:
        memory, metadata, expected = pair(magic, **options)
        context = contexts.Context()
        for label, data in [("memory", memory), ("metadata", metadata)]:
            context.layers.add_layer(BufferDataLayer(context, label, label, data))
        context.config["vmware.base_layer"] = "memory"
        context.config["vmware.meta_layer"] = "metadata"
        result = {}
        try:
            layer = VmwareLayer(context, "vmware", "vmware")
            result["segments"] = [dict(address=hex(a), offset=o, size=n) for a, o, n, _ in layer._segments]
            result["reads"] = [dict(address=hex(a), sha256=hashlib.sha256(layer.read(a, n)).hexdigest()) for a, _, n, _ in layer._segments]
        except Exception as exc:
            result["error"] = type(exc).__name__
        cases.append(dict(name=name, memory=base64.b64encode(memory).decode(), metadata=base64.b64encode(metadata).decode(),
                          memory_sha256=hashlib.sha256(memory).hexdigest(), metadata_sha256=hashlib.sha256(metadata).hexdigest(),
                          native_error=native_error, expected=expected, upstream=result))
    return json.dumps(dict(schema="gomem.vmware-oracle/v1", baseline_commit=COMMIT, python_tree_sha256=lock["python_tree_sha256"],
                           scope="Actual pinned VmwareLayer, four signatures and byte-backed metadata; invalid controls retain divergences", cases=cases), ensure_ascii=False, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != text:
            raise SystemExit("VMware oracle differs; regenerate")
    else:
        OUTPUT.write_text(text)
    print("26 byte-backed VMware controls evaluated with the actual pinned layer")


if __name__ == "__main__":
    main()
