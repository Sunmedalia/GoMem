#!/usr/bin/env python3
"""Construct Xen ELF cores and run the unmodified pinned Xen layer."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/memory/testdata/xen-oracle.json"


def core(frames, p2m=False, page_size=4096, notes=False, big=False, reorder_names=False):
    endian = ">" if big else "<"
    pack = lambda fmt, *values: struct.pack(endian + fmt, *values)
    stride = 16 if p2m else 8
    entries = b"".join(pack("QQ", n, (2**64 - 1 if n == 2**64 - 1 else n + 100)) if p2m else pack("Q", n) for n in frames)
    names = ["", ".shstrtab", ".xen_p2m" if p2m else ".xen_pfn", ".xen_pages"]
    if notes:
        names.append(".note.Xen")
    string_names = list(names)
    if reorder_names:
        string_names[2], string_names[3] = string_names[3], string_names[2]
    strings = b"\x00".join(n.encode() for n in string_names) + b"\x00"
    sections = [(".shstrtab", 3, strings), (names[2], 1, entries), (".xen_pages", 1, b"".join(bytes([65 + i % 26]) * page_size for i in range(len(frames))))]
    if notes:
        def note(kind, desc):
            return pack("III", 4, len(desc), kind) + b"Xen\x00" + desc + b"\x00" * (-len(desc) % 4)
        payload = note(0x2000000, b"") + note(0x2000001, pack("QQQQ", 0xF00FEBED if p2m else 0xF00FEBEE, 2, len(frames), page_size)) + note(0x2000003, pack("Q", 1))
        sections.append((".note.Xen", 7, payload))
    shnum = len(sections) + 1
    data = bytearray(64 + 64 * shnum)
    data[:16] = b"\x7fELF" + bytes([2, 2 if big else 1, 1]) + bytes(9)
    data[16:64] = pack("HHIQQQIHHHHHH", 4, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, shnum, 1)
    locations = {}
    for i, (name, kind, body) in enumerate(sections, 1):
        alignment = 4096 if name == ".xen_pages" else 16
        data.extend(bytes(-len(data) % alignment))
        location = len(data)
        data.extend(body)
        name_offset = strings.index(name.encode() + b"\x00")
        data[64 + 64 * i:128 + 64 * i] = pack("IIQQQQIIQQ", name_offset, kind, 0, 0, location, len(body), 0, 0, alignment, stride if name in (".xen_pfn", ".xen_p2m") else 0)
        locations[name] = location
    expected = []
    for i, frame in enumerate(frames):
        invalid = frame == 2**64 - 1 or (not notes and frame == 0xFFFFFFFF)
        if invalid:
            continue
        expected.append(dict(address=hex(frame * page_size), offset=locations[".xen_pages"] + i * page_size, size=page_size, sha256=hashlib.sha256(bytes([65 + i % 26]) * page_size).hexdigest()))
    return bytes(data), expected, locations


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.xen import XenCoreDumpLayer

    cases = []
    for name, frames, options in [
        ("pfn-basic", [1, 2, 5], {}),
        ("pfn-zero", [0, 2], {}),
        ("pfn-invalid32", [1, 0xFFFFFFFF, 3], {}),
        ("pfn-invalid64", [1, 2**64 - 1, 3], {}),
        ("p2m-basic", [1, 3], dict(p2m=True)),
        ("p2m-zero-invalid", [0, 2**64 - 1, 4], dict(p2m=True, notes=True)),
        ("notes-pfn", [1, 2, 5], dict(notes=True)),
        ("notes-high-valid-pfn", [0xFFFFFFFF], dict(notes=True)),
        ("notes-64k", [1, 2], dict(notes=True, page_size=65536)),
        ("big-endian", [1, 3], dict(notes=True, big=True)),
        ("section-name-order", [1, 3], dict(reorder_names=True)),
    ]:
        data, expected, locations = core(frames, **options)
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context, "physical", "physical", data))
        context.config["xen.base_layer"] = "physical"
        result = {}
        try:
            layer = XenCoreDumpLayer(context, "xen", "xen")
            segments = [dict(address=hex(a), offset=o, size=n) for a, o, n, _ in layer._segments]
            result["segments"] = segments[:16]
            result["segments_count"] = len(segments)
            result["segments_sha256"] = hashlib.sha256(json.dumps(segments, sort_keys=True).encode()).hexdigest()
            result["reads"] = [dict(address=hex(a), sha256=hashlib.sha256(layer.read(a, n)).hexdigest()) for a, _, n, _ in layer._segments]
        except Exception as exc:
            result["error"] = type(exc).__name__
        cases.append(dict(name=name, raw=base64.b64encode(data).decode(), sha256=hashlib.sha256(data).hexdigest(), expected=expected, locations=locations, options=options, upstream=result))
    return json.dumps(dict(schema="gomem.xen-oracle/v1", baseline_commit=COMMIT, python_tree_sha256=lock["python_tree_sha256"],
                           scope="Actual pinned XenCoreDumpLayer plus independently specified guest-physical bytes; divergences are explicit, not accepted parity", cases=cases), ensure_ascii=False, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != text:
            raise SystemExit("Xen oracle differs; regenerate")
    else:
        OUTPUT.write_text(text)
    print("11 Xen core controls evaluated against actual pinned layer; differences retained")


if __name__ == "__main__":
    main()
