#!/usr/bin/env python3
"""Evaluate byte-backed QEMU migration streams with the unmodified pinned layer."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import subprocess
import tempfile
import urllib.request
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/memory/testdata/qemu-oracle.json"
QEMU_SHA = "5d92df832acebee546695648f378dde7b303798effaaea17048ec6dd2f33a7c9"
QEMU_SCRIPT = ROOT / ".cache/qemu-analyze-migration-v9.2.0.py"
QEMU_URL = "https://raw.githubusercontent.com/qemu/qemu/v9.2.0/scripts/analyze-migration.py"

def qemu_reference(raw, expected):
    if not QEMU_SCRIPT.exists():
        QEMU_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(QEMU_URL, timeout=30) as response:
            data = response.read(1 << 20)
        if hashlib.sha256(data).hexdigest() != QEMU_SHA:
            raise ValueError("QEMU script hash differs")
        QEMU_SCRIPT.write_bytes(data)
    if hashlib.sha256(QEMU_SCRIPT.read_bytes()).hexdigest() != QEMU_SHA:
        raise ValueError("requires pinned unmodified QEMU analyzer")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "stream.qemu"
        path.write_bytes(raw)
        # The official v9.2.0 script retains a Python-2 ord(bytes-item) call.
        # Adapt only ord(int) for Python 3; the original source stays untouched.
        launcher = "import builtins,runpy,sys; original=builtins.ord; builtins.ord=lambda x:x if isinstance(x,int) else original(x); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
        completed = subprocess.run([sys.executable, "-c", launcher, str(QEMU_SCRIPT), "-f", str(path), "-m"], capture_output=True, text=True, timeout=30)
        if completed.returncode:
            raise ValueError(completed.stderr[-2000:])
        parsed = json.loads(completed.stdout)
    memory = parsed["ram (2)"]["memory"]
    reads = []
    for entry in expected:
        value = memory["pc.ram (0x%016x)" % int(entry["ram_address"], 0)]
        if value.startswith("Filled with 0x"):
            data = bytes([int(value[-2:], 16)]) * entry["size"]
        else:
            data = bytes.fromhex(value)
        reads.append(dict(address=entry["address"], sha256=hashlib.sha256(data).hexdigest()))
    return dict(reads=reads)


def section(kind, ident, name=None, version=1):
    data = bytes([kind]) + struct.pack(">I", ident)
    if name is not None:
        encoded = name.encode()
        data += bytes([len(encoded)]) + encoded + struct.pack(">II", 0, version)
    return data

def stream(machine="pc-i440fx-2.0", page_size=4096, fill=False, split=False, high=False, extra=False, continuation=True, fallback=False, update=False, device=None):
    data = bytearray(b"QEVM\0\0\0\3")
    if not fallback:
        data.extend(b"\x07" + struct.pack(">I", len(machine)) + machine.encode())
    # Length-prefixed opaque state makes the actual pinned tail search usable.
    data.extend(section(4, 1, "pbs-state") + struct.pack(">Q", 8192) + bytes(8192) + b"\x7e" + struct.pack(">I", 1))
    devices = [dict(name="pbs-state", instance_id=0, version=1, vmsd_name="PIIX3", fields=[dict(name="payload", type="buffer", size=8200)])]
    if device:
        fields = [dict(name="value", type="uint32", size=4)]
        payload = b"\x11\x22\x33\x44"
        subsections = []
        if device == "array":
            fields = [dict(name="values", type="uint16", size=2, array_len=3)]
            payload = b"\x11\x22\x33\x44\x55\x66"
        if device == "nested":
            fields = [dict(name="state", type="struct", array_len=2, struct=dict(fields=[dict(name="value", type="uint16", size=2)]))]
        if device == "subsection":
            subsections = [dict(vmsd_name="cpu/extra", version=2, fields=[dict(name="value", type="uint32", size=4)])]
            payload += b"\x05\x09cpu/extra" + struct.pack(">I", 2) + b"\x55\x66\x77\x88"
        devices.append(dict(name="cpu", instance_id=0, version=1, vmsd_name="cpu", fields=fields, subsections=subsections))
        data.extend(section(4, 3, "cpu", 1) + payload + b"\x7e" + struct.pack(">I", 3))
    data.extend(section(1 if split else 4, 2, "ram", 4))
    address = 0
    ram_size = page_size * 3
    if high:
        address = {"pc-q35-2.0": 0x80000000, "pc-i440fx-1.0": 0xe0000000, "microvm": 0xc0000000, "xen": 0xf0000000}.get(machine, 0xc0000000)
        ram_size = 0x100000000 + page_size
    sizes = [(b"pc.ram", ram_size)]
    if extra:
        sizes.append((b"video", page_size))
    data.extend(struct.pack(">Q", sum(size for _, size in sizes) | 4))
    for name, size in sizes:
        data.extend(bytes([len(name)]) + name + struct.pack(">Q", size))
    expected = []
    for i in range(2):
        if split and i == 1:
            data.extend(struct.pack(">Q", 16) + b"\x7e" + struct.pack(">I", 2))
            data.extend(section(3, 2))
        flags = 2 if fill else 8
        if i and continuation:
            flags |= 32
        data.extend(struct.pack(">Q", (address + i * page_size) | flags))
        if not i or not continuation:
            data.extend(b"\x06pc.ram")
        offset = len(data)
        payload = bytes([65 + i]) * (1 if fill else page_size)
        data.extend(payload)
        physical = address + i * page_size
        if high:
            hole_start = {"pc-q35-2.0": 0x80000000, "pc-i440fx-1.0": 0xe0000000, "microvm": 0xc0000000, "xen": 0xf0000000}.get(machine, 0xc0000000)
            physical += 0x100000000 - hole_start
        expected.append(dict(address=hex(physical), ram_address=hex(address + i * page_size), offset=offset, size=page_size, fill=fill,
                             sha256=hashlib.sha256(bytes([65 + i]) * page_size).hexdigest()))
    if extra:
        data.extend(struct.pack(">Q", 2) + b"\x05video" + b"V")
    if update:
        data.extend(struct.pack(">Q", address | 8) + b"\x06pc.ram")
        offset = len(data)
        data.extend(b"Z" * page_size)
        expected[0].update(offset=offset, fill=False, sha256=hashlib.sha256(b"Z" * page_size).hexdigest())
    data.extend(struct.pack(">Q", 16) + b"\x7e" + struct.pack(">I", 2) + b"\x00")
    config = json.dumps(dict(page_size=page_size, devices=devices), separators=(",", ":")).encode()
    data.extend(b"\x06" + struct.pack(">I", len(config)) + config)
    return bytes(data), expected

def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires unmodified pinned source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.qemu import QemuSuspendLayer
    cases = []
    controls = [("raw", {}), ("fill", dict(fill=True)), ("split-raw", dict(split=True)),
                ("split-fill", dict(split=True, fill=True)), ("named-pages", dict(continuation=False)),
                ("other-block", dict(extra=True)), ("large-page", dict(page_size=65536)),
                ("small-page", dict(page_size=512)), ("fallback", dict(fallback=True)),
                ("updated-raw", dict(update=True)), ("updated-fill", dict(update=True, fill=True))]
    for machine in ["pc-i440fx-2.0", "pc-i440fx-1.0", "pc-q35-2.0", "microvm", "xen"]:
        controls.append((machine + "-hole", dict(machine=machine, high=True)))
    for device in ["scalar", "array", "nested", "subsection"]:
        controls.append(("device-" + device, dict(device=device)))
    for name, options in controls:
        raw, expected = stream(**options)
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context, "physical", "physical", raw))
        context.config["qemu.base_layer"] = "physical"
        upstream = {}
        try:
            layer = QemuSuspendLayer(context, "qemu", "qemu")
            upstream["segments"] = [dict(address=hex(a), offset=o, size=n, stored=z) for a, o, n, z in layer._segments]
            upstream["reads"] = [dict(address=e["address"], sha256=hashlib.sha256(layer.read(int(e["address"], 0), e["size"])).hexdigest()) for e in expected]
        except Exception as exc:
            upstream["error"] = type(exc).__name__
        cases.append(dict(name=name, raw=base64.b64encode(raw).decode(), sha256=hashlib.sha256(raw).hexdigest(), expected=expected, upstream=upstream, qemu_reference=qemu_reference(raw, expected)))
    return json.dumps(dict(schema="gomem.qemu-oracle/v1", baseline_commit=COMMIT, python_tree_sha256=lock["python_tree_sha256"], qemu_analyzer_sha256=QEMU_SHA, qemu_analyzer_url=QEMU_URL, qemu_runtime_shim="ord(int) returns the integer under Python 3; no source or parser methods modified", cases=cases), indent=2) + "\n"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise SystemExit("QEMU oracle differs; regenerate")
    else:
        OUTPUT.write_text(result)
    print("20 byte-backed controls evaluated against pinned Volatility and actual QEMU v9.2.0 analyzer")
if __name__ == "__main__":
    main()
