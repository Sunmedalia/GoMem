#!/usr/bin/env python3
"""Exercise locked Volatility disassembly and real Capstone without method mocks."""
import argparse
import base64
import json
import importlib.metadata
import random
from pathlib import Path
import sys
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/disasm/testdata/capstone-oracle.json"


def generate(source):
    import capstone
    # Upstream 5.0.9 retains __version__ = 5.0.7 in its Python module.
    # Check the installed distribution rather than that stale module constant.
    if importlib.metadata.version("capstone") != "5.0.9":
        raise ValueError("requires capstone 5.0.9")
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified Volatility source")
    sys.path.insert(0, str(source))
    from volatility3.cli.text_renderer import display_disassembly
    from volatility3.framework import renderers
    modes = dict(x86=(capstone.CS_ARCH_X86, capstone.CS_MODE_32), x64=(capstone.CS_ARCH_X86, capstone.CS_MODE_64), arm=(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM), arm64=(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM), thumb=(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB))
    samples = dict(x86=["", "4889d8c3", "e80500000090c3", "f30f1efa", "0f", "900f", "c5f877"], x64=["", "4889d8c3", "e80500000090c3", "f30f1efa", "0f", "900f", "c5f877"], arm=["", "1eff2fe1", "0000a0e1", "ff", "1eff2fe100"], arm64=["", "c0035fd6", "1f2003d5", "00", "c0035fd600"], thumb=["", "7047", "0120", "08bf0120", "f0", "7047f0"])
    cases = []
    rng = random.Random(20261023)
    for arch, mode in modes.items():
        inputs = [bytes.fromhex(value) for value in samples[arch]] + [rng.randbytes(16) for _ in range(12)]
        for address in [0x1000, 0x400000, 0xffff800000001000]:
            for index, data in enumerate(inputs):
                decoder = capstone.Cs(*mode)
                instructions = [dict(address=item.address, bytes=base64.b64encode(item.bytes).decode(), mnemonic=item.mnemonic, operands=item.op_str) for item in decoder.disasm(data, address)]
                text = "".join(f"\n{item['address']:#x}:\t{item['mnemonic']}\t{item['operands']}" for item in instructions)
                upstream = {"x86": "intel", "x64": "intel64", "arm": "arm", "arm64": "arm64"}.get(arch)
                if upstream is not None:
                    actual = display_disassembly(renderers.Disassembly(data, address, upstream))
                    if actual != text:
                        raise ValueError("actual fixed display_disassembly differs from direct Capstone")
                consumed = sum(len(base64.b64decode(item["bytes"])) for item in instructions)
                cases.append(dict(name=f"{arch}-{address:x}-{index}", arch=arch, address=address, data=base64.b64encode(data).decode(), instructions=instructions, text=text, consumed=consumed, incomplete=consumed != len(data), reference="actual-pinned-display-disassembly" if upstream else "direct-capstone-thumb"))
    return dict(schema="gomem.capstone-oracle/v1", baseline_commit=COMMIT, capstone="5.0.9", cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    value = json.dumps(result, indent=2) + "\n"
    if args.check:
        if OUTPUT.read_text() != value:
            raise SystemExit("Capstone oracle differs; regenerate")
    else:
        OUTPUT.parent.mkdir(exist_ok=True)
        OUTPUT.write_text(value)
    print(f"{len(result['cases'])} actual disassembly controls verified")


if __name__ == "__main__":
    main()
