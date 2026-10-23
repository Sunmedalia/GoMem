#!/usr/bin/env python3
"""Capture actual locked volshell integer displays from byte-backed layers."""
import argparse
import base64
import contextlib
import io
import json
from pathlib import Path
import random
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/explore/testdata/shell-integers-oracle.json"


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.cli.volshell.generic import Volshell

    cases = []
    rng = random.Random(20261023)
    for width, method in [(1, "display_bytes"), (2, "display_words"), (4, "display_doublewords"), (8, "display_quadwords")]:
        for order in ["<", ">"]:
            for address in [0, 3, 0x1000]:
                for count in [0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 128]:
                    data = (bytes(range(256)) if count == 128 else rng.randbytes(count))[:count]
                    ctx = contexts.Context()
                    ctx.layers.add_layer(BufferDataLayer(ctx, "ram", "ram", bytes(address) + data + b"\x00"))
                    ctx.config["shell.primary"] = "ram"
                    shell = Volshell(ctx, "shell")
                    out = io.StringIO()
                    error = ""
                    with contextlib.redirect_stdout(out):
                        try:
                            if width == 1:
                                shell.display_bytes(address, count=count)
                            else:
                                getattr(shell, method)(address, count=count, byteorder=order)
                        except exceptions.InvalidAddressException as exc:
                            error = type(exc).__name__
                    cases.append(dict(width=width, order=order, address=address,
                                      data=base64.b64encode(data).decode(), text=out.getvalue(), error=error))
    return dict(schema="gomem.shell-integers-oracle/v1", baseline_commit=COMMIT, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    text = json.dumps(result, indent=2) + "\n"
    if args.check:
        if OUTPUT.read_text() != text:
            raise SystemExit("shell integer oracle differs; regenerate")
    else:
        OUTPUT.parent.mkdir(exist_ok=True)
        OUTPUT.write_text(text)
    print(f"{len(result['cases'])} actual volshell integer displays verified")


if __name__ == "__main__":
    main()
