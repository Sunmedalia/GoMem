#!/usr/bin/env python3
"""Compare actual locked ArrowRenderer output after independent PyArrow decoding."""
import argparse
import base64
import contextlib
import io
import json
import sys
from pathlib import Path
from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/render/testdata/arrow-oracle.json"


def generate(source):
    import pyarrow as pa
    if pa.__version__ != "26.0.0":
        raise ValueError("requires pyarrow 26.0.0")
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires unmodified locked source")
    sys.path.insert(0, str(source))
    from volatility3.framework import renderers
    from volatility3.framework.renderers import format_hints
    from volatility3.plugins.renderers.parquet_renderer import ArrowRenderer
    columns = [("Signed", int), ("Address", format_hints.Hex), ("Name", str), ("Flag", bool), ("Bytes", bytes)]
    cases = []
    for name, depths in [("empty", []), ("flat", [0, 0, 0]), ("tree", [0, 1, 2, 1, 0]), ("deep", [0, 1, 2, 3]), ("missing", [0, 1]), ("unicode", [0, 1])]:
        rows = []
        for index, depth in enumerate(depths):
            if name == "missing" and index == 1:
                values = [renderers.UnreadableValue() for _ in columns]
            else:
                values = [-(1 << 63) if index == 0 else (1 << 63) - 1, format_hints.Hex((1 << 64) - 1 - index), "" if index == 0 else "进程\nquoted\"value", index % 2 == 1, bytes([0, 255, index])]
            rows.append((depth, values))
        grid = renderers.TreeGrid(columns, iter(rows))
        binary = io.BytesIO()
        text = io.TextIOWrapper(binary, encoding="utf-8")
        with contextlib.redirect_stdout(text):
            ArrowRenderer().render(grid)
        table = pa.ipc.open_stream(binary.getvalue()).read_all()
        table.validate(full=True)
        decoded = table.to_pylist()
        for row in decoded:
            if row["Bytes"] is not None:
                row["Bytes"] = base64.b64encode(row["Bytes"]).decode()
            if row["Address"] is not None:
                row["Address"] = f"0x{row['Address']:016x}"
        cases.append(dict(name=name, depths=depths, rows=decoded))
    return dict(schema="gomem.arrow-oracle/v1", baseline_commit=COMMIT, pyarrow=pa.__version__, scope="selected actual ArrowRenderer scalars, nulls and tree links; addresses normalized as hexadecimal", cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    value = json.dumps(generate(args.source), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if OUTPUT.read_text() != value:
            raise SystemExit("Arrow oracle differs; regenerate")
    else:
        OUTPUT.write_text(value)
    print("6 actual pinned ArrowRenderer/PyArrow controls verified")


if __name__ == "__main__":
    main()
