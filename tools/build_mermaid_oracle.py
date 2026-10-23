#!/usr/bin/env python3
"""Render actual pinned TreeGrids; no upstream method replacements."""
import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/render/testdata/mermaid-oracle.json"


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.cli.text_renderer import MermaidRenderer
    from volatility3.framework import renderers

    cases = []
    for name, depths, names in [
        ("empty", [], []),
        ("flat", [0, 0, 0], ["same", "same", "last"]),
        ("tree", [0, 1, 2, 1, 0], ["root", "child", "leaf", "sibling", "root2"]),
        ("deep", [0, 1, 2, 3, 0, 1], ["a", "b", "c", "d", "e", "f"]),
        ("quoted", [0, 1], ['name"value', "line1\nline2"]),
        ("unicode", [0, 1], ["进程", "内核模块"]),
    ]:
        rows = [(depth, [index + 1, text]) for index, (depth, text) in enumerate(zip(depths, names))]
        grid = renderers.TreeGrid([("PID", int), ("Name", str)], iter(rows))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            MermaidRenderer().render(grid)
        cases.append(dict(name=name, rows=[dict(depth=d, pid=v[0], name=v[1]) for d, v in rows], output=out.getvalue()))
    return dict(schema="gomem.mermaid-oracle/v1", baseline_commit=COMMIT,
                python_tree_sha256=lock["python_tree_sha256"],
                scope="actual pinned TreeGrid/MermaidRenderer; selected scalar columns and trees only", cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = json.dumps(generate(args.source), ensure_ascii=False, indent=2) + "\n"
    if args.check:
        if OUTPUT.read_text() != text:
            raise SystemExit("Mermaid oracle differs; regenerate")
    else:
        OUTPUT.parent.mkdir(exist_ok=True)
        OUTPUT.write_text(text)
    print("6 pinned Mermaid renderer controls verified")


if __name__ == "__main__":
    main()
