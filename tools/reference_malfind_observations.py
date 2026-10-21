#!/usr/bin/env python3
"""Observe the locked Malfind executable-page probes without changing selection.

The unmodified full-plugin run remains authoritative for finding rows. This
separate delegated probe records translation failures, leaf states and actual
probe counts, so an empty finding list is not mistaken for complete coverage.
"""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import struct
import sys

from baseline_matrix import ROOT, tree_digest
from reference import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "image", "symbols", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(args.source) != lock["python_tree_sha256"]:
        raise ValueError("Malfind observations require pinned source")
    config = args.output.with_suffix(".config.json")
    plugin_output = args.output.with_suffix(".plugin.json")
    manifest = args.output.with_suffix(".manifest.json")
    if any(p.exists() for p in (args.output, config, plugin_output, manifest)):
        raise ValueError("choose new output paths; never overwrite")
    image_hash = digest(args.image)
    sys.path.insert(0, str(args.source.resolve()))
    import volatility3.cli
    from volatility3.plugins.linux.malware.malfind import Malfind
    from volatility3.framework import exceptions

    original_list = Malfind._list_injections
    original_dirty = Malfind._get_dirty_pages
    rows = []

    def observing_list(self, task):
        self.observed_task = task
        yield from original_list(self, task)

    def observing_dirty(self, layer, vma):
        probes = missing = dirty = 0
        first_missing = last_missing = 0
        states = hashlib.sha256()

        class ObservedLayer:
            page_size = layer.page_size

            @staticmethod
            def _translate(address):
                nonlocal probes, missing, first_missing, last_missing
                probes += 1
                try:
                    value = layer._translate(address)
                except (AttributeError, exceptions.InvalidAddressException):
                    missing += 1
                    if missing == 1:
                        first_missing = address
                    last_missing = address
                    states.update(struct.pack("<QQ", address, (1 << 64) - 1))
                    raise
                entry, _ = layer._translate_entry(address & layer.page_mask)
                states.update(struct.pack("<QQQQ", address, value[1], entry, layer._entry_size))
                return value

            @staticmethod
            def is_dirty(address):
                return layer.is_dirty(address)

        for value in original_dirty(self, ObservedLayer(), vma):
            dirty += 1
            yield value
        rows.append(dict(PID=int(self.observed_task.pid), Start=int(vma.vm_start), End=int(vma.vm_end),
                         Probes=probes, MissingPages=missing, DirtyPages=dirty,
                         FirstMissing=first_missing, LastMissing=last_missing,
                         StateDigest=states.hexdigest()))

    Malfind._list_injections = observing_list
    Malfind._get_dirty_pages = observing_dirty
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sys.argv = ["vol.py", "--offline", "-q", "--cache-path", str(ROOT / ".cache/reference-cache"),
                "-s", str(args.symbols.resolve()), "-f", str(args.image.resolve()),
                "--save-config", str(config.resolve()), "-r", "json", "linux.malware.malfind.Malfind"]
    with plugin_output.open("x") as out, contextlib.redirect_stdout(out):
        volatility3.cli.main()
    if not rows or not isinstance(json.loads(plugin_output.read_text()), list):
        raise ValueError("Malfind observation run did not inspect executable mappings")
    if tree_digest(args.source) != lock["python_tree_sha256"] or digest(args.image) != image_hash:
        raise ValueError("source or image changed during observation")
    with args.output.open("x") as out:
        out.write(json.dumps(rows, indent=2) + "\n")
    manifest.write_text(json.dumps(dict(scope=__doc__, baseline=lock, image_sha256=image_hash,
                                       output_sha256=digest(args.output), plugin_output_sha256=digest(plugin_output),
                                       config_sha256=digest(config), probe_sha256=digest(Path(__file__)),
                                       observed_mappings=len(rows), python=sys.version), indent=2) + "\n")
    print(f"{len(rows)} delegated executable mapping scans observed; separate unmodified output required")


if __name__ == "__main__":
    main()
