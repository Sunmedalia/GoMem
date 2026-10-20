#!/usr/bin/env python3
"""Compare selected native region files with locked-reference extracted bytes.

Runtime forensics remains Go-only. This developer tool reads case-owned files
and a reference manifest; it never normalizes gaps or certifies whole plugins.
"""
import argparse
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def member(directory, name):
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or "\\" in name:
        raise ValueError("unsafe extraction member path")
    result = (directory / str(relative)).resolve()
    if not result.is_relative_to(directory.resolve()) or not result.is_file():
        raise ValueError("extraction is outside its directory or absent")
    return result


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def compare(native, case, reference_manifest, reference_dir, name_map=None):
    reference = json.loads(reference_manifest.read_text())
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if reference["baseline"] != lock:
        raise ValueError("extraction reference is not the locked baseline")
    entries = reference["extracted_files"]
    expected = {e["name"]: e for e in entries}
    name_map = {} if name_map is None else name_map
    if not isinstance(name_map, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in name_map.items()):
        raise ValueError("name mapping must explicitly map native to reference file names")
    if len(expected) != len(entries):
        raise ValueError("duplicate reference file names")
    for name, entry in expected.items():
        file = member(reference_dir, name)
        if file.stat().st_size != int(entry["size"]) or digest(file) != entry["sha256"]:
            raise ValueError("reference extraction checksum/size mismatch")
    results, seen = [], set()
    for line in native.read_text().splitlines():
        row = json.loads(line)
        cell = row["cells"]["FileOutput"]
        if cell["kind"] != "artifact":
            raise ValueError("selected region did not produce an artifact")
        a = cell["value"]
        if a["state"] not in ("completed", "completed_with_gaps"):
            raise ValueError("selected region extraction is incomplete")
        reference_name = name_map.get(a["name"], a["name"])
        if reference_name in seen or reference_name not in expected:
            raise ValueError("unexpected or duplicate native file name")
        seen.add(reference_name)
        file, gaps = member(case, a["path"]), member(case, a["gaps_path"])
        if file.stat().st_size != int(a["size"]) or digest(file) != a["sha256"]:
            raise ValueError("native extraction checksum/size mismatch")
        if gaps.stat().st_size != int(a["gaps_size"]) or digest(gaps) != a["gaps_sha256"]:
            raise ValueError("native padding log checksum/size mismatch")
        for key in ("image_sha256", "engine_build", "symbols_sha256", "plugin", "parameters"):
            if a["provenance"].get(key) != row["provenance"].get(key):
                raise ValueError("native extraction provenance mismatch")
        if a["provenance"]["image_sha256"] != reference["image_sha256"]:
            raise ValueError("native/reference image mismatch")
        other = expected[reference_name]
        differences, first_offsets, offset = 0, [], 0
        with file.open("rb") as left, member(reference_dir, reference_name).open("rb") as right:
            while True:
                x, y = left.read(1 << 20), right.read(1 << 20)
                if x != y:
                    for i in range(max(len(x), len(y))):
                        if i >= len(x) or i >= len(y) or x[i] != y[i]:
                            differences += 1
                            if len(first_offsets) < 32:
                                first_offsets.append(hex(offset + i))
                if not x and not y:
                    break
                offset += max(len(x), len(y))
        results.append({"name": a["name"], "reference_name": reference_name, "size": a["size"], "reference_size": other["size"],
                        "native_sha256": a["sha256"], "reference_sha256": other["sha256"],
                        "bytes_equal": differences == 0, "differing_bytes": differences, "first_differing_offsets": first_offsets,
                        "state": a["state"], "missing_bytes": a["missing_bytes"],
                        "gap_count": a["gap_count"], "gaps_sha256": a["gaps_sha256"],
                        "image_sha256": a["provenance"]["image_sha256"],
                        "engine_build_sha256": a["provenance"]["engine_build"],
                        "symbols_sha256": a["provenance"]["symbols_sha256"],
                        "layer": a["provenance"]["layer"], "offset": a["provenance"]["offset"]})
    return {"scope": "Selected extracted regions only; padding is explicit and full capability acceptance remains pending",
            "baseline_commit": lock["commit"], "reference_parameters": reference["parameters"],
            "native_files": len(results), "reference_files": len(expected),
            "explicit_file_name_mapping": name_map,
            "matched": bool(results) and seen == set(expected) and all(r["bytes_equal"] for r in results),
            "files": results, "native_rows_sha256": digest(native), "reference_manifest_sha256": digest(reference_manifest)}


def main():
    parser = argparse.ArgumentParser()
    for name in ("native", "case", "reference-manifest", "reference-dir", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--name-map", type=pathlib.Path, help="Explicit native-to-reference name mapping; bytes remain unchanged")
    args = parser.parse_args()
    report = compare(args.native, args.case, args.reference_manifest, args.reference_dir,
                     json.loads(args.name_map.read_text()) if args.name_map else None)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if not report["matched"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
