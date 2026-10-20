#!/usr/bin/env python3
"""Compare exact multisets using an explicit, reviewable field mapping.

Reports selected-field parity only. Never certifies an entire capability. Missing
values, duplicate rows and parent relationships are preserved in comparisons.
"""
import argparse
import collections
import hashlib
import json
import pathlib


def load_rows(path, native):
    if native:
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("reference output must be a JSON TreeGrid array")
    return data


def normalized(value, kind, mask=None):
    if isinstance(value, dict) and "kind" in value:
        if value["kind"] == "missing":
            return {"missing": value.get("reason"), "error": value.get("error")}
        value = value.get("value")
    if value is None:
        return {"missing": "reference-null"}
    if kind in ("address", "uint64"):
        number = int(value, 0) if isinstance(value, str) and value.lower().startswith("0x") else int(value)
        if mask is not None:
            number &= int(mask, 0)
        return str(number)
    return value


def compare(native_path, reference_path, mapping_path):
    mapping = json.loads(mapping_path.read_text())
    native = load_rows(native_path, True)
    reference = load_rows(reference_path, False)
    fields = mapping["fields"]

    def field_values(row, native):
        result = {}
        for name, field in fields.items():
            source = row["cells"] if native else row
            key = field["native" if native else "reference"]
            if key not in source:
                raise ValueError(f"missing mapped column {key}")
            result[name] = normalized(source[key], field["kind"], field.get("mask"))
        return result

    native_ids = {row["id"]: row for row in native if row.get("id")}

    def record(row, native, parent=None):
        result = field_values(row, native)
        if native and row.get("parent_id"):
            if "tree_key" not in mapping:
                raise ValueError("hierarchical output requires an explicit tree_key profile")
            if row["parent_id"] not in native_ids:
                raise ValueError("native parent evidence is absent from the comparison")
            parent = field_values(native_ids[row["parent_id"]], True)[mapping["tree_key"]]
        result["parent"] = parent
        return json.dumps(result, sort_keys=True)

    def walk(rows, parent=None):
        for row in rows:
            yield record(row, False, parent)
            children = row.get("__children", [])
            if not isinstance(children, list):
                raise ValueError("invalid reference child list")
            # Parent keys are explicit in the profile, never silently discarded.
            if children and "tree_key" not in mapping:
                raise ValueError("hierarchical output requires an explicit tree_key profile")
            yield from walk(children, field_values(row, False)[mapping["tree_key"]] if children else None)

    a = collections.Counter(record(r, True) for r in native)
    b = collections.Counter(walk(reference))
    missing = list((b - a).elements())
    extra = list((a - b).elements())
    hashes = {}
    for key, path in (("native", native_path), ("reference", reference_path), ("mapping", mapping_path)):
        hashes[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"scope": "selected fields only; full capability acceptance remains pending", "fields": list(fields),
            "native_rows": sum(a.values()), "reference_rows": sum(b.values()), "matched": not missing and not extra,
            "missing": [json.loads(s) for s in missing], "extra": [json.loads(s) for s in extra], "sha256": hashes}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", type=pathlib.Path, required=True)
    parser.add_argument("--reference", type=pathlib.Path, required=True)
    parser.add_argument("--mapping", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    result = compare(args.native, args.reference, args.mapping)
    report = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
    else:
        print(report, end="")
    raise SystemExit(0 if result["matched"] else 1)


if __name__ == "__main__":
    main()
