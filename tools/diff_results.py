#!/usr/bin/env python3
"""Compare exact multisets using an explicit, reviewable field mapping.

Reports selected-field parity only. Never certifies an entire capability. Missing
values, duplicate rows and parent relationships are preserved in comparisons.
"""
import base64
import argparse
import collections
import hashlib
import json
import pathlib
import datetime
import re


def load_rows(path, native):
    if native:
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("reference output must be a JSON TreeGrid array")
    return data


def normalized(value, kind, mask=None, missing_reasons=()):
    source_kind = value.get("kind") if isinstance(value, dict) else None
    if isinstance(value, dict) and "kind" in value:
        if value["kind"] == "missing":
            if value.get("reason") in missing_reasons and not value.get("error"):
                return {"missing": "reference-null"}
            return {"missing": value.get("reason"), "error": value.get("error")}
        value = value.get("value")
    if value is None:
        return {"missing": "reference-null"}
    if kind == "hex_bytes":
        if source_kind == "bytes" and isinstance(value, str):
            return base64.b64decode(value, validate=True).hex()
        if isinstance(value, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}(?: +|$))*", value):
            return bytes.fromhex(value).hex()
        raise ValueError("hex_bytes requires typed base64 bytes or space-separated hexadecimal")
    if kind == "artifact_name":
        # This profile compares the displayed filename only. File contents,
        # state, hashes and gap provenance require separate extraction checks.
        if isinstance(value, dict) and isinstance(value.get("name"), str):
            return value["name"]
        if isinstance(value, str):
            return value
        raise ValueError("artifact_name requires a filename or artifact object")
    if kind in ("address", "uint64", "int64"):
        number = int(value, 0) if isinstance(value, str) and value.lower().startswith("0x") else int(value)
        if mask is not None:
            number &= int(mask, 0)
        # Signed fields such as Windows loader counts retain their sign.
        if kind == "int64" and not -(1 << 63) <= number < 1 << 63:
            raise ValueError("signed result exceeds int64")
        return str(number)
    if kind == "timestamp_seconds":
        stamp = datetime.datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            raise ValueError("timestamp comparison requires an explicit timezone")
        return stamp.astimezone(datetime.timezone.utc).replace(microsecond=0).isoformat()
    if kind == "timestamp_microseconds_rounded":
        # Go retains nanoseconds; Python datetime displays microseconds. This
        # profile explicitly rounds ties to even without a floating-point epoch.
        match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", value)
        if match is None:
            raise ValueError("microsecond timestamp comparison requires an explicit timezone and at most 9 fractional digits")
        base = datetime.datetime.fromisoformat(match[1] + match[3])
        nanos = int((match[2] or "").ljust(9, "0"))
        micros, remainder = divmod(nanos, 1000)
        if remainder > 500 or remainder == 500 and micros % 2:
            micros += 1
        return (base + datetime.timedelta(microseconds=micros)).astimezone(datetime.timezone.utc).isoformat(timespec="microseconds")
    if kind == "bool":
        if isinstance(value, bool):
            return "true" if value else "false"
        raise ValueError("bool comparison requires a JSON boolean")
    if kind == "linux_path_display" and isinstance(value, str):
        # The pinned Linux path renderer prefixes deleted absolute paths with
        # one display space. Preserve spaces inside filenames and unmarked paths.
        if value.startswith(" /") and value.endswith(" (deleted)"):
            return value[1:]
    return value


def compare(native_path, reference_path, mapping_path):
    mapping = json.loads(mapping_path.read_text())
    native = [] if "native_record_type" in mapping else load_rows(native_path, True)
    reference = load_rows(reference_path, False)
    fields = mapping["fields"]

    # Some native plugins retain diagnostic records that the reference silently
    # skips. Entity profiles must declare those record types and report their
    # counts. Never discard rows with an unrecognized type or missing selector.
    input_rows = len(native)
    excluded = collections.Counter()
    if "native_record_type" in mapping:
        selector = mapping["native_record_type"]
        if "value" in selector and "values" in selector:
            raise ValueError("record-type selector cannot contain both value and values")
        values = selector.get("values", [selector.get("value")])
        if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values) or len(values) != len(set(values)) or set(values) & set(selector["excluded_values"]):
            raise ValueError("invalid record-type selection values")
        selected = []
        def native_records():
            with native_path.open(encoding="utf-8") as source:
                for line in source:
                    if line.strip():
                        yield json.loads(line)
        for row in native_records():
            input_rows += 1
            cell = row["cells"][selector["field"]]
            if cell["kind"] != "string":
                raise ValueError("invalid native record-type selector")
            if cell["value"] in values:
                selected.append(row)
            elif cell["value"] in selector["excluded_values"]:
                excluded[cell["value"]] += 1
            else:
                raise ValueError("unexpected native record type")
        native = selected

    def field_values(row, native, depth=0):
        result = {}
        for name, field in fields.items():
            if field.get("kind") == "tree_depth":
                if "native" not in field:
                    raise ValueError("tree depth needs a native column")
                if native:
                    source = row["cells"]
                    key = field["native"]
                    if key not in source:
                        raise ValueError(f"missing mapped column {key}")
                    result[name] = normalized(source[key], "uint64")
                else:
                    result[name] = str(depth)
                continue
            source = row["cells"] if native else row
            key = field["native" if native else "reference"]
            if key not in source:
                raise ValueError(f"missing mapped column {key}")
            result[name] = normalized(source[key], field["kind"], field.get("mask"), field.get("missing_reasons", ()))
        return result

    tree_key = mapping.get("tree_key")
    tree_path = mapping.get("tree_path", False)
    if "tree_key" in mapping:
        keys = tree_key if isinstance(tree_key, list) else [tree_key]
        if not keys or any(not isinstance(k, str) or k not in fields for k in keys) or len(keys) != len(set(keys)):
            raise ValueError("invalid tree_key columns")
    if not isinstance(tree_path, bool) or tree_path and tree_key is None:
        raise ValueError("tree_path requires an explicit tree_key profile")

    def node_key(row, native, depth=0):
        values = field_values(row, native, depth)
        return [values[k] for k in tree_key] if isinstance(tree_key, list) else values[tree_key]

    native_ids = {row["id"]: row for row in native if row.get("id")}
    if tree_path and len(native_ids) != len(native):
        raise ValueError("tree_path requires unique native evidence IDs")

    def native_parent(row):
        path, seen = [], set()
        while row.get("parent_id"):
            parent_id = row["parent_id"]
            if parent_id in seen:
                raise ValueError("cycle in native parent evidence")
            seen.add(parent_id)
            if parent_id not in native_ids:
                raise ValueError("native parent evidence is absent from the comparison")
            row = native_ids[parent_id]
            path.append(node_key(row, True))
            if not tree_path:
                return path[0]
        return list(reversed(path)) if path else None

    def record(row, native, parent=None, depth=0):
        result = field_values(row, native, depth)
        if native and row.get("parent_id"):
            if "tree_key" not in mapping:
                raise ValueError("hierarchical output requires an explicit tree_key profile")
            parent = native_parent(row)
        result["parent"] = parent
        return json.dumps(result, sort_keys=True)

    def walk(rows, parent=None, depth=0):
        for row in rows:
            yield record(row, False, parent, depth)
            children = row.get("__children", [])
            if not isinstance(children, list):
                raise ValueError("invalid reference child list")
            # Parent keys are explicit in the profile, never silently discarded.
            if children and "tree_key" not in mapping:
                raise ValueError("hierarchical output requires an explicit tree_key profile")
            next_parent = None
            if children:
                key = node_key(row, False, depth)
                next_parent = (parent or []) + [key] if tree_path else key
            yield from walk(children, next_parent, depth + 1)

    a = collections.Counter(record(r, True) for r in native)
    b = collections.Counter(walk(reference))
    missing = list((b - a).elements())
    extra = list((a - b).elements())
    hashes = {}
    for key, path in (("native", native_path), ("reference", reference_path), ("mapping", mapping_path)):
        with path.open("rb") as source:
            hashes[key] = hashlib.file_digest(source, "sha256").hexdigest()
    report = {"scope": "selected fields only; full capability acceptance remains pending", "fields": list(fields),
            "native_rows": sum(a.values()), "reference_rows": sum(b.values()), "matched": not missing and not extra,
            "missing": [json.loads(s) for s in missing], "extra": [json.loads(s) for s in extra], "sha256": hashes}
    if "native_record_type" in mapping:
        report.update(native_input_rows=input_rows, native_non_entity_records=dict(excluded),
                      entity_selection=mapping["native_record_type"])
    return report


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
