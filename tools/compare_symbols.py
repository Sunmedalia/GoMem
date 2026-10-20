#!/usr/bin/env python3
"""Compare selected ISF layouts without losing differences in memory bit ranges.

Typedef/anonymous names and minimal bitfield read widths are representational.
Enum base types are reported separately: some dwarf2json outputs use void as the
base even when DWARF supplies an integer. Constants and declared widths compare.
"""
import argparse
import hashlib
import json
import pathlib


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signature(ref, table):
    kind = ref["kind"]
    if kind == "base":
        base = table["base_types"][ref["name"]]
        return [kind, base["kind"], base["size"], base["signed"], base["endian"]]
    if kind in ("struct", "union", "class"):
        user = table["user_types"].get(ref["name"])
        if user is None:
            return ["unavailable_type", kind, ref["name"]]
        return [kind, user["size"]]
    if kind == "pointer":
        return [kind, table["base_types"][ref.get("base", "pointer")]["size"], signature(ref["subtype"], table)]
    if kind == "array":
        return [kind, ref["count"], signature(ref["subtype"], table)]
    if kind == "enum":
        enum = table["enums"][ref["name"]]
        return [kind, enum["size"], enum["constants"]]
    if kind == "bitfield":
        return [kind, ref["bit_length"]]
    return [kind]


def layout_key(user, table):
    fields = [["@anonymous" if f.get("anonymous") else name, f["offset"], signature(f["type"], table)] for name, f in user["fields"].items()]
    return json.dumps([user["kind"], user["size"], sorted(fields, key=lambda f: json.dumps(f, sort_keys=True))], sort_keys=True)


def scalar(ref, table):
    if ref["kind"] == "enum":
        enum = table["enums"][ref["name"]]
        base = table["base_types"][enum["base"]]
        return {**base, "size": enum["size"]}
    return table["base_types"][ref["name"]]


def normalized(ref, table, seen=None):
    seen = set() if seen is None else seen
    kind = ref["kind"]
    if kind == "base":
        return signature(ref, table)
    if kind == "pointer":
        # Compare the declared pointee shape without recursively traversing an
        # entire kernel object graph. Named targets are selected explicitly in
        # --types when their fields must also be checked.
        return signature(ref, table)
    if kind == "array":
        return [kind, ref["count"], normalized(ref["subtype"], table, seen)]
    if kind == "enum":
        enum = table["enums"][ref["name"]]
        return [kind, enum["size"], enum["constants"]]
    if kind in ("struct", "union", "class"):
        user = table["user_types"][ref["name"]]
        key = layout_key(user, table)
        if key in seen:
            return ["recursive", user["kind"], user["size"]]
        fields = {}

        def members(current, offset=0, depth=0):
            if depth > 128:
                raise ValueError("anonymous layout depth limit")
            for name, field in current["fields"].items():
                if field.get("anonymous"):
                    members(table["user_types"][field["type"]["name"]], offset + field["offset"], depth + 1)
                    continue
                if name in fields:
                    raise ValueError("ambiguous field")
                descriptor = field["type"]
                address = offset + field["offset"]
                if descriptor["kind"] == "bitfield":
                    base = scalar(descriptor["type"], table)
                    position = descriptor["bit_position"]
                    length = descriptor["bit_length"]
                    bit_address = address * 8 + (position if base["endian"] == "little" else base["size"] * 8 - position - length)
                    fields[name] = {"memory_bit_offset": bit_address, "bits": length, "signed": base["signed"]}
                else:
                    fields[name] = {"byte_offset": address, "type": normalized(descriptor, table, seen | {key})}

        members(user)
        return [user["kind"], user["size"], fields]
    return [kind]


def compare(native_path, reference_path, types, symbol_names=("init_task", "answer", "linux_banner", "version")):
    native, reference = [json.loads(path.read_text()) for path in (native_path, reference_path)]
    differences = {}
    for name in types:
        a = normalized({"kind": native["user_types"][name]["kind"], "name": name}, native)
        b = normalized({"kind": reference["user_types"][name]["kind"], "name": name}, reference)
        if a != b:
            differences[name] = {"native": a, "reference": b}
    symbol_differences = {name: [native["symbols"].get(name, {}).get("address"), reference["symbols"].get(name, {}).get("address")]
                          for name in symbol_names if native["symbols"].get(name, {}).get("address") != reference["symbols"].get(name, {}).get("address")}
    return {"scope": {"types": types, "symbol_addresses": list(symbol_names), "enum_base_metadata_compared": False,
                      "pointer_target_fields_compared": False},
            "matched": not differences and not symbol_differences, "type_differences": differences,
            "symbol_differences": symbol_differences, "sha256": {"native": digest(native_path), "reference": digest(reference_path)}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", type=pathlib.Path, required=True)
    parser.add_argument("--reference", type=pathlib.Path, required=True)
    parser.add_argument("--types", nargs="+", default=["task_struct", "flags", "packed_flags"])
    parser.add_argument("--symbols", nargs="+", default=["init_task", "answer", "linux_banner", "version"])
    args = parser.parse_args()
    result = compare(args.native, args.reference, args.types, args.symbols)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["matched"] else 1)


if __name__ == "__main__":
    main()
