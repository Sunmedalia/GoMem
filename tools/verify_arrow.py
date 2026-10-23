#!/usr/bin/env python3
"""Independently validate GoMem IPC streams and lossless evidence using PyArrow."""
import argparse
import base64
import json
from pathlib import Path
import pyarrow as pa


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    args = parser.parse_args()
    if pa.__version__ != "26.0.0":
        raise ValueError("requires pyarrow 26.0.0")
    with args.input.open("rb") as stream:
        table = pa.ipc.open_stream(stream).read_all()
    table.validate(full=True)
    metadata = table.schema.metadata
    if metadata[b"gomem.schema"] != b"gomem.arrow-evidence/v1":
        raise ValueError("wrong schema")
    columns = json.loads(metadata[b"gomem.columns"])
    expected = json.loads(args.expected.read_text())
    decoded = table.to_pylist()
    if len(expected) != len(decoded):
        raise ValueError("row count mismatch")
    for reference, row in zip(expected, decoded):
        evidence = json.loads(row["_gomem_evidence"])
        if evidence != reference:
            raise ValueError("evidence differs")
        if row["_gomem_id"] != evidence["id"] or row["_gomem_parent_id"] != evidence.get("parent_id"):
            raise ValueError("tree identity mismatch")
        for column in columns:
            kind, name = column["kind"], column["name"]
            value = evidence["cells"].get(name)
            data = value.get("value") if value else None
            if value is None or value["kind"] == "missing":
                want = None
            elif kind in ("uint64", "int64", "integer"):
                want = int(data)
            elif kind == "bytes":
                want = base64.b64decode(data) if data is not None else None
            elif kind in ("structure", "artifact"):
                want = data
            elif kind == "value":
                want = value
            else:
                want = data
            actual = row[name]
            if actual is not None and kind in ("structure", "artifact", "value"):
                actual = json.loads(actual)
            if actual != want:
                raise ValueError(f"projection differs: {name}")
    print(json.dumps(dict(schema="gomem.arrow-verification/v1", pyarrow=pa.__version__, rows=len(decoded), columns=len(columns))))


if __name__ == "__main__":
    main()
