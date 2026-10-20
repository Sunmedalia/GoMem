#!/usr/bin/env python3
"""Verify exported member hashes, counts, task membership and safe ZIP names."""
import hashlib
import json
import pathlib
import sys
import zipfile


def verify(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate ZIP members")
        for name in names:
            parts = pathlib.PurePosixPath(name)
            if parts.is_absolute() or ".." in parts.parts or "\\" in name:
                raise ValueError("unsafe member name")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest["schema"] != "gomem.evidence/v1":
            raise ValueError("unknown bundle schema")
        expected = {"manifest.json"}
        tasks = {task["id"]: task for task in manifest["tasks"]}
        entries = manifest["entries"]
        if len(tasks) != len(manifest["tasks"]) or len({entry["path"] for entry in entries}) != len(entries):
            raise ValueError("duplicate task or manifest member")
        if len(entries) != len(tasks):
            raise ValueError("task/member count mismatch")
        seen_tasks = set()
        for entry in entries:
            name = entry["path"]
            expected.add(name)
            task = tasks[pathlib.PurePosixPath(name).stem]
            seen_tasks.add(task["id"])
            if name != f"results/{task['id']}.jsonl":
                raise ValueError("unexpected result member path")
            count = 0
            digest = hashlib.sha256()
            with archive.open(name) as stream:
                for line in stream:
                    digest.update(line)
                    row = json.loads(line)
                    if row["provenance"]["image_sha256"] != task["provenance"]["image_sha256"]:
                        raise ValueError("image provenance mismatch")
                    count += 1
            if digest.hexdigest() != entry["sha256"] or count != entry["rows"] or count != task["rows"]:
                raise ValueError("result checksum/count mismatch")
        if expected != set(names):
            raise ValueError("unexpected or missing members")
        if seen_tasks != set(tasks):
            raise ValueError("task has no result member")
        return {"tasks": len(tasks), "members": len(names), "verified": True}


if __name__ == "__main__":
    print(json.dumps(verify(sys.argv[1])))
