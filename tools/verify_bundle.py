#!/usr/bin/env python3
"""Verify exported member hashes, counts, task membership and safe ZIP names."""
import hashlib
import json
import pathlib
import re
import sys
import zipfile


def decimal(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise ValueError("artifact sizes must be canonical decimal strings")
    number = int(value)
    if number > (1 << 63) - 1:
        raise ValueError("artifact size is too large")
    return number


def member_hash(archive, name, size, checksum):
    if archive.getinfo(name).file_size != size:
        raise ValueError("artifact member size mismatch")
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != checksum:
        raise ValueError("artifact member checksum mismatch")


def artifact_records(archive, manifest, tasks, expected):
    index = manifest["artifact_index"]
    if index["path"] != "artifacts.jsonl":
        raise ValueError("unexpected artifact index")
    expected.add(index["path"])
    digest, records, seen = hashlib.sha256(), 0, set()
    included_count, partial_count = 0, 0
    with archive.open(index["path"]) as stream:
        for line in stream:
            digest.update(line)
            record = json.loads(line)
            a = record["artifact"]
            if not re.fullmatch(r"[0-9a-f]{32}", a["id"]) or a["id"] in seen:
                raise ValueError("invalid or duplicate artifact ID")
            seen.add(a["id"])
            task = tasks[a["task_id"]]
            name = a["name"]
            if (not name or name in (".", "..") or any(c in name for c in '/\\:*?"<>|\0')
                    or any(ord(c) < 32 for c in name) or name.rstrip(" .") != name):
                raise ValueError("unsafe artifact name")
            base = name.split(".")[0].upper()
            if base in ("CON", "PRN", "AUX", "NUL") or re.fullmatch(r"(?:COM|LPT)[1-9]", base):
                raise ValueError("nonportable artifact name")
            path = f"artifacts/{task['id']}/{a['id']}/{name}"
            if a["path"] != path or a["gaps_path"] != path + ".gaps.jsonl":
                raise ValueError("artifact path mismatch")
            claimed = dict(a["provenance"])
            for key in ("layer", "offset"):
                if key in task["provenance"]:
                    claimed[key] = task["provenance"][key]
                else:
                    claimed.pop(key, None)
            if claimed != task["provenance"]:
                raise ValueError("artifact task provenance mismatch")
            expected_size = decimal(a["expected_size"])
            included = record["included"]
            if not isinstance(included, bool):
                raise ValueError("invalid artifact inclusion state")
            if not included:
                if a["state"] not in ("writing", "interrupted") or not record.get("error"):
                    raise ValueError("unexplained omitted extraction")
            else:
                size, missing, gaps = decimal(a["size"]), decimal(a["missing_bytes"]), decimal(a["gap_count"])
                if size > expected_size or missing > size or gaps > missing:
                    raise ValueError("inconsistent artifact sizes")
                if a["state"] not in ("completed", "completed_with_gaps", "partial", "failed"):
                    raise ValueError("invalid finalized extraction state")
                complete = a["state"] in ("completed", "completed_with_gaps")
                if complete and size != expected_size:
                    raise ValueError("incomplete extraction marked complete")
                if a["state"] == "completed" and (missing or gaps):
                    raise ValueError("padding concealed in complete extraction")
                if a["state"] == "completed_with_gaps" and (not missing or not gaps):
                    raise ValueError("padded extraction has no padding")
                if not complete and not a.get("error"):
                    raise ValueError("partial extraction lacks reason")
                for member, length, checksum in ((path, size, a["sha256"]), (a["gaps_path"], decimal(a["gaps_size"]), a["gaps_sha256"])):
                    if member in expected:
                        raise ValueError("duplicate artifact member")
                    expected.add(member)
                    member_hash(archive, member, length, checksum)
                if complete:
                    total, count, end = 0, 0, 0
                    with archive.open(a["gaps_path"]) as log, archive.open(path) as data:
                        for gap_line in log:
                            gap = json.loads(gap_line)
                            offset, length = int(gap["offset"], 16), decimal(gap["length"])
                            address = int(gap["address"], 16)
                            if (not length or offset < end or offset + length > size or not gap["error"]
                                    or not gap["layer"] or address < 0 or address + length > 1 << 64):
                                raise ValueError("invalid padding range/provenance")
                            data.seek(offset)
                            left = length
                            while left:
                                block = data.read(min(left, 1 << 20))
                                if not block or any(block):
                                    raise ValueError("padding range contains captured/nonzero bytes")
                                left -= len(block)
                            end, total, count = offset + length, total + length, count + 1
                    if total != missing or count != gaps:
                        raise ValueError("padding log count/size mismatch")
                included_count += 1
                partial_count += not complete
            records += 1
    if digest.hexdigest() != index["sha256"] or records != index["rows"]:
        raise ValueError("artifact index checksum/count mismatch")
    return records, included_count, partial_count


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
        if manifest["schema"] not in ("gomem.evidence/v1", "gomem.evidence/v2"):
            raise ValueError("unknown bundle schema")
        expected = {"manifest.json"}
        tasks = {task["id"]: task for task in manifest["tasks"]}
        entries = manifest["entries"]
        if len(tasks) != len(manifest["tasks"]) or len({entry["path"] for entry in entries}) != len(entries):
            raise ValueError("duplicate task or manifest member")
        if len(entries) != len(tasks):
            raise ValueError("task/member count mismatch")
        seen_tasks = set()
        artifact_refs = set()
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
                    for cell in row["cells"].values():
                        if cell["kind"] == "artifact":
                            artifact_refs.add((task["id"], cell["value"]["id"]))
                    count += 1
            if digest.hexdigest() != entry["sha256"] or count != entry["rows"] or count != task["rows"]:
                raise ValueError("result checksum/count mismatch")
        artifacts, included, partial = 0, 0, 0
        if manifest["schema"] == "gomem.evidence/v2":
            artifacts, included, partial = artifact_records(archive, manifest, tasks, expected)
            with archive.open("artifacts.jsonl") as stream:
                identities = {(r["artifact"]["task_id"], r["artifact"]["id"]) for r in map(json.loads, stream)}
            if not artifact_refs <= identities:
                raise ValueError("evidence references an absent extraction")
        elif artifact_refs:
            raise ValueError("v1 bundle cannot contain extraction references")
        if expected != set(names):
            raise ValueError("unexpected or missing members")
        if seen_tasks != set(tasks):
            raise ValueError("task has no result member")
        result = {"tasks": len(tasks), "members": len(names), "verified": True}
        if manifest["schema"] == "gomem.evidence/v2":
            result.update(artifacts=artifacts, included_artifacts=included, partial_artifacts=partial)
        return result


if __name__ == "__main__":
    print(json.dumps(verify(sys.argv[1])))
