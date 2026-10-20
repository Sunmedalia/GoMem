import json
import pathlib
import tempfile
import unittest
import hashlib
import zipfile

from diff_results import compare, normalized as normalized_result
from compare_symbols import normalized
from verify_bundle import verify as verify_bundle


class DifferentialTests(unittest.TestCase):
    def test_v2_bundle_extraction_and_padding_integrity(self):
        task_id, artifact_id = "a" * 32, "b" * 32
        provenance = {"image_sha256": "synthetic", "layer": "physical", "plugin": "fixture"}
        path = f"artifacts/{task_id}/{artifact_id}/segment.bin"
        data = b"AB\0\0"
        gaps = json.dumps({"offset": "0x2", "length": "2", "address": "0x1002", "layer": "process", "error": "not captured"}).encode() + b"\n"
        artifact = {"id": artifact_id, "task_id": task_id, "name": "segment.bin", "path": path, "gaps_path": path + ".gaps.jsonl", "state": "completed_with_gaps", "expected_size": "4", "size": "4", "missing_bytes": "2", "gap_count": "1", "gaps_size": str(len(gaps)), "sha256": hashlib.sha256(data).hexdigest(), "gaps_sha256": hashlib.sha256(gaps).hexdigest(), "provenance": dict(provenance, layer="process", offset="0x1000")}
        rows = (json.dumps({"cells": {"File": {"kind": "artifact", "value": artifact}}, "provenance": provenance}) + "\n").encode()
        metadata = (json.dumps({"artifact": artifact, "included": True}) + "\n").encode()
        manifest = {"schema": "gomem.evidence/v2", "tasks": [{"id": task_id, "rows": 1, "provenance": provenance}], "entries": [{"path": f"results/{task_id}.jsonl", "sha256": hashlib.sha256(rows).hexdigest(), "rows": 1}], "artifact_index": {"path": "artifacts.jsonl", "sha256": hashlib.sha256(metadata).hexdigest(), "rows": 1}}
        with tempfile.TemporaryDirectory() as directory:
            bundle = pathlib.Path(directory) / "evidence.zip"
            def write(payload, index=metadata):
                with zipfile.ZipFile(bundle, "w") as archive:
                    for name, body in {"manifest.json": json.dumps(manifest).encode(), f"results/{task_id}.jsonl": rows, "artifacts.jsonl": index, path: payload, path + ".gaps.jsonl": gaps}.items():
                        archive.writestr(name, body)
            write(data)
            self.assertEqual(verify_bundle(bundle)["included_artifacts"], 1)
            write(b"ABXX")
            with self.assertRaisesRegex(ValueError, "checksum"):
                verify_bundle(bundle)
            # Even matching hashes cannot disguise real bytes as recorded padding.
            artifact["sha256"] = hashlib.sha256(b"ABXX").hexdigest()
            changed = (json.dumps({"artifact": artifact, "included": True}) + "\n").encode()
            manifest["artifact_index"]["sha256"] = hashlib.sha256(changed).hexdigest()
            write(b"ABXX", changed)
            with self.assertRaisesRegex(ValueError, "padding range"):
                verify_bundle(bundle)
    def test_linux_deleted_path_display_space_only(self):
        self.assertEqual(normalized_result(" /home/a file (deleted)", "linux_path_display"), "/home/a file (deleted)")
        self.assertEqual(normalized_result(" /home/a file ", "linux_path_display"), " /home/a file ")
        self.assertEqual(normalized_result("/home/a file (deleted)", "linux_path_display"), "/home/a file (deleted)")
    def test_explicit_missing_and_timestamp_precision_profiles(self):
        self.assertEqual(normalized_result({"kind":"missing","reason":"not_set"}, "string", missing_reasons=["not_set"]), {"missing":"reference-null"})
        self.assertNotEqual(normalized_result({"kind":"missing","reason":"not_set","error":"unmapped page"}, "string", missing_reasons=["not_set"]), {"missing":"reference-null"})
        self.assertEqual(normalized_result("2025-01-01T01:00:00.1234567+01:00", "timestamp_seconds"), "2025-01-01T00:00:00+00:00")
        with self.assertRaisesRegex(ValueError, "timezone"):
            normalized_result("2025-01-01T00:00:00", "timestamp_seconds")
    def test_symbol_bitfields_compare_memory_positions(self):
        def table(size, offset, position, endian):
            return {"base_types": {"int": {"kind": "int", "size": size, "signed": False, "endian": endian}},
                    "user_types": {"flags": {"kind": "struct", "size": 4, "fields": {
                        "flag": {"offset": offset, "type": {"kind": "bitfield", "bit_position": position,
                                                             "bit_length": 3, "type": {"kind": "base", "name": "int"}}}}}}}
        ref = {"kind": "struct", "name": "flags"}
        minimal = normalized(ref, table(1, 1, 0, "little"))
        full = normalized(ref, table(4, 0, 8, "little"))
        self.assertEqual(minimal, full)
        self.assertNotEqual(minimal, normalized(ref, table(4, 0, 8, "big")))
        self.assertEqual(minimal, normalized(ref, table(4, 0, 21, "big")))

    def test_symbol_comparison_preserves_missing_pointee(self):
        table = {"base_types": {"pointer": {"size": 8}, "pointer32": {"size": 4}}, "user_types": {}}
        missing = {"kind": "pointer", "subtype": {"kind": "struct", "name": "opaque"}}
        self.assertIn("unavailable_type", str(normalized(missing, table)))
        narrow = {**missing, "base": "pointer32"}
        self.assertNotEqual(normalized(missing, table), normalized(narrow, table))

    def test_multisets_and_tree_parents(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            native, reference, mapping = [directory / name for name in ("native.jsonl", "reference.json", "mapping.json")]
            profile = {"tree_key": "Offset", "fields": {"Offset": {"native": "Offset", "reference": "Offset", "kind": "address"},
                                                          "Name": {"native": "Name", "reference": "Name", "kind": "string"}}}
            mapping.write_text(json.dumps(profile))
            parent = {"id": "parent", "cells": {"Offset": {"kind": "address", "value": "0x1000"}, "Name": {"kind": "string", "value": "parent"}}}
            child = {"id": "child", "parent_id": "parent", "cells": {"Offset": {"kind": "address", "value": "0x2000"}, "Name": {"kind": "string", "value": "child"}}}
            native.write_text(json.dumps(parent) + "\n" + json.dumps(child) + "\n")
            reference.write_text(json.dumps([{"Offset": 4096, "Name": "parent", "__children": [{"Offset": 8192, "Name": "child", "__children": []}]}]))
            self.assertTrue(compare(native, reference, mapping)["matched"])
            native.write_text(native.read_text() + json.dumps(child) + "\n")
            result = compare(native, reference, mapping)
            self.assertFalse(result["matched"])
            self.assertEqual(len(result["extra"]), 1)
            child["parent_id"] = "absent"
            native.write_text(json.dumps(parent) + "\n" + json.dumps(child) + "\n")
            with self.assertRaisesRegex(ValueError, "parent evidence"):
                compare(native, reference, mapping)

    def test_missing_cells_are_not_zeroes(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            native, reference, mapping = [directory / name for name in ("native", "reference", "mapping")]
            native.write_text(json.dumps({"cells": {"PID": {"kind": "missing", "reason": "unmapped"}}}) + "\n")
            reference.write_text(json.dumps([{"PID": 0, "__children": []}]))
            mapping.write_text(json.dumps({"fields": {"PID": {"native": "PID", "reference": "PID", "kind": "uint64"}}}))
            self.assertFalse(compare(native, reference, mapping)["matched"])


if __name__ == "__main__":
    unittest.main()
