import json
import pathlib
import tempfile
import unittest
import hashlib
import zipfile

from diff_results import compare, normalized as normalized_result
from compare_symbols import normalized
from verify_bundle import verify as verify_bundle
from compare_extractions import compare as compare_extractions


class DifferentialTests(unittest.TestCase):
    def test_artifact_filename_profile_keeps_errors_distinct(self):
        artifact = {"kind": "artifact", "value": {"name": "module.elf", "state": "completed_with_gaps", "sha256": "other-check"}}
        self.assertEqual(normalized_result(artifact, "artifact_name"), "module.elf")
        self.assertEqual(normalized_result("module.elf", "artifact_name"), "module.elf")
        missing = {"kind": "missing", "reason": "unreadable", "error": "page absent"}
        self.assertEqual(normalized_result(missing, "artifact_name"), {"missing": "unreadable", "error": "page absent"})
        with self.assertRaisesRegex(ValueError, "artifact_name"):
            normalized_result({"size": "0"}, "artifact_name")

    def test_nanosecond_comparison_rounding_is_explicit_and_exact(self):
        profile = "timestamp_microseconds_rounded"
        self.assertEqual(normalized_result("2014-06-24T10:22:33.016000956Z", profile), "2014-06-24T10:22:33.016001+00:00")
        self.assertEqual(normalized_result("2014-06-24T10:22:33.016000500Z", profile), "2014-06-24T10:22:33.016000+00:00")
        self.assertEqual(normalized_result("2014-06-24T10:22:33.016001500Z", profile), "2014-06-24T10:22:33.016002+00:00")
        self.assertEqual(normalized_result("2014-06-24T10:22:33.999999999+01:00", profile), "2014-06-24T09:22:34.000000+00:00")
        with self.assertRaisesRegex(ValueError, "timezone"):
            normalized_result("2014-06-24T10:22:33", profile)
        with self.assertRaisesRegex(ValueError, "fractional"):
            normalized_result("2014-06-24T10:22:33.1234567890Z", profile)
    def test_multiple_record_types_preserve_diagnostic_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            native, reference, mapping = root / "native", root / "reference", root / "mapping"
            native.write_text("\n".join(json.dumps({"cells": {"RecordType": {"kind": "string", "value": value}, "PID": {"kind": "uint64", "value": "1"}}}) for value in ("task", "thread", "diagnostic")) + "\n")
            reference.write_text(json.dumps([{"PID": 1}, {"PID": 1}]))
            profile = {"native_record_type": {"field": "RecordType", "values": ["task", "thread"], "excluded_values": ["diagnostic"]}, "fields": {"PID": {"native": "PID", "reference": "PID", "kind": "uint64"}}}
            mapping.write_text(json.dumps(profile))
            report = compare(native, reference, mapping)
            self.assertTrue(report["matched"])
            self.assertEqual(report["native_input_rows"], 3)
            self.assertEqual(report["native_rows"], 2)
            self.assertEqual(report["native_non_entity_records"], {"diagnostic": 1})
            profile["native_record_type"]["values"].append("diagnostic")
            mapping.write_text(json.dumps(profile))
            with self.assertRaisesRegex(ValueError, "selection"):
                compare(native, reference, mapping)
    def test_signed_result_preserves_negative_loader_counts(self):
        self.assertEqual(normalized_result({"kind": "int64", "value": "-1"}, "int64"), "-1")
        self.assertEqual(normalized_result(-1, "int64"), "-1")
        with self.assertRaisesRegex(ValueError, "int64"):
            normalized_result(str(1 << 63), "int64")
    def test_entity_profile_records_retained_diagnostic_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            native, reference, mapping = root / "native", root / "reference", root / "mapping"
            module = {"cells": {"RecordType": {"kind": "string", "value": "module"}, "Base": {"kind": "address", "value": "0x1000"}}}
            diagnostic = {"cells": {"RecordType": {"kind": "string", "value": "diagnostic"}, "Base": {"kind": "missing", "reason": "unreadable", "error": "page absent"}}}
            native.write_text(json.dumps(module) + "\n" + json.dumps(diagnostic) + "\n")
            reference.write_text(json.dumps([{"Base": 4096}]))
            profile = {"native_record_type": {"field": "RecordType", "value": "module", "excluded_values": ["diagnostic"]}, "fields": {"Base": {"native": "Base", "reference": "Base", "kind": "address"}}}
            mapping.write_text(json.dumps(profile))
            result = compare(native, reference, mapping)
            self.assertTrue(result["matched"])
            self.assertEqual(result["native_input_rows"], 2)
            self.assertEqual(result["native_non_entity_records"], {"diagnostic": 1})
            diagnostic["cells"]["RecordType"]["value"] = "unknown"
            native.write_text(json.dumps(module) + "\n" + json.dumps(diagnostic) + "\n")
            with self.assertRaisesRegex(ValueError, "unexpected native record"):
                compare(native, reference, mapping)
    def test_extracted_region_comparison_keeps_byte_differences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            case, reference = root / "case", root / "reference"
            case.mkdir()
            reference.mkdir()
            data, gaps = b"real\0\0", b""
            (case / "region.dmp").write_bytes(data)
            (case / "region.gaps").write_bytes(gaps)
            (reference / "region.dmp").write_bytes(data)
            provenance = {"image_sha256": "test-image", "engine_build": "test-build", "symbols_sha256": "test-symbols", "plugin": "test", "parameters": {}, "layer": "process:test", "offset": "0x1000"}
            artifact = {"name": "region.dmp", "path": "region.dmp", "gaps_path": "region.gaps", "state": "completed", "size": str(len(data)), "gaps_size": "0", "sha256": hashlib.sha256(data).hexdigest(), "gaps_sha256": hashlib.sha256(gaps).hexdigest(), "missing_bytes": "0", "gap_count": "0", "provenance": provenance}
            native, manifest = root / "native.jsonl", root / "manifest.json"
            def write_native():
                native.write_text(json.dumps({"cells": {"FileOutput": {"kind": "artifact", "value": artifact}}, "provenance": provenance}) + "\n")
            write_native()
            baseline = json.loads((pathlib.Path(__file__).resolve().parents[1] / "baseline.lock.json").read_text())
            manifest.write_text(json.dumps({"baseline": baseline, "image_sha256": "test-image", "parameters": ["--dump"], "extracted_files": [{"name": "region.dmp", "size": str(len(data)), "sha256": hashlib.sha256(data).hexdigest()}]}))
            self.assertTrue(compare_extractions(native, case, manifest, reference)["matched"])
            (case / "region.dmp").write_bytes(b"fake\0\0")
            with self.assertRaisesRegex(ValueError, "native extraction checksum"):
                compare_extractions(native, case, manifest, reference)
            artifact["sha256"] = hashlib.sha256(b"fake\0\0").hexdigest()
            write_native()
            changed = compare_extractions(native, case, manifest, reference)
            self.assertFalse(changed["matched"])
            self.assertEqual(changed["files"][0]["differing_bytes"], 4)
            self.assertEqual(changed["files"][0]["first_differing_offsets"], ["0x0", "0x1", "0x2", "0x3"])
            (reference / "mapped-name.dmp").write_bytes(data)
            manifest_data = json.loads(manifest.read_text())
            manifest_data["extracted_files"][0]["name"] = "mapped-name.dmp"
            manifest.write_text(json.dumps(manifest_data))
            self.assertFalse(compare_extractions(native, case, manifest, reference, {"region.dmp": "mapped-name.dmp"})["matched"])
            artifact["path"] = "../outside.dmp"
            write_native()
            with self.assertRaisesRegex(ValueError, "unsafe extraction"):
                compare_extractions(native, case, manifest, reference, {"region.dmp": "mapped-name.dmp"})
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
        self.assertEqual(normalized_result(True, "bool"), "true")
        self.assertEqual(normalized_result({"kind": "bool", "value": False}, "bool"), "false")
        with self.assertRaisesRegex(ValueError, "boolean"):
            normalized_result("true", "bool")
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

    def test_tree_depth_distinguishes_shared_offsets(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            native, reference, mapping = [directory / name for name in ("native.jsonl", "reference.json", "mapping.json")]
            profile = {"tree_key": "Offset", "fields": {
                "Offset": {"native": "Offset", "reference": "Offset", "kind": "address"},
                "Depth": {"native": "Depth", "kind": "tree_depth"}}}
            mapping.write_text(json.dumps(profile))
            parent = {"id": "parent", "cells": {"Offset": {"kind": "address", "value": "0x1000"}, "Depth": {"kind": "uint64", "value": "0"}}}
            child = {"id": "child", "parent_id": "parent", "cells": {"Offset": {"kind": "address", "value": "0x1000"}, "Depth": {"kind": "uint64", "value": "1"}}}
            native.write_text(json.dumps(parent) + "\n" + json.dumps(child) + "\n")
            reference.write_text(json.dumps([{"Offset": 4096, "__children": [{"Offset": 4096, "__children": []}]}]))
            self.assertTrue(compare(native, reference, mapping)["matched"])
            child["cells"]["Depth"]["value"] = "2"
            native.write_text(json.dumps(parent) + "\n" + json.dumps(child) + "\n")
            self.assertFalse(compare(native, reference, mapping)["matched"])

    def test_composite_tree_paths_detect_same_range_reparenting(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            native, reference, mapping = [directory / name for name in ("native", "reference", "mapping")]
            profile = {"tree_key": ["Name", "Start"], "tree_path": True, "fields": {
                "Name": {"native": "Name", "reference": "Name", "kind": "string"},
                "Start": {"native": "Start", "reference": "Start", "kind": "address"},
                "Depth": {"native": "Depth", "kind": "tree_depth"}}}
            mapping.write_text(json.dumps(profile))
            def row(id, name, depth, parent=None):
                result = {"id": id, "cells": {"Name": {"kind": "string", "value": name},
                    "Start": {"kind": "address", "value": "0x0"}, "Depth": {"kind": "uint64", "value": str(depth)}}}
                if parent:
                    result["parent_id"] = parent
                return result
            rows = [row("a", "a", 0), row("b", "b", 0), row("x", "same", 1, "a"),
                    row("y", "same", 1, "b"), row("z", "leaf", 2, "x")]
            ref = [{"Name": "a", "Start": 0, "__children": [{"Name": "same", "Start": 0,
                "__children": [{"Name": "leaf", "Start": 0}]}]},
                {"Name": "b", "Start": 0, "__children": [{"Name": "same", "Start": 0}]}]
            def write():
                native.write_text("".join(json.dumps(r) + "\n" for r in rows))
            reference.write_text(json.dumps(ref))
            write()
            self.assertTrue(compare(native, reference, mapping)["matched"])
            rows[-1]["parent_id"] = "y"
            write()
            self.assertFalse(compare(native, reference, mapping)["matched"])
            rows[0]["parent_id"] = "x"
            write()
            with self.assertRaisesRegex(ValueError, "cycle"):
                compare(native, reference, mapping)
            rows[0].pop("parent_id")
            rows[-1]["parent_id"] = "missing"
            write()
            with self.assertRaisesRegex(ValueError, "parent evidence"):
                compare(native, reference, mapping)
            for keys in (None, [], ["absent"], ["Name", "Name"]):
                profile["tree_key"] = keys
                mapping.write_text(json.dumps(profile))
                with self.assertRaisesRegex(ValueError, "invalid tree_key"):
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
