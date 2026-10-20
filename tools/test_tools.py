import json
import pathlib
import tempfile
import unittest

from diff_results import compare
from compare_symbols import normalized


class DifferentialTests(unittest.TestCase):
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
