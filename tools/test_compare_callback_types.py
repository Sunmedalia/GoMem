import copy
import json
from pathlib import Path
import tempfile
import unittest

from compare_callback_types import compare


class CallbackTypedComparisonTests(unittest.TestCase):
    def setUp(self):
        self.reference = {'Type': 'test', 'Callback': 0x1234,
                          'Module': 'kernel', 'Symbol': {'__absent': 'NotAvailableValue'},
                          'Detail': {'__absent': 'UnreadableValue'}, '__children': []}
        self.native = {'cells': {'RecordType': {'kind': 'string', 'value': 'callback'},
                                'Type': {'kind': 'string', 'value': 'test'},
                                'Callback': {'kind': 'address', 'value': '0xffff000000001234'},
                                'Module': {'kind': 'string', 'value': 'kernel'},
                                'Symbol': {'kind': 'missing', 'reason': 'not_available'},
                                'Detail': {'kind': 'missing', 'reason': 'unreadable', 'error': 'page missing'}}}

    def run_comparison(self, references, natives):
        with tempfile.TemporaryDirectory() as directory:
            native, reference = Path(directory) / 'native', Path(directory) / 'reference'
            reference.write_text(json.dumps(references))
            native.write_text(''.join(json.dumps(row) + '\n' for row in natives))
            return compare(native, reference)

    def test_missing_classes_match_but_errors_are_retained(self):
        report = self.run_comparison([self.reference], [self.native])
        self.assertTrue(report['matched'])
        self.assertEqual(report['native_error_details_retained'], {'Detail:unreadable': 1})

    def test_different_classes_and_duplicates_fail(self):
        other = copy.deepcopy(self.reference)
        other['Detail'] = {'__absent': 'NotApplicableValue'}
        self.assertFalse(self.run_comparison([other], [self.native])['matched'])
        report = self.run_comparison([self.reference, self.reference], [self.native])
        self.assertFalse(report['matched'])
        self.assertEqual(len(report['missing']), 1)

    def test_null_invalid_class_and_unknown_records_rejected(self):
        for value in (None, {'__absent': 'UnknownClass'}):
            reference = copy.deepcopy(self.reference)
            reference['Detail'] = value
            with self.assertRaises(ValueError):
                self.run_comparison([reference], [self.native])
        native = copy.deepcopy(self.native)
        native['cells']['RecordType']['value'] = 'unexpected'
        with self.assertRaises(ValueError):
            self.run_comparison([self.reference], [native])
