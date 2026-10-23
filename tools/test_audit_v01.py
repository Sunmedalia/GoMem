import json
from pathlib import Path
import tempfile
import unittest

from audit_v01 import inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'docs').mkdir()
        (self.root / 'docs/control.md').write_text('selected fields only')
        self.spec = dict(name='linux.example', description='Example', upstream='linux.Example',
                         columns=[dict(name='Offset', kind='address')])
        self.entry = dict(id='linux.Example', native='linux.example', status='partial', accepted=False,
                          applicability='x64', corpora=['fixture'], comparison='selected_fields_match',
                          gaps=['modern kernels'], validation_record='docs/control.md')

    def build(self):
        return inventory([self.spec], dict(baseline={}, plugins=[self.entry]), self.root)

    def test_no_implicit_behavioral_acceptance(self):
        r = self.build()
        self.assertEqual(r['native_plugins'], 1)
        self.assertEqual(r['plugins'][0]['behavioral_acceptance'], 'pending')
        self.assertFalse(r['plugins'][0]['upstream'][0]['accepted'])
        before = json.dumps(r)
        (self.root / 'docs/control.md').write_text('changed scope')
        self.assertNotEqual(before, json.dumps(self.build()))

    def test_invalid_mappings_and_scope_fail(self):
        for field, value in [('native', 'absent'), ('status', 'missing'),
                             ('corpora', []), ('gaps', []),
                             ('validation_record', '../outside'),
                             ('validation_record', 'docs/absent.md')]:
            with self.subTest(field=field, value=value):
                original = self.entry[field]
                self.entry[field] = value
                with self.assertRaises(ValueError):
                    self.build()
                self.entry[field] = original

    def test_schema_and_upstream_drift_fail(self):
        with self.assertRaises(ValueError):
            inventory([self.spec, self.spec], dict(plugins=[]), self.root)
        self.spec['columns'].append(self.spec['columns'][0])
        with self.assertRaises(ValueError):
            self.build()
        self.spec['columns'].pop()
        self.spec['upstream'] = 'unknown'
        with self.assertRaises(ValueError):
            self.build()


if __name__ == '__main__':
    unittest.main()
