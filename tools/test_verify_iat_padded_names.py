import base64
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from verify_iat_padded_names import explain


class IATPaddedNameProofTests(unittest.TestCase):
    def fixture(self, directory):
        rows = []

        def read(at, raw, failed=False):
            rows.append(dict(id=f'capture-{len(rows)}', cells={
                'RecordType': dict(kind='string', value='memory_read'),
                'Offset': dict(kind='address', value=hex(at)),
                'Requested': dict(kind='uint64', value=str(len(raw) if not failed else 1)),
                'Captured': dict(kind='uint64', value=str(len(raw))),
                'Raw': dict(kind='bytes', value=base64.b64encode(raw).decode() if raw else None),
                'Resolution': dict(kind='structure', value=dict(method='imports')),
                'Error': dict(kind='string', value='missing original page') if failed else dict(kind='missing', reason='no_error'),
            }, provenance=dict(layer='process:test')))

        dos = bytearray(64)
        dos[:2] = b'MZ'
        struct.pack_into('<I', dos, 60, 0x80)
        header = bytearray(24)
        header[:4] = b'PE\0\0'
        struct.pack_into('<H', header, 4, 0x8664)
        read(0x1000, dos)
        read(0x1080, header)
        read(0x1200, struct.pack('<IIIII', 0x400, 0, 0, 0x500, 0x300))
        read(0x1400, struct.pack('<Q', 0x600))
        for index, byte in enumerate(b'ApiName\0'):
            read(0x1602+index, bytes([byte]))
        for index, byte in enumerate(b'api-ms'):
            read(0x1500+index, bytes([byte]))
        read(0x1506, b'', True)
        rows.append(dict(id='diagnostic', cells={
            'RecordType': dict(kind='string', value='diagnostic'),
            'PID': dict(kind='uint64', value='100'),
            'ProcessOffset': dict(kind='address', value='0x800'),
            'ProcessIdentity': dict(kind='string', value='test-identity'),
            'Error': dict(kind='missing', reason='imports_incomplete', error='original page missing'),
        }, provenance=dict(layer='process:test', offset='0x1000')))
        missing = dict(PID='100', Name='test.exe', Library='api-ms', Function='ApiName', Address=str(0x2300), Bound='false', parent=None)
        comparison = dict(sha256=dict(native='', reference='b'*64), missing=[missing], extra=[], matched=False)
        verification = dict(jsonl_sha256='', plugin='windows.iat', rows=len(rows), image_sha256='a'*64,
                            all_captures_independently_reread=True, all_seals_and_provenance_verified=True)
        return rows, comparison, verification

    def write(self, directory, rows, comparison, verification):
        native, diff, verified = (directory/name for name in ('native.jsonl', 'diff.json', 'verified.json'))
        native.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        digest = hashlib.sha256(native.read_bytes()).hexdigest()
        comparison['sha256']['native'] = digest
        verification['jsonl_sha256'] = digest
        verification['rows'] = len(rows)
        diff.write_text(json.dumps(comparison))
        verified.write_text(json.dumps(verification))
        return native, diff, verified

    def test_failed_byte_explains_prefix_without_passing_diff(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            result = explain(*self.write(directory, *self.fixture(directory)))
            self.assertEqual(result['explained_rows'], 1)
            self.assertFalse(result['full_differential_matched'])
            explanation = result['explanations'][0]
            self.assertEqual(explanation['first_unavailable_address'], '0x1506')
            self.assertEqual(explanation['readable_prefix'], 'api-ms')
            self.assertEqual(len(explanation['prefix_and_fault_evidence']), 7)

    def test_rejects_unbacked_or_stale_explanations(self):
        for mode in ('real-terminator', 'missing-capture', 'wrong-function', 'wrong-library', 'native-extra', 'unverified', 'ambiguous-process', 'stale-hash'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                rows, comparison, verification = self.fixture(directory)
                if mode == 'real-terminator':
                    row = rows[-2]
                    row['cells']['Raw']['value'] = 'AA=='
                    row['cells']['Captured']['value'] = '1'
                    row['cells']['Error'] = dict(kind='missing', reason='no_error')
                elif mode == 'missing-capture':
                    del rows[-2]
                elif mode == 'wrong-function':
                    comparison['missing'][0]['Function'] = 'OtherName'
                elif mode == 'wrong-library':
                    comparison['missing'][0]['Library'] = 'api-ms-longer'
                elif mode == 'native-extra':
                    comparison['extra'] = [comparison['missing'][0]]
                elif mode == 'unverified':
                    verification['all_captures_independently_reread'] = False
                elif mode == 'ambiguous-process':
                    duplicate = json.loads(json.dumps(rows[-1]))
                    duplicate['cells']['ProcessIdentity']['value'] = 'another-object'
                    rows.append(duplicate)
                paths = self.write(directory, rows, comparison, verification)
                if mode == 'stale-hash':
                    paths[0].write_text(paths[0].read_text()+'\n')
                with self.assertRaises(ValueError):
                    explain(*paths)


if __name__ == '__main__':
    unittest.main()
