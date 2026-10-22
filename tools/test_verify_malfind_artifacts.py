import base64
import json
import pathlib
import tempfile
import unittest

from compare_extractions import digest
from verify_malfind_artifacts import verify


class MalfindArtifactVerificationTests(unittest.TestCase):
    def test_original_calls_and_gap_tampering(self):
        for mode in ('valid', 'zero-capture', 'fully-captured', 'unbound', 'wrong-bytes', 'wrong-zeroes', 'gap-address',
                     'gap-offset', 'gap-length', 'gap-error', 'extra-gap',
                     'no-calls', 'duplicate-call', 'wrong-layer', 'wrong-size',
                     'wrong-totals', 'wrong-provenance', 'unsafe-path'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                stream, report = root / 'rows.jsonl', root / 'verified.json'
                file, log = root / 'region.dmp', root / 'region.gaps.jsonl'
                file.write_bytes(b'\xaa\xbb\0\0')
                provenance = dict(layer='process:test', offset='0x1000', image_sha256='image',
                                  engine_build='build', symbols_sha256='symbols',
                                  plugin='windows.malfind', parameters={'dump': 'true'})
                artifact = dict(name='region.dmp', path=file.name, gaps_path=log.name,
                                size='4', expected_size='4', missing_bytes='2', gap_count='1',
                                state='completed_with_gaps', provenance=dict(provenance))
                gap = dict(offset='0x2', address='0x1002', length='2', layer='process:test', error='hole')
                def cell(kind, value):
                    return dict(kind=kind, value=value)
                finding = dict(provenance=provenance, cells=dict(
                    RecordType=cell('string', 'finding'), Start=cell('address', '0x1000'),
                    End=cell('address', '0x1003'), FileOutput=cell('artifact', artifact)))
                call = dict(provenance=provenance, cells=dict(
                    RecordType=cell('string', 'memory_read'), Offset=cell('address', '0x1000'),
                    Requested=cell('uint64', '4'), Captured=cell('uint64', '2'),
                    Raw=cell('bytes', base64.b64encode(b'\xaa\xbb').decode()),
                    Error=cell('string', 'hole'), Resolution=cell('structure', {'method': 'dump'})))
                rows = [call, finding]
                if mode == 'zero-capture':
                    file.write_bytes(bytes(4))
                    call['cells']['Captured']['value'] = '0'
                    call['cells']['Raw']['value'] = None
                    gap.update(offset='0x0', address='0x1000', length='4')
                    artifact['missing_bytes'] = '4'
                elif mode == 'fully-captured':
                    file.write_bytes(b'\xaa\xbb\xcc\xdd')
                    call['cells']['Captured']['value'] = '4'
                    call['cells']['Raw']['value'] = base64.b64encode(file.read_bytes()).decode()
                    call['cells']['Error'] = dict(kind='missing', reason='no_error')
                    artifact.update(missing_bytes='0', gap_count='0', state='completed')
                elif mode == 'wrong-bytes':
                    file.write_bytes(b'\xcc\xbb\0\0')
                elif mode == 'wrong-zeroes':
                    file.write_bytes(b'\xaa\xbb\x01\0')
                elif mode.startswith('gap-'):
                    key = mode.removeprefix('gap-')
                    gap[key] = {'address': '0x1003', 'offset': '0x1', 'length': '1', 'error': 'invented'}[key]
                elif mode == 'no-calls':
                    rows = [finding]
                elif mode == 'duplicate-call':
                    rows.insert(0, call)
                elif mode == 'wrong-layer':
                    artifact['provenance']['layer'] = 'process:other'
                elif mode == 'wrong-size':
                    artifact['expected_size'] = '5'
                elif mode == 'wrong-totals':
                    artifact['missing_bytes'] = '1'
                elif mode == 'wrong-provenance':
                    artifact['provenance']['symbols_sha256'] = 'other'
                elif mode == 'unsafe-path':
                    artifact['path'] = '../region.dmp'
                log.write_text('' if mode == 'fully-captured' else json.dumps(gap) + '\n')
                if mode == 'extra-gap':
                    log.write_text(log.read_text() * 2)
                artifact.update(sha256=digest(file), gaps_sha256=digest(log),
                                gaps_size=str(log.stat().st_size))
                stream.write_text(''.join(json.dumps(row) + '\n' for row in rows))
                bound = dict(plugin='windows.malfind', jsonl_sha256=digest(stream), findings=1,
                             image_sha256='image', all_captures_independently_reread=True,
                             all_seals_and_provenance_verified=True)
                if mode == 'unbound':
                    bound['jsonl_sha256'] = 'other'
                report.write_text(json.dumps(bound))
                if mode in ('valid', 'zero-capture', 'fully-captured'):
                    result = verify(stream, root, report)
                    self.assertTrue(result['all_bytes_and_gaps_bound_to_original_calls'])
                    self.assertEqual(result['files'][0]['missing_bytes'], int(artifact['missing_bytes']))
                else:
                    with self.assertRaises(ValueError):
                        verify(stream, root, report)


if __name__ == '__main__':
    unittest.main()
